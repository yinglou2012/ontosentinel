<#
.SYNOPSIS
    Multi-seed experiment runner wrapper for Windows.
    Handles crashes, auto-retry, and progress tracking.

.DESCRIPTION
    This script wraps run_multi_seed.py with automatic retry logic:
    - If a seed's run crashes (exit code != 0), it retries up to MaxRetries times.
    - Between retries, it waits CooldownSeconds to let the API rate limit reset.
    - It logs all output to results/multi_seed_logs/orchestrator.log
    - It tracks progress in results/multi_seed_logs/progress.json

.PARAMETER Seeds
    Comma-separated list of seeds to run. Default: 42,123,456,789,2024

.PARAMETER Method
    Single method to run (e.g., "full"). Omit to run all methods.

.PARAMETER RemediationOnly
    Re-run scp_only+full with --no-resume to get step_details for remediation_rate.

.PARAMETER MaxRetries
    Maximum retry attempts per seed. Default: 3

.PARAMETER CooldownSeconds
    Seconds to wait between retries. Default: 60

.EXAMPLE
    .\run_multi_seed.ps1
    .\run_multi_seed.ps1 -Seeds 42,123
    .\run_multi_seed.ps1 -Method full
    .\run_multi_seed.ps1 -AggregateOnly
    .\run_multi_seed.ps1 -RemediationOnly
#>

param(
    [string]$Seeds = "42,123,456,789,2024",
    [string]$Method = "",
    [int]$MaxRetries = 3,
    [int]$CooldownSeconds = 60,
    [int]$ScenarioTimeout = 195,
    [int]$MaxSteps = 15,
    [switch]$AggregateOnly,
    [switch]$RemediationOnly,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"

# Force UTF-8 for child Python processes
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

# Setup
$LogDir = "results\multi_seed_logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$OrchestratorLog = Join-Path $LogDir "orchestrator.log"
$ProgressFile = Join-Path $LogDir "progress.json"

function Write-Progress-File {
    param([string]$Phase, [string]$Seed, [string]$Status, [hashtable]$Extra = @{})
    $progress = @{
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        phase = $Phase
        seed = $Seed
        status = $Status
    }
    foreach ($k in $Extra.Keys) { $progress[$k] = $Extra[$k] }
    $progress | ConvertTo-Json -Depth 5 | Out-File -FilePath $ProgressFile -Encoding UTF8
}

function Log {
    param([string]$Msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $Msg"
    Write-Host $line
    Add-Content -Path $OrchestratorLog -Value $line -Encoding UTF8
}

$modeStr = if ($RemediationOnly) { "remediation" } elseif ($AggregateOnly) { "aggregate" } else { "full" }
Log "=== Multi-seed orchestrator started ($modeStr) ==="
Log "Seeds: $Seeds"
Log "Method: $(if ($Method) { $Method } else { 'all' })"
Log "Max retries per seed: $MaxRetries"
Log "Cooldown between retries: ${CooldownSeconds}s"

# Parse seeds
$SeedList = $Seeds.Split(",") | ForEach-Object { [int]$_.Trim() }

# Build Python arguments
$CmdArgs = @("--scenario-timeout", $ScenarioTimeout, "--max-steps", $MaxSteps, "--seeds") + $SeedList
if ($Method) { $CmdArgs += @("--method", $Method) }
if ($AggregateOnly) { $CmdArgs += "--aggregate-only" }
if ($RemediationOnly) { $CmdArgs += "--remediation-only" }
if ($Verbose) { $CmdArgs += "--verbose" }

if ($AggregateOnly) {
    Log "Aggregate-only mode -- skipping experiment runs"
    $fullCmd = "python run_multi_seed.py $($CmdArgs -join ' ')"
    Invoke-Expression $fullCmd 2>&1 | Tee-Object -FilePath $OrchestratorLog -Append
    exit 0
}

# Phase 1: Run experiments with retry
$totalSeeds = $SeedList.Count
$seedIndex = 0
$allComplete = $true

foreach ($seed in $SeedList) {
    $seedIndex++
    Log ""
    Log "========================================"
    $modeLabel = if ($RemediationOnly) { "Remediation seed" } else { "Seed" }
    Log "$modeLabel $seed ($seedIndex/$totalSeeds)"
    Log "========================================"

    $retryCount = 0
    $seedSuccess = $false

    while (-not $seedSuccess -and $retryCount -lt $MaxRetries) {
        if ($retryCount -gt 0) {
            Log "Retry $retryCount/$MaxRetries for seed $seed (waiting ${CooldownSeconds}s...)"
            Write-Progress-File -Phase "retry" -Seed $seed -Status "cooldown" -Extra @{retry = $retryCount; max_retries = $MaxRetries}
            Start-Sleep -Seconds $CooldownSeconds
        }

        Write-Progress-File -Phase "running" -Seed $seed -Status "started" -Extra @{retry = $retryCount; seed_index = $seedIndex; total_seeds = $totalSeeds}

        # Determine log file name
        if ($RemediationOnly) {
            $logFile = Join-Path $LogDir "seed${seed}_remediation.log"
        } elseif ($Method) {
            $logFile = Join-Path $LogDir "seed${seed}_$Method.log"
        } else {
            $logFile = Join-Path $LogDir "seed${seed}_all.log"
        }

        $start = Get-Date

        Log "Running: python run_multi_seed.py $($CmdArgs -join ' ')"
        Log "Logging to: $logFile"

        $process = Start-Process -FilePath "python" -ArgumentList $CmdArgs `
            -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err" `
            -NoNewWindow -PassThru

        # Wait for process to complete (with periodic heartbeat)
        $maxWait = 30 * 3600  # 30 hours max per seed (full 6 methods ~15-25h)
        if ($RemediationOnly) { $maxWait = 8 * 3600 }  # remediation only ~3h
        $waited = 0
        $heartbeatInterval = 300  # every 5 minutes

        while (-not $process.HasExited) {
            Start-Sleep -Seconds 60
            $waited += 60

            if ($waited % $heartbeatInterval -eq 0) {
                $elapsed = (Get-Date) - $start
                $lastLine = ""
                if (Test-Path $logFile) {
                    $lines = Get-Content $logFile -Tail 1
                    if ($lines) { $lastLine = $lines[0] }
                }
                Log "  [heartbeat] Seed $seed running for $($elapsed.TotalHours.ToString('F1'))h -- last: $lastLine"
                Write-Progress-File -Phase "running" -Seed $seed -Status "in_progress" -Extra @{elapsed_h = [math]::Round($elapsed.TotalHours, 1); last_line = $lastLine}
            }

            if ($waited -ge $maxWait) {
                Log "  [timeout] Seed $seed exceeded ${maxWait}s -- killing process tree"
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $process.Id } | ForEach-Object {
                    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                }
                break
            }
        }

        $exitCode = $process.ExitCode
        $elapsed = (Get-Date) - $start

        if ($exitCode -eq 0) {
            Log "OK: Seed $seed completed successfully ($($elapsed.TotalHours.ToString('F1'))h, exit=0)"
            Write-Progress-File -Phase "complete" -Seed $seed -Status "success" -Extra @{elapsed_h = [math]::Round($elapsed.TotalHours, 1)}
            $seedSuccess = $true
        } else {
            Log "FAIL: Seed $seed exited with code $exitCode after $($elapsed.TotalHours.ToString('F1'))h"
            Write-Progress-File -Phase "retry" -Seed $seed -Status "failed" -Extra @{exit_code = $exitCode; elapsed_h = [math]::Round($elapsed.TotalHours, 1); retry = $retryCount}

            $tailLines = ""
            if (Test-Path $logFile) {
                $tailLines = (Get-Content $logFile -Tail 5) -join " "
            }

            if ($tailLines -match "circuit.*abort|sustained failures") {
                Log "  -> Circuit breaker tripped -- API may be down. Extended cooldown."
                Start-Sleep -Seconds ($CooldownSeconds * 3)
            }

            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                Log "  -> Max retries ($MaxRetries) reached for seed $seed -- moving on"
                $allComplete = $false
            }
        }
    }
}

# Phase 2: Aggregate (normal mode only; remediation mode prints its own aggregate at end)
if (-not $RemediationOnly) {
    Log ""
    Log "========================================"
    Log "Phase 2: Aggregating results"
    Log "========================================"
    Write-Progress-File -Phase "aggregate" -Seed "all" -Status "started"

    $seedsStr = $SeedList -join " "
    $aggCmd = "python run_multi_seed.py --aggregate-only --seeds $seedsStr"
    Log "Running: $aggCmd"
    Invoke-Expression $aggCmd 2>&1 | Tee-Object -FilePath $OrchestratorLog -Append

    Write-Progress-File -Phase "done" -Seed "all" -Status "complete" -Extra @{all_complete = $allComplete}
}

Log ""
Log "=== Multi-seed orchestrator finished ==="
Log "All seeds complete: $allComplete"
Log "Logs: $LogDir"
