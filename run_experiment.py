"""Main experiment runner.

Usage:
    python run_experiment.py                     # run all methods on all scenarios
    python run_experiment.py --method full       # run only OntoGuard full
    python run_experiment.py --quick             # quick test on 20 scenarios

Resilience features:
    - Each scenario runs as a SEPARATE python subprocess (scripts/scenario_worker.py),
      NOT a multiprocessing fork. This guarantees that taskkill /F /T can kill the
      entire process tree on Windows even when C-level socket I/O is blocking.
    - Worker self-kills via os._exit(2) after WORKER_INTERNAL_TIMEOUT seconds.
    - Parent enforces a wall-clock kill via taskkill /F /T (and ctypes
      TerminateProcess as final fallback) after SCENARIO_TIMEOUT seconds.
    - Per-scenario checkpoint: after EACH successful scenario, results are
      atomically saved to disk. Network drop / crash mid-method loses at most
      the single in-flight scenario.
    - Resume: on restart, already-completed (method, scenario_id) pairs are
      skipped; only missing scenarios are re-run.
    - Network-failure circuit breaker: consecutive worker errors trigger a
      cooldown; sustained failures abort the run gracefully (checkpoint intact).
"""

import argparse
import json
import os
import sys
import time
import threading
import tempfile
import subprocess as sp
from pathlib import Path

import yaml
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))

from src.eval.metrics import compute_metrics, print_results_table, ScenarioResult as _SR
from src.runner.executor import StepResult


def _build_steps(raw: dict) -> list:
    """Reconstruct StepResult list from checkpoint step_details."""
    steps = []
    for sd in raw.get("step_details", []):
        steps.append(StepResult(
            step=0, tool_name="", tool_args={},
            action_type=sd.get("action_type"),
            executed=sd.get("executed", False),
            violation_ids=sd.get("violation_ids", []),
            violation_severity=sd.get("violation_severity", []),
            scp_feedback="", rate_rho=None, rate_tier=None,
            revision_round=0, tool_result="",
        ))
    return steps


SCENARIO_TIMEOUT = 195       # parent taskkills after 195s (3.25 min)
WORKER_INTERNAL_TIMEOUT = 180 # worker os._exit bombs after 180s (3 min)
# Per-scenario budget: typical benign 25-50s, complex benign ≤120s, real stuck calls 180s bomb.
# This gives LLM enough steps (15 × ~10s per step) to complete chatty scenarios while
# guaranteeing no scenario runs forever on a dead API connection.
CONSECUTIVE_FAIL_COOLDOWN = 5
CONSECUTIVE_FAIL_ABORT    = 15
COOLDOWN_SLEEP_S          = 30


def load_scenarios(scenarios_dir: Path, quick: bool = False, category: str | None = None):
    index_path = scenarios_dir / "index.json"
    with open(index_path, encoding="utf-8") as f:
        index = json.load(f)
    scenarios = []
    files = list((scenarios_dir / "benign").glob("*.json"))
    for sub in ["single_step", "drift", "threshold", "odcv"]:
        files.extend((scenarios_dir / "traps" / sub).glob("*.json"))
    for fp in files:
        with open(fp, encoding="utf-8") as f:
            s = json.load(f)
        if category and s.get("category") != category and not s.get("category","").startswith(category):
            continue
        scenarios.append(s)
    if quick:
        scenarios = ([s for s in scenarios if s["category"]=="benign"][:10] +
                     [s for s in scenarios if s["category"]!="benign"][:10])
    return scenarios


def _save_checkpoint(output_path: Path, per_method_raw: dict):
    """Atomically write per-method scenario results."""
    tmp = output_path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(per_method_raw, f, indent=2, default=str)
    os.replace(tmp, output_path)


def _load_checkpoint(output_path: Path, methods_order: list[str], n_scenarios: int = 140):
    """Load checkpoint; return (per_method_raw, done_pairs)."""
    per_method_raw = {}
    done_pairs = set()
    if not output_path.exists():
        return per_method_raw, done_pairs
    try:
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
        for method, payload in data.items():
            if isinstance(payload, dict) and "per_scenario" in payload:
                scens = {s["id"]: s for s in payload["per_scenario"]}
                per_method_raw[method] = {"scenarios": scens,
                                          "elapsed": payload.get("elapsed_seconds", 0)}
            elif isinstance(payload, dict) and "scenarios" in payload:
                per_method_raw[method] = payload
            else:
                continue
            for sid, sraw in per_method_raw[method]["scenarios"].items():
                if isinstance(sraw, dict) and sraw.get("completed"):
                    done_pairs.add((method, sid))
                elif not isinstance(sraw, dict):
                    done_pairs.add((method, sid))
        done_methods = {m for m in methods_order
                        if m in per_method_raw
                        and sum(1 for s in per_method_raw[m]["scenarios"].values()
                                if isinstance(s, dict) and s.get("completed")) >= n_scenarios}
        print(f"[resume] Checkpoint found: {len(done_pairs)} (method,scenario) pairs done, "
              f"methods fully complete: {sorted(done_methods)}")
        return per_method_raw, done_pairs
    except Exception as e:
        print(f"[resume] Could not load checkpoint ({e}); starting fresh.")
        return {}, set()


def _is_network_error(msg: str) -> bool:
    m = str(msg).lower()
    return any(k in m for k in ("timeout", "timed out", "connection", "connect",
                                 "reset", "refused", "network", "502", "503",
                                 "504", "apierror", "rate", "429", "overloaded",
                                 "unreachable", "dns", "name or service",
                                 "remotedisconnected", "connectionerror"))


def _kill_process_tree(pid: int):
    """Brute-force kill a process and all its children on Windows."""
    # 1) taskkill /F /T — kills the tree
    for _ in range(2):
        try:
            sp.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                   capture_output=True, timeout=5)
        except Exception:
            pass
        time.sleep(0.5)
        try:
            # Quick check: still alive?
            r = sp.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True,
                       text=True, timeout=3)
            if str(pid) not in r.stdout.split("=")[-1] or "No tasks" in r.stdout:
                return
        except Exception:
            pass
    # 2) ctypes TerminateProcess as last resort
    try:
        import ctypes
        k = ctypes.windll.kernel32
        PROCESS_TERMINATE = 0x0001
        h = k.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h:
            k.TerminateProcess(h, 1)
            k.CloseHandle(h)
    except Exception:
        pass


def run_single_method(method: str, scenarios: list[dict], model_name: str,
                      temperature: float, llm_max_tokens: int, llm_timeout: int,
                      max_steps: int, seed: int, verbose: bool,
                      scenario_timeout: int,
                      done_pairs: set, per_method_raw: dict,
                      output_path: Path,
                      worker_script: Path,
                      tmpdir: Path):
    """Run scenarios in SEPARATE python subprocesses (not multiprocessing).
    subprocess.Popen + a standalone worker script guarantees that taskkill /F /T
    can kill the child even when it's stuck in C-level socket I/O (because the
    child is its own python.exe process, not a fork sharing parent handles).
    """
    results = []
    already_done = 0
    timeout_count = 0
    error_count = 0
    net_err_streak = 0
    aborted = False
    t_method_start = time.time()
    elapsed_partial = per_method_raw.get(method, {}).get("elapsed", 0)
    python_exe = sys.executable

    for s in tqdm(scenarios, desc=f"Running {method}", leave=False):
        sid = s["scenario_id"]
        if (method, sid) in done_pairs:
            already_done += 1
            continue

        # Write args + result to temp files (simple IPC; avoids queue/pipe issues)
        args_fd, args_path = tempfile.mkstemp(suffix=".json", dir=tmpdir, prefix="args_")
        res_fd, res_path = tempfile.mkstemp(suffix=".json", dir=tmpdir, prefix="res_")
        os.close(args_fd); os.close(res_fd)
        worker_args = {
            "scenario_dict": s,
            "model_name": model_name,
            "temperature": temperature,
            "max_tokens": llm_max_tokens,
            "llm_timeout": llm_timeout,
            "method": method,
            "max_steps": max_steps,
            "seed": seed,
            "verbose": verbose,
            "internal_timeout_s": WORKER_INTERNAL_TIMEOUT,
        }
        with open(args_path, "w", encoding="utf-8") as f:
            json.dump(worker_args, f)

        t0 = time.time()
        proc = sp.Popen(
            [python_exe, str(worker_script), args_path, res_path],
            stdout=sp.DEVNULL, stderr=sp.DEVNULL,  # DEVNULL to avoid pipe-buffer deadlock
            cwd=str(worker_script.parent.parent),
            creationflags=sp.CREATE_NO_WINDOW if os.name=="nt" else 0,
        )
        try:
            proc.wait(timeout=scenario_timeout)
            timed_out = False
        except sp.TimeoutExpired:
            timed_out = True
            _kill_process_tree(proc.pid)
            try:
                proc.wait(5)
            except Exception:
                pass

        elapsed = time.time() - t0
        # Read result file
        outcome = None
        try:
            if os.path.exists(res_path) and os.path.getsize(res_path) > 0:
                with open(res_path, encoding="utf-8") as f:
                    outcome = json.load(f)
        except Exception:
            outcome = None
        # Clean up temp files
        for p in (args_path, res_path):
            try: os.unlink(p)
            except Exception: pass

        if timed_out or (proc.returncode == 2):
            timeout_count += 1
            net_err_streak += 1
            reason = "killed" if timed_out else "self-kill"
            msg = outcome.get("message", "") if outcome else ""
            print(f"  TIMEOUT({reason}) on {sid} ({elapsed:.0f}s) {msg}")
        elif proc.returncode != 0:
            error_count += 1
            if outcome and outcome.get("status") == "err":
                msg = f"{outcome.get('error_type','')}: {outcome.get('message','')}"
            else:
                msg = f"exitcode={proc.returncode}"
            if _is_network_error(msg):
                net_err_streak += 1
            else:
                net_err_streak = 0
            print(f"  ERROR on {sid} ({elapsed:.0f}s): {msg}")
        else:
            if outcome and outcome.get("status") == "ok":
                raw = outcome["result"]
                from src.runner.executor import ScenarioResult as _SRExec
                r = _SRExec(
                    scenario_id=raw["id"], category=raw["category"],
                    trap_type=raw.get("category", "").split("/")[-1] if "/" in raw.get("category", "") else None,
                    is_trap=raw["category"]!="benign",
                    total_steps=raw["steps"],
                    violations=[[]], violation_severities=[[]],
                    catastrophic_violations=raw.get("catastrophic",0),
                    executed_violations=raw["violations"],
                    completed=raw["completed"],
                    fpl_actions=raw.get("fpl_actions",0),
                    total_actions=raw.get("total_actions",0),
                    approval_count=raw.get("approval_count",0),
                    steps=_build_steps(raw),
                )
                results.append(r)
                per_method_raw.setdefault(method, {"scenarios": {}, "elapsed": 0})
                per_method_raw[method]["scenarios"][sid] = raw
                _save_checkpoint(output_path, per_method_raw)
                net_err_streak = 0
            elif outcome and outcome.get("status") == "timeout":
                timeout_count += 1
                net_err_streak += 1
                print(f"  TIMEOUT(worker) on {sid} ({elapsed:.0f}s): {outcome.get('message','')}")
            else:
                error_count += 1
                net_err_streak += 1
                print(f"  NO_RESULT on {sid} ({elapsed:.0f}s)")

        if net_err_streak == CONSECUTIVE_FAIL_COOLDOWN:
            print(f"  [circuit] {net_err_streak} consecutive failures — "
                  f"sleeping {COOLDOWN_SLEEP_S}s...")
            time.sleep(COOLDOWN_SLEEP_S)
        if net_err_streak >= CONSECUTIVE_FAIL_ABORT:
            print(f"  [circuit] {net_err_streak} consecutive failures — aborting {method}")
            aborted = True
            break

    per_method_raw.setdefault(method, {"scenarios": {}, "elapsed": 0})
    per_method_raw[method]["elapsed"] = round(elapsed_partial + (time.time() - t_method_start), 1)
    _save_checkpoint(output_path, per_method_raw)

    all_r = []
    for s in scenarios:
        sid = s["scenario_id"]
        raw = per_method_raw[method]["scenarios"].get(sid)
        if raw is None: continue
        trap_t = raw.get("category", "").split("/")[-1] if "/" in raw.get("category", "") else None
        all_r.append(_SR(
            scenario_id=sid, category=raw["category"],
            trap_type=trap_t,
            is_trap=raw["category"]!="benign",
            total_steps=raw["steps"],
            violations=[[]], violation_severities=[[]],
            catastrophic_violations=raw.get("catastrophic", 0),
            executed_violations=raw["violations"],
            completed=raw["completed"],
            fpl_actions=raw.get("fpl_actions",0),
            total_actions=raw.get("total_actions",0),
            approval_count=raw.get("approval_count",0), steps=_build_steps(raw),
        ))

    total_scens = len(scenarios)
    done_count = len(per_method_raw[method]["scenarios"])
    if timeout_count or error_count or aborted or already_done:
        print(f"  [warn] already_done={already_done}, timeout={timeout_count}, "
              f"error={error_count}, aborted={aborted}, done={done_count}/{total_scens}")
    return all_r, aborted, done_count >= total_scens


def _print_summary(all_metrics):
    print("\n" + "="*80)
    print("RESULTS SUMMARY")
    print("="*80)
    if all_metrics:
        print_results_table(all_metrics)
    else:
        print("(no complete results yet)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", default=None,
                        choices=["none","react_p","ipc","sre","scp_only","full","cf_full","llamafirewall"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--output", default=None)
    parser.add_argument("--scenario-timeout", type=int, default=SCENARIO_TIMEOUT)
    parser.add_argument("--no-resume", action="store_true",
                        help="Ignore existing checkpoint and start fresh")
    args = parser.parse_args()

    scenario_timeout = args.scenario_timeout
    config_path = Path(__file__).parent / "configs" / "default.yaml"
    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    model_name = args.model or config["model"]["primary"]
    temperature = config["model"]["temperature"]
    llm_max_tokens = config["model"]["max_tokens"]
    llm_timeout = config["model"].get("timeout", 30)
    print(f"Model: {model_name}")
    print(f"Quick mode: {args.quick}")
    print(f"Scenario timeout: {scenario_timeout}s (taskkill)")
    print(f"LLM request timeout: {llm_timeout}s")
    print(f"Circuit breaker: cooldown@{CONSECUTIVE_FAIL_COOLDOWN}, abort@{CONSECUTIVE_FAIL_ABORT}")
    print(f"Checkpoint: per-scenario atomic save; resume skips done pairs")

    scenarios_dir = Path(__file__).parent / "scenarios"
    scenarios = load_scenarios(scenarios_dir, quick=args.quick)
    print(f"Loaded {len(scenarios)} scenarios")

    tag = 'quick' if args.quick else 'full'
    output_path = Path(args.output or f"results/results_{model_name.replace('/','_')}_{tag}.json")
    worker_script = Path(__file__).parent / "scripts" / "scenario_worker.py"
    os.makedirs(output_path.parent, exist_ok=True)
    tmpdir_obj = tempfile.TemporaryDirectory(prefix="ontoguard_worker_")
    tmpdir = Path(tmpdir_obj.name)

    methods = (["none","react_p","ipc","sre","scp_only","full"]
               if args.method is None else [args.method])

    # Resume
    per_method_raw, done_pairs = ({}, set())
    if not args.no_resume:
        per_method_raw, done_pairs = _load_checkpoint(output_path, methods, n_scenarios=len(scenarios))

    all_metrics = []
    fully_done = set()

    for method in methods:
        done_count = len([1 for (m,_) in done_pairs if m == method])
        is_fully_done = done_count >= len(scenarios)
        if is_fully_done:
            print(f"\n{'='*60}")
            print(f"Skipping method {method} ({done_count}/{len(scenarios)} already done)")
            print(f"{'='*60}")
            # Rebuild SR list straight from checkpoint (no LLM calls)
            from src.runner.executor import ScenarioResult as _SR
            all_r = []
            for s in scenarios:
                sid = s["scenario_id"]
                raw = per_method_raw[method]["scenarios"].get(sid)
                if raw is None: continue
                trap_t = raw.get("category", "").split("/")[-1] if "/" in raw.get("category", "") else None
                all_r.append(_SR(
                    scenario_id=sid, category=raw["category"],
                    trap_type=trap_t,
                    is_trap=raw["category"]!="benign",
                    total_steps=raw["steps"],
                    violations=[[]], violation_severities=[[]],
                    catastrophic_violations=raw.get("catastrophic",0),
                    executed_violations=raw["violations"],
                    completed=raw["completed"],
                    fpl_actions=raw.get("fpl_actions",0),
                    total_actions=raw.get("total_actions",0),
                    approval_count=raw.get("approval_count",0), steps=_build_steps(raw),
                ))
            if all_r:
                all_metrics.append(compute_metrics(method, all_r))
                fully_done.add(method)
            continue

        print(f"\n{'='*60}")
        print(f"Running method: {method} ({done_count}/{len(scenarios)} already done, resuming)")
        print(f"{'='*60}")
        results, aborted, method_complete = run_single_method(
            method, scenarios, model_name, temperature, llm_max_tokens,
            llm_timeout, args.max_steps, args.seed, args.verbose,
            scenario_timeout, done_pairs, per_method_raw, output_path,
            worker_script=worker_script, tmpdir=tmpdir)
        if not results:
            print(f"  No results for {method}.")
            if aborted:
                print(f"  Aborting run due to sustained failures. Checkpoint at {output_path}")
                break
            continue
        all_metrics.append(compute_metrics(method, results))
        if method_complete:
            fully_done.add(method)
        if aborted:
            print(f"  Method {method} aborted mid-run; partial results saved to {output_path}")
            break

    _save_checkpoint(output_path, per_method_raw)
    print(f"\nResults/checkpoint at: {output_path}")
    print(f"Methods fully complete: {sorted(fully_done)}")
    if len(fully_done) < len(methods):
        print(f"Re-run the same command to resume remaining methods.")
    try:
        _print_summary(all_metrics)
    except ModuleNotFoundError as e:
        print(f"[warn] Skipping summary print (missing optional dep: {e})")


if __name__ == "__main__":
    main()
