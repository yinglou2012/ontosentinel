"""Multi-seed experiment runner.

Runs the full 6-method x 140-scenario experiment across multiple seeds,
with per-seed checkpoint files and automatic resume.

Usage:
    python run_multi_seed.py                          # all seeds, all methods
    python run_multi_seed.py --seeds 42 123           # specific seeds
    python run_multi_seed.py --method full            # single method, all seeds
    python run_multi_seed.py --seeds 42 --method full # single seed+method
    python run_multi_seed.py --aggregate-only          # just aggregate existing results
    python run_multi_seed.py --remediation-only        # re-run scp_only+full with step_details

Design:
    - Each seed gets its own checkpoint file: results/results_{model}_seed{N}.json
    - Seeds run sequentially (API rate limits make parallel seeds impractical)
    - If a seed's run is interrupted, re-running the same command resumes from checkpoint
    - After all seeds complete, aggregates mean+/-std across seeds into a summary table
    - The seed=42 run reuses the existing checkpoint (renamed from the single-seed run)
    - --remediation-only: forces --no-resume on scp_only+full to get step_details
      (needed because old checkpoints lack step_details for remediation_rate calc)
"""

import argparse
import json
import os
import sys
import time
import subprocess as sp
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent))

from src.eval.metrics import compute_metrics, print_results_table, ScenarioResult as _SR


SEEDS_DEFAULT = [42, 123, 456, 789, 2024]
METHODS = ["none", "react_p", "ipc", "sre", "scp_only", "full", "llamafirewall"]
REMEDIATION_METHODS = ["scp_only", "full"]


def get_model_name():
    config_path = Path(__file__).parent / "configs" / "default.yaml"
    config = yaml.safe_load(open(config_path, encoding="utf-8"))
    return os.getenv("DEFAULT_MODEL", config["model"]["primary"])


def seed_checkpoint_path(model_name, seed):
    """Per-seed checkpoint file path."""
    model_safe = model_name.replace("/", "_")
    return Path(f"results/results_{model_safe}_seed{seed}.json")


def migrate_seed42(model_name):
    """If seed=42 checkpoint doesn't exist but the old single-seed file does, copy it."""
    s42 = seed_checkpoint_path(model_name, 42)
    old = Path(f"results/results_{model_name.replace('/','_')}_full.json")
    if not s42.exists() and old.exists():
        import shutil
        shutil.copy2(old, s42)
        print(f"[migrate] Copied {old.name} -> {s42.name} (seed=42 baseline)")
        return True
    return False


def run_subprocess_with_logging(cmd, seed, method_label):
    """Run a subprocess, tee output to log file and console."""
    log_dir = Path("results/multi_seed_logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"seed{seed}_{method_label}.log"

    # Force UTF-8 output from child process to avoid cp950 decode errors on Windows
    child_env = os.environ.copy()
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"

    log_file = open(log_path, "w", encoding="utf-8")
    proc = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.STDOUT, text=True,
                    bufsize=1, cwd=str(Path(__file__).parent),
                    env=child_env, encoding="utf-8", errors="replace")

    for line in proc.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        log_file.write(line)
        log_file.flush()

    proc.wait()
    log_file.close()
    return proc.returncode


def run_single_seed(seed, model_name, methods,
                     max_steps, scenario_timeout, verbose):
    """Run all methods for a single seed by invoking run_experiment.py as subprocess.

    Returns True if all methods completed, False if interrupted/aborted.
    """
    ckpt_path = seed_checkpoint_path(model_name, seed)
    cmd = [
        sys.executable, "run_experiment.py",
        "--seed", str(seed),
        "--max-steps", str(max_steps),
        "--scenario-timeout", str(scenario_timeout),
        "--output", str(ckpt_path),
    ]
    if verbose:
        cmd.append("--verbose")

    if len(methods) < 6:
        all_done = True
        for method in methods:
            method_cmd = cmd + ["--method", method]
            print(f"\n{'='*60}")
            print(f"  Seed {seed} | Method: {method}")
            print(f"{'='*60}")
            ret = run_subprocess_with_logging(method_cmd, seed, method)
            if ret != 0:
                all_done = False
                print(f"  Warning: Method {method} exited with code {ret} (may be resumable)")
        return all_done
    else:
        print(f"\n{'='*60}")
        print(f"  Seed {seed} | All methods")
        print(f"{'='*60}")
        ret = run_subprocess_with_logging(cmd, seed, "all")
        return ret == 0


def check_seed_complete(model_name, seed, n_scenarios=140):
    """Check if a seed's checkpoint has all 6 methods x n_scenarios complete."""
    ckpt = seed_checkpoint_path(model_name, seed)
    if not ckpt.exists():
        return False, {}

    try:
        data = json.load(open(ckpt, encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError):
        return False, {}

    status = {}
    all_done = True
    for m in METHODS:
        scens = data.get(m, {}).get("scenarios", {})
        n_total = len(scens)
        n_completed = sum(1 for s in scens.values() if s.get("completed"))
        status[m] = {"total": n_total, "completed": n_completed}
        if n_completed < n_scenarios:
            all_done = False
    return all_done, status


def check_remediation_complete(model_name, seed, n_scenarios=140):
    """Check if a seed's remediation re-runs (scp_only+full) are all complete.
    Uses per-method checkpoint files.
    """
    status = {}
    all_done = True
    for method in REMEDIATION_METHODS:
        method_ckpt = Path(f"results/results_{model_name.replace('/','_')}_remediation_seed{seed}_{method}.json")
        n_total = 0
        n_completed = 0
        if method_ckpt.exists():
            try:
                data = json.load(open(method_ckpt, encoding="utf-8"))
                scens = data.get(method, {}).get("scenarios", {})
                n_total = len(scens)
                n_completed = sum(1 for s in scens.values() if s.get("completed"))
            except Exception:
                pass
        status[method] = {"total": n_total, "completed": n_completed}
        if n_completed < n_scenarios:
            all_done = False
    return all_done, status


def run_remediation_seed(seed, model_name,
                          max_steps, scenario_timeout, verbose):
    """Re-run scp_only+full with step_details for remediation_rate.

    Key design decisions:
    1. Uses a SEPARATE checkpoint per method (not shared) so --no-resume on one
       method doesn't wipe another method's already-completed data.
    2. First run of a method uses --no-resume (forces fresh execution to get
       step_details; old checkpoints lack them). If interrupted, resume from
       the per-method checkpoint on next invocation.
    3. Only scp_only+full need remediation (only OntoGuard modes have remedial actions).
    """
    all_done = True
    for method in REMEDIATION_METHODS:
        # Per-method checkpoint so methods don't interfere with each other
        method_ckpt = Path(f"results/results_{model_name.replace('/','_')}_remediation_seed{seed}_{method}.json")

        # Check if this specific method is already done
        method_done = False
        existing_count = 0
        existing_completed = 0
        if method_ckpt.exists():
            try:
                existing = json.load(open(method_ckpt, encoding="utf-8"))
                scens = existing.get(method, {}).get("scenarios", {})
                existing_count = len(scens)
                existing_completed = sum(1 for s in scens.values()
                                         if isinstance(s, dict) and s.get("completed"))
                method_done = existing_completed >= 140
            except Exception:
                existing_count = 0

        if method_done:
            print(f"  OK: {method}: remediation complete ({existing_completed}/140 done) - skipping")
            continue

        if existing_completed > 0:
            print(f"  -> {method}: resuming remediation ({existing_completed}/140 done)")
            no_resume = False
        else:
            print(f"  -> {method}: fresh remediation run (--no-resume for step_details)")
            no_resume = True

        cmd = [
            sys.executable, "run_experiment.py",
            "--seed", str(seed),
            "--max-steps", str(max_steps),
            "--scenario-timeout", str(scenario_timeout),
            "--method", method,
            "--output", str(method_ckpt),
        ]
        if no_resume:
            cmd.append("--no-resume")
        if verbose:
            cmd.append("--verbose")

        print(f"\n{'='*60}")
        print(f"  Remediation | Seed {seed} | Method: {method}")
        print(f"  Output: {method_ckpt.name}")
        print(f"{'='*60}")

        ret = run_subprocess_with_logging(cmd, seed, f"remediation_{method}")
        if ret != 0:
            all_done = False
            print(f"  Warning: {method} exited with code {ret} (may be resumable)")

    return all_done


def _build_step_results(steps_raw):
    """Rebuild StepResult list from step_details in checkpoint."""
    from src.runner.executor import StepResult
    steps = []
    for st in steps_raw:
        steps.append(StepResult(
            step=st.get("step", 0),
            tool_name=st.get("tool_name", ""),
            tool_args=st.get("tool_args", {}),
            action_type=st.get("action_type"),
            executed=st.get("executed", False),
            violation_ids=st.get("violation_ids", []),
            violation_severity=st.get("violation_severity", []),
            scp_feedback=st.get("scp_feedback", ""),
            rate_rho=st.get("rate_rho"),
            rate_tier=st.get("rate_tier"),
            revision_round=st.get("revision_round", 0),
            tool_result=st.get("tool_result", ""),
        ))
    return steps


def aggregate_results(model_name, seeds):
    """Aggregate metrics across seeds, computing mean+/-std for each method.

    Returns list of per-method aggregated metrics dicts.
    """
    import statistics

    per_seed_metrics = {}
    for seed in seeds:
        ckpt = seed_checkpoint_path(model_name, seed)
        if not ckpt.exists():
            print(f"  [skip] {ckpt.name} not found")
            continue

        try:
            data = json.load(open(ckpt, encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"  [skip] {ckpt.name} corrupted")
            continue

        from run_experiment import load_scenarios
        scenarios_dir = Path(__file__).parent / "scenarios"
        scenarios = load_scenarios(scenarios_dir)
        scen_by_id = {s["scenario_id"]: s for s in scenarios}

        for method in METHODS:
            mdata = data.get(method, {})
            scens = mdata.get("scenarios", {})
            if not scens:
                continue

            srs = []
            for sid, raw in scens.items():
                if not isinstance(raw, dict):
                    continue
                # Skip scenarios that never actually ran (corrupt/incomplete
                # placeholders left over from interrupted runs).  These have
                # violations=0, total_actions=0, and step_details=[] by default
                # and would dilute SVR/CVR artificially.
                if (not raw.get("completed")
                        and raw.get("total_actions", 0) == 0
                        and raw.get("steps", 0) <= 1
                        and not raw.get("step_details")):
                    continue
                s = scen_by_id.get(sid, {})
                steps_raw = raw.get("step_details", [])
                steps = _build_step_results(steps_raw)

                category = raw.get("category", s.get("category", ""))
                trap_type = None
                if category.startswith("trap/"):
                    trap_type = category.split("/", 1)[1]

                srs.append(_SR(
                    scenario_id=sid, category=category,
                    trap_type=trap_type,
                    is_trap=category != "benign",
                    total_steps=raw.get("steps", 0),
                    violations=[[]], violation_severities=[[]],
                    catastrophic_violations=raw.get("catastrophic", 0),
                    executed_violations=raw.get("violations", 0),
                    completed=raw.get("completed", False),
                    fpl_actions=raw.get("fpl_actions", 0),
                    total_actions=raw.get("total_actions", 0),
                    approval_count=raw.get("approval_count", 0),
                    steps=steps,
                ))

            if srs:
                m = compute_metrics(method, srs)
                per_seed_metrics.setdefault(method, []).append(m)

    print("\n" + "=" * 90)
    print("AGGREGATED RESULTS (mean +/- std across seeds)")
    print("=" * 90)

    metric_fields = [
        ("SVR", "svr"),
        ("CVR", "cvr"),
        ("DVR", "dvr"),
        ("TCR", "tcr"),
        ("FPR", "fpr"),
        ("Approval", "approval_rate"),
        ("Remed.", "remediation_rate"),
    ]

    header = f"{'Method':<10} {'N_seeds':>7}"
    for label, _ in metric_fields:
        header += f" {label:>14}"
    print(header)
    print("-" * (17 + 14 * len(metric_fields)))

    aggregated = []
    for method in METHODS:
        seeds_data = per_seed_metrics.get(method, [])
        n_seeds = len(seeds_data)
        if n_seeds == 0:
            continue

        row = {"method": method, "n_seeds": n_seeds}
        line = f"{method:<10} {n_seeds:>7}"
        for label, field in metric_fields:
            values = [getattr(m, field) for m in seeds_data]
            mean = statistics.mean(values)
            if n_seeds >= 2:
                std = statistics.stdev(values)
                line += f" {mean*100:>6.1f}+/-{std*100:>4.1f}%"
                row[field] = {"mean": mean, "std": std}
            else:
                line += f" {mean*100:>6.1f}%    "
                row[field] = {"mean": mean, "std": 0}
        print(line)
        aggregated.append(row)

    return aggregated


def aggregate_remediation(model_name, seeds):
    """Aggregate remediation-specific results from per-method remediation checkpoints."""
    import statistics

    model_safe = model_name.replace("/", "_")
    per_seed_metrics = {}

    from run_experiment import load_scenarios
    scenarios_dir = Path(__file__).parent / "scenarios"
    scenarios = load_scenarios(scenarios_dir)
    scen_by_id = {s["scenario_id"]: s for s in scenarios}

    for seed in seeds:
        for method in REMEDIATION_METHODS:
            method_ckpt = Path(f"results/results_{model_safe}_remediation_seed{seed}_{method}.json")
            if not method_ckpt.exists():
                continue
            try:
                data = json.load(open(method_ckpt, encoding="utf-8"))
            except json.JSONDecodeError:
                continue

            mdata = data.get(method, {})
            scens = mdata.get("scenarios", {})
            if not scens:
                continue

            srs = []
            has_step_details = False
            for sid, raw in scens.items():
                # Skip placeholder entries (never actually ran) — they
                # artificially dilute SVR/CVR/TCR toward 0.
                if (not raw.get("completed")
                        and raw.get("total_actions", 0) == 0
                        and raw.get("steps", 0) <= 1
                        and not raw.get("step_details")):
                    continue
                s = scen_by_id.get(sid, {})
                steps_raw = raw.get("step_details", [])
                if steps_raw:
                    has_step_details = True
                steps = _build_step_results(steps_raw)

                category = raw.get("category", s.get("category", ""))
                trap_type = None
                if category.startswith("trap/"):
                    trap_type = category.split("/", 1)[1]

                srs.append(_SR(
                    scenario_id=sid, category=category,
                    trap_type=trap_type,
                    is_trap=category != "benign",
                    total_steps=raw.get("steps", 0),
                    violations=[[]], violation_severities=[[]],
                    catastrophic_violations=raw.get("catastrophic", 0),
                    executed_violations=raw.get("violations", 0),
                    completed=raw.get("completed", False),
                    fpl_actions=raw.get("fpl_actions", 0),
                    total_actions=raw.get("total_actions", 0),
                    approval_count=raw.get("approval_count", 0),
                    steps=steps,
                ))

            if srs:
                m = compute_metrics(method, srs)
                per_seed_metrics.setdefault(method, []).append((m, has_step_details))

    print("\n" + "=" * 80)
    print("REMEDIATION RESULTS (mean +/- std across seeds)")
    print("=" * 80)

    metric_fields = [
        ("SVR", "svr"),
        ("CVR", "cvr"),
        ("DVR", "dvr"),
        ("TCR", "tcr"),
        ("Approval", "approval_rate"),
        ("Remed.", "remediation_rate"),
    ]

    header = f"{'Method':<10} {'N':>4} {'step_details':>12}"
    for label, _ in metric_fields:
        header += f" {label:>14}"
    print(header)
    print("-" * (30 + 14 * len(metric_fields)))

    for method in REMEDIATION_METHODS:
        seeds_data = per_seed_metrics.get(method, [])
        n_seeds = len(seeds_data)
        if n_seeds == 0:
            print(f"{method:<10} {'--':>4} {'--':>12}")
            continue

        has_sd = all(sd for _, sd in seeds_data)
        sd_label = "yes" if has_sd else "partial"

        line = f"{method:<10} {n_seeds:>4} {sd_label:>12}"
        for label, field in metric_fields:
            values = [getattr(m, field) for m, _ in seeds_data]
            mean = statistics.mean(values)
            if n_seeds >= 2:
                std = statistics.stdev(values)
                line += f" {mean*100:>6.1f}+/-{std*100:>4.1f}%"
            else:
                line += f" {mean*100:>6.1f}%    "
        print(line)

    print("\n--- Remediation detail (per seed) ---")
    for method in REMEDIATION_METHODS:
        seeds_data = per_seed_metrics.get(method, [])
        if not seeds_data:
            continue
        print(f"\n  {method}:")
        for i, (m, has_sd) in enumerate(seeds_data):
            seed = seeds[i]
            sd_str = "yes" if has_sd else "NO"
            print(f"    Seed {seed}: Remed={m.remediation_rate*100:.1f}%, "
                  f"SVR={m.svr*100:.1f}%, TCR={m.tcr*100:.1f}%, "
                  f"Approval={m.approval_rate*100:.1f}%, step_details={sd_str}")


def main():
    parser = argparse.ArgumentParser(description="Multi-seed experiment runner")
    parser.add_argument("--seeds", type=int, nargs="*", default=None,
                        help="Seeds to run (default: all 5 from config)")
    parser.add_argument("--method", default=None,
                        choices=METHODS,
                        help="Run only this method across all seeds")
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--scenario-timeout", type=int, default=195)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--aggregate-only", action="store_true",
                        help="Skip running, just aggregate existing checkpoint results")
    parser.add_argument("--remediation-only", action="store_true",
                        help="Re-run scp_only+full with --no-resume to get step_details "
                             "for remediation_rate calculation. Uses separate checkpoint files.")
    parser.add_argument("--output", default=None,
                        help="Output path for aggregated summary JSON")
    args = parser.parse_args()

    model_name = get_model_name()
    seeds = args.seeds or SEEDS_DEFAULT
    methods = [args.method] if args.method else METHODS

    print(f"Model: {model_name}")
    print(f"Seeds: {seeds}")
    print(f"Methods: {methods}")
    print(f"Max steps: {args.max_steps}")
    print(f"Scenario timeout: {args.scenario_timeout}s")

    # Migrate disabled — we want a fresh seed42 run with step_details
    # if 42 in seeds and not args.remediation_only:
    #     migrated = migrate_seed42(model_name)
    #     if migrated:
    #         print("[migrate] Seed 42 checkpoint ready (reuses existing run)")

    if args.aggregate_only:
        aggregate_results(model_name, seeds)
        return

    # -- Remediation-only mode --
    if args.remediation_only:
        print(f"\n{'='*80}")
        print(f"REMEDIATION RE-RUN: {len(seeds)} seeds x {REMEDIATION_METHODS}")
        print(f"(scp_only + full only, with --no-resume for step_details)")
        print(f"{'='*80}")

        overall_start = time.time()
        remediation_status = {}

        for seed in seeds:
            is_complete, status = check_remediation_complete(model_name, seed)
            if is_complete:
                print(f"\nOK: Seed {seed}: remediation complete - skipping")
                remediation_status[seed] = "complete"
                continue

            if status:
                print(f"\n-> Seed {seed}: resuming remediation (current: {status})")
            else:
                print(f"\n-> Seed {seed}: starting remediation fresh")

            seed_start = time.time()
            success = run_remediation_seed(seed, model_name,
                                             args.max_steps, args.scenario_timeout, args.verbose)
            elapsed = time.time() - seed_start

            is_complete, status = check_remediation_complete(model_name, seed)
            if is_complete:
                print(f"\nOK: Seed {seed}: remediation completed in {elapsed/3600:.1f}h")
                remediation_status[seed] = "complete"
            else:
                print(f"\nWarning: Seed {seed}: remediation incomplete - {status}")
                remediation_status[seed] = "incomplete"

        total_elapsed = time.time() - overall_start
        print(f"\n{'='*80}")
        print(f"Remediation total elapsed: {total_elapsed/3600:.1f}h")
        print(f"Status: {remediation_status}")
        print(f"{'='*80}")

        print(f"\n{'='*80}")
        print("Remediation results:")
        print(f"{'='*80}")
        aggregate_remediation(model_name, seeds)
        return

    # -- Normal multi-seed mode --
    print(f"\n{'='*80}")
    print(f"PHASE 1: Running {len(seeds)} seeds x {len(methods)} methods")
    print(f"{'='*80}")

    overall_start = time.time()
    seed_status = {}

    for seed in seeds:
        is_complete, status = check_seed_complete(model_name, seed)
        if is_complete:
            print(f"\nOK: Seed {seed}: all 6 methods complete - skipping")
            seed_status[seed] = "complete"
            continue

        if status:
            print(f"\n-> Seed {seed}: resuming (current progress: {status})")
        else:
            print(f"\n-> Seed {seed}: starting fresh")

        seed_start = time.time()
        success = run_single_seed(seed, model_name, methods,
                                   args.max_steps, args.scenario_timeout, args.verbose)
        elapsed = time.time() - seed_start

        is_complete, status = check_seed_complete(model_name, seed)
        if is_complete:
            print(f"\nOK: Seed {seed}: completed in {elapsed/3600:.1f}h")
            seed_status[seed] = "complete"
        else:
            print(f"\nWarning: Seed {seed}: incomplete after {elapsed/3600:.1f}h - {status}")
            seed_status[seed] = "incomplete"

    total_elapsed = time.time() - overall_start
    print(f"\n{'='*80}")
    print(f"Total elapsed: {total_elapsed/3600:.1f}h")
    print(f"Seed status: {seed_status}")
    print(f"{'='*80}")

    print(f"\n{'='*80}")
    print("PHASE 2: Aggregating results")
    print(f"{'='*80}")

    aggregated = aggregate_results(model_name, seeds)

    summary_path = args.output or f"results/summary_multi_seed_{model_name.replace('/', '_')}.json"
    summary = {
        "model": model_name,
        "seeds": seeds,
        "methods": methods,
        "total_elapsed_s": round(total_elapsed, 1),
        "seed_status": seed_status,
        "results": aggregated,
    }
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\nSummary saved to: {summary_path}")
    print(f"Per-seed checkpoints: results/results_{model_name.replace('/', '_')}_seed{{N}}.json")


if __name__ == "__main__":
    main()
