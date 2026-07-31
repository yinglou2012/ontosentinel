"""Analyze experiment results and produce paper-formatted tables."""

import json
import sys
from pathlib import Path
from tabulate import tabulate

def load_results(path):
    with open(path) as f:
        return json.load(f)

def print_table(results_dict, title=""):
    headers = ["Method", "SVR% ↓", "CVR% ↓", "TCR% ↑", "FPR% ↓", "Approval%", "N"]
    rows = []
    order = ["none", "react_p", "ipc", "sre", "scp_only", "full"]
    names = {
        "none": "ReAct (no guardrail)",
        "react_p": "ReAct + Enhanced Prompt",
        "ipc": "Isolated Precondition Checks",
        "sre": "Stateful Rule Engine (SRE)",
        "scp_only": "OntoGuard (SCP only)",
        "full": "OntoGuard (full)",
    }
    for method in order:
        if method in results_dict:
            m = results_dict[method]["metrics"]
            rows.append([
                names.get(method, method),
                m["SVR"], m["CVR"], m["TCR"], m["FPR"], m["Approval"], m["n_scenarios"]
            ])
    if title:
        print(f"\n{'='*80}")
        print(f"  {title}")
        print(f"{'='*80}")
    print(tabulate(rows, headers=headers, tablefmt="simple", floatfmt=".1f"))
    print()

def main():
    results_dir = Path(__file__).resolve().parent.parent / "results"
    files = sorted(results_dir.glob("results_*.json"))
    if not files:
        print("No result files found. Run run_experiment.py first.")
        return

    latest = files[-1]
    print(f"Loading: {latest.name}")
    data = load_results(latest)
    print_table(data, title=f"Results — {latest.stem}")

    # Per-category breakdown
    for method in data:
        per_scen = data[method].get("per_scenario", [])
        traps = [s for s in per_scen if "trap" in s.get("category","")]
        benign = [s for s in per_scen if s["category"] == "benign"]
        drift = [s for s in per_scen if "drift" in s.get("category","")]
        t_viol = sum(1 for s in traps if s["violations"] > 0)
        b_viol = sum(1 for s in benign if s["violations"] > 0)
        d_viol = sum(1 for s in drift if s["violations"] > 0)
        print(f"  {method:12s}: traps violated={t_viol:2d}/{len(traps)} ({100*t_viol/max(len(traps),1):.0f}%), "
              f"benign violations={b_viol:2d}/{len(benign)}, "
              f"drift caught={len(drift)-d_viol:2d}/{len(drift)}")

if __name__ == "__main__":
    main()
