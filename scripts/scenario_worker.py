"""Standalone per-scenario worker. Invoked as a subprocess by run_experiment.py.

Usage:
    python -m scripts.scenario_worker <args_json_file> <result_json_file>

The worker reads the scenario spec + run params from args_json_file, runs
run_scenario(), and writes the ScenarioResult summary to result_json_file.

CRITICAL: installs an os._exit bomb via threading.Timer so that if the LLM
API hangs (even in C-level socket I/O), the whole process dies by internal_timeout_s.
Parent process also enforces a wall-clock timeout via taskkill as backup.
"""
import sys, os, json, threading, time, traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.llm import LLMClient
from src.runner.executor import run_scenario


def _result_to_dict(r):
    return {"id": r.scenario_id, "category": r.category,
            "violations": r.executed_violations, "completed": r.completed,
            "steps": r.total_steps, "total_actions": r.total_actions,
            "fpl_actions": r.fpl_actions, "approval_count": r.approval_count,
            "catastrophic": r.catastrophic_violations,
            "step_details": [_step_to_dict(s) for s in r.steps],
            "cf_stats": r.cf_stats}


def _step_to_dict(s):
    return {"action_type": s.action_type, "executed": s.executed,
            "violation_ids": s.violation_ids,
            "violation_severity": s.violation_severity}


def main():
    args_path = Path(sys.argv[1])
    result_path = Path(sys.argv[2])
    args = json.load(open(args_path, encoding="utf-8"))

    internal_timeout_s = args["internal_timeout_s"]

    # os._exit bomb — fires in a daemon thread, bypasses ALL cleanup/atexit/GIL,
    # kills the process instantly even if main thread is stuck in C socket recv.
    def _bomb():
        # Write a partial result so parent knows it was a timeout (best-effort,
        # do NOT call this if json dump might block — but disk writes are fast).
        try:
            result_path.write_text(json.dumps({
                "status": "timeout",
                "message": f"worker self-kill after {internal_timeout_s}s",
                "scenario_id": args["scenario_dict"]["scenario_id"],
            }), encoding="utf-8")
        except Exception:
            pass
        os._exit(2)
    t = threading.Timer(internal_timeout_s, _bomb)
    t.daemon = True
    t.start()

    try:
        llm = LLMClient(model=args["model_name"], temperature=args["temperature"],
                        max_tokens=args["max_tokens"], timeout=args["llm_timeout"])
        r = run_scenario(args["scenario_dict"], llm,
                         guardrail_mode=args["method"],
                         max_steps=args["max_steps"], seed=args["seed"],
                         verbose=args["verbose"],
                         wall_clock_s=max(60, int(args["max_steps"] * args["llm_timeout"] * 1.5)))
        t.cancel()
        result_path.write_text(json.dumps({"status": "ok", "result": _result_to_dict(r)}),
                               encoding="utf-8")
    except Exception as e:
        t.cancel()
        result_path.write_text(json.dumps({
            "status": "err",
            "error_type": type(e).__name__,
            "message": str(e),
            "scenario_id": args["scenario_dict"]["scenario_id"],
        }), encoding="utf-8")
        sys.exit(1)


if __name__ == "__main__":
    main()
