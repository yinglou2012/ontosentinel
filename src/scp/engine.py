"""Semantic Constraint Propagation (SCP) engine.

SCP is the core safety interceptor:
1. Maintains a ground-truth ABox (symbolic state) independent of LLM attention.
2. Before each action execution, constructs a hypothetical ABox (projection),
   runs all applicable invariants, and returns violations (if any).
3. Supports up to R revision rounds: structured violation feedback injected
   back to the LLM for action repair.
4. Tracks I_active (set of invariants activated by scenario context).

This implementation uses the Python-native check functions in checks.py,
which semantically simulate rule-based reasoning over the FRC ontology. The
subsumption-based invariant propagation is handled by get_invariants_for_action(),
which traverses the action TBox hierarchy.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from ontology.invariants import get_invariants_for_action, get_invariant_by_id, INVARIANTS
from src.scp.state import ABox
from src.scp.checks import CHECK_FNS
from src.scp.counterfactual import CounterfactualEngine, CounterfactualBundle


@dataclass
class Violation:
    inv_id: str
    description: str
    severity: str
    detail: str           # human-readable explanation
    action_type: str
    args: dict
    suggestion: str = ""  # suggested remediation

    def format_feedback(self) -> str:
        s = f"[{self.severity}] {self.inv_id}: {self.description}\n  Detail: {self.detail}"
        if self.suggestion:
            s += f"\n  Suggestion: {self.suggestion}"
        return s


@dataclass
class SCPResult:
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    projected_abox: ABox | None = None
    feedback_to_llm: str = ""
    counterfactual: CounterfactualBundle | None = None


class SCPEngine:
    """Semantic Constraint Propagation engine."""

    def __init__(self, initial_abox: ABox, max_revisions: int = 3,
                 enable_counterfactual: bool = True):
        self.abox = initial_abox
        self.max_revisions = max_revisions
        self.revision_count = 0
        self.active_invariants: set[str] = set()
        self.violation_history: list[list[Violation]] = []
        self.enable_counterfactual = enable_counterfactual
        self.counterfactual_engine: CounterfactualEngine | None = None
        if enable_counterfactual:
            self.counterfactual_engine = CounterfactualEngine(self.abox)
        # Statistics for counterfactual
        self.cf_stats = {
            "total_violations": 0,
            "parameter_fixable": 0,
            "precondition_fixable": 0,
            "not_fixable": 0,
            "suggestions_generated": 0,
            "suggestions_adopted": 0,  # incremented when LLM follows the suggestion
        }
        # Activate scenario-relevant invariants based on action types
        # referenced in the scenario; full activation occurs on first action.

    def _activate_invariants(self, action_type: str):
        """Add invariants applicable to this action type (and supertypes) to active set."""
        applicable = get_invariants_for_action(action_type)
        for inv in applicable:
            self.active_invariants.add(inv["id"])

    def verify(self, action_type: str, args: dict,
               refresh_state: bool = True) -> SCPResult:
        """Verify a candidate action against all applicable invariants.

        1. Refresh external state (simulated: sync ABox from 'database').
        2. Build hypothetical ABox via apply_action projection.
        3. Run all active invariants on the hypothetical state.
        4. Return pass/fail with structured violation feedback.
        """
        # Refresh state (in production, re-query the banking DB here)
        if refresh_state:
            self._refresh_external_state()

        # Activate invariants for this action type
        self._activate_invariants(action_type)

        # Hypothetical projection
        projected = self.abox.apply_action(action_type, args)

        # Run all applicable invariants
        applicable = get_invariants_for_action(action_type)
        violations: list[Violation] = []

        for inv in applicable:
            fn = CHECK_FNS.get(inv["check"])
            if fn is None:
                continue
            ok, detail = fn(args, projected)
            if not ok:
                suggestion = self._suggest_remediation(inv, args, detail)
                violations.append(Violation(
                    inv_id=inv["id"],
                    description=inv["desc"],
                    severity=inv["severity"],
                    detail=detail,
                    action_type=action_type,
                    args=args,
                    suggestion=suggestion,
                ))

        passed = len(violations) == 0
        feedback = ""
        cf_bundle = None
        if not passed:
            feedback = self._build_feedback(violations, action_type, args)
            self.violation_history.append(violations)

            # Generate counterfactual repair suggestions
            if self.enable_counterfactual and self.counterfactual_engine:
                self.counterfactual_engine.abox = self.abox  # keep in sync
                cf_bundle = self.counterfactual_engine.generate_bundle(
                    violations, action_type, args,
                )
                # Append counterfactual guidance to feedback
                if cf_bundle and cf_bundle.primary_fix:
                    feedback += "\n\n" + cf_bundle.primary_fix
                # Update statistics
                for r in cf_bundle.results:
                    self.cf_stats["total_violations"] += 1
                    if r.fixable == "parameter":
                        self.cf_stats["parameter_fixable"] += 1
                    elif r.fixable == "precondition":
                        self.cf_stats["precondition_fixable"] += 1
                    else:
                        self.cf_stats["not_fixable"] += 1
                    if r.suggested_fix:
                        self.cf_stats["suggestions_generated"] += 1

        return SCPResult(
            passed=passed,
            violations=violations,
            projected_abox=projected if passed else None,
            feedback_to_llm=feedback,
            counterfactual=cf_bundle,
        )

    def commit(self, action_type: str | None = None, args: dict | None = None,
               new_abox: ABox | None = None):
        """Commit after successful execution.

        If new_abox is provided (env-driven state), trust it directly — env.call_tool
        is the single source of truth for state mutation, avoiding double-apply.
        Otherwise (standalone use), apply the action to current abox.
        """
        if new_abox is not None:
            self.abox = new_abox
        elif action_type is not None and args is not None:
            self.abox = self.abox.apply_action(action_type, args)
        self.revision_count = 0

    def record_revision(self):
        """Increment revision round counter."""
        self.revision_count += 1

    def record_cf_adopted(self):
        """Record that the LLM followed a counterfactual suggestion."""
        self.cf_stats["suggestions_adopted"] += 1

    def can_revise(self) -> bool:
        return self.revision_count < self.max_revisions

    def _refresh_external_state(self):
        """In production: re-query DB for latest KYC status, balances, etc.
        In simulation: check for exogenous state changes defined in the scenario."""
        # The simulation environment handles exogenous state injection;
        # SCP simply trusts its ABox, which gets updated when the env
        # calls scp.abox = env.inject_exogenous_change(scp.abox).
        pass

    def _build_feedback(self, violations: list[Violation], action_type: str, args: dict) -> str:
        lines = [f"Action '{action_type}' FAILED OntoGuard safety verification. Violations:"]
        for v in violations:
            lines.append(f"  - {v.format_feedback()}")
        if self.revision_count < self.max_revisions - 1:
            lines.append(f"\nYou may revise the action (revision {self.revision_count+1}/{self.max_revisions}).")
            lines.append("Address the above violations and propose a corrected action.")
        else:
            lines.append(f"\nMaximum revision rounds ({self.max_revisions}) reached. Action will be rejected.")
        return "\n".join(lines)

    def _suggest_remediation(self, inv: dict, args: dict, detail: str) -> str:
        """Generate a concrete remediation suggestion based on the violated invariant."""
        iid = inv["id"]
        if iid == "KYC-001":
            return "Trigger KYCRefresh for this client before resubmitting."
        if iid == "KYC-002":
            return "Complete Enhanced Due Diligence (EDD) process before int'l wire."
        if iid == "KYC-003":
            return f"Initiate KYC refresh (last verified >{self.abox.kyc_validity_days}d)."
        if iid == "KYC-004":
            return "Complete PEP-specific EDD and obtain supervisor sign-off."
        if iid in ("LIM-001", "LIM-006"):
            return f"Reduce amount to within limit, or request approval for exception."
        if iid == "LIM-002":
            remaining = self.abox.daily_limit - args.get("amount", 0)
            _, acct_data = _acct_for_args(self.abox, args)
            if acct_data:
                remaining = self.abox.daily_limit - acct_data.daily_transfer_total
            return f"Reduce transfer to ≤${remaining:,.0f} (remaining daily cap), or schedule for tomorrow."
        if iid == "LIM-004":
            return "Use domestic wire for this amount, or split across days with int'l limit."
        if iid == "LIM-005":
            return "File CTR before completing withdrawal, or reduce amount below threshold."
        if iid == "AML-001":
            return "STOP — this beneficiary is sanctioned. Do not execute. Escalate to compliance."
        if iid == "AML-002":
            return f"Structuring pattern detected. File SAR, do not execute this transfer; consolidate into reported single transfer."
        if iid == "ACC-001":
            return "Check actual balance; reduce amount or notify client of insufficient funds."
        if iid == "ACC-002":
            return f"Account is {self.abox.accounts.get(args.get('from_account',''), None) and self.abox.accounts[args['from_account']].status}. Cannot transact."
        if iid == "APPR-001":
            return f"Request maker-checker approval before executing (amount >${self.abox.maker_checker_threshold:,.0f})."
        if iid == "APPR-004":
            return "Complete SAR review before proceeding with this transfer."
        if iid.startswith("SUIT"):
            return "Reassess trade for suitability; consider recommending a product matching client profile."
        # Generic suggestion
        return "Review the violated constraint and propose a compliant alternative action."


def _acct_for_args(abox: ABox, args: dict):
    from_acct = args.get("from_account", "")
    acct = abox.accounts.get(from_acct)
    if acct:
        cid = acct.client_id
        return abox.clients.get(cid), acct
    cid = args.get("client_id", "")
    return abox.clients.get(cid), None
