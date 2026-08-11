"""Counterfactual Repair Generation for SCP.

When SCP detects a violation, this module generates actionable repair
suggestions by searching the parameter space or recommending prerequisite
actions. Each violation is classified into one of three repairability
categories:

  - parameter:  adjust a numeric argument (e.g., reduce amount)
  - precondition: insert a missing prerequisite action (e.g., KYCRefresh)
  - none:        not repairable by parameter/precondition change
                 (e.g., sanctioned beneficiary, frozen account)

The counterfactual search uses the existing check functions
(CHECK_FNS) to verify candidate fixes, ensuring that suggestions are
grounded in formal ontological reasoning rather than LLM hallucination.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from ontology.invariants import get_invariants_for_action, get_invariant_by_id
from src.scp.state import ABox
from src.scp.checks import CHECK_FNS


# ── Repairability classification ────────────────────────────────────────────

# Violations where a numeric parameter adjustment can fix the issue.
# Maps inv_id -> the argument key that should be adjusted.
PARAMETER_REPAIRABLE: dict[str, str] = {
    "LIM-001": "amount",       # single transfer limit exceeded → reduce amount
    "LIM-002": "amount",       # daily limit exceeded → reduce amount
    "LIM-003": "amount",       # weekly limit exceeded → reduce amount
    "LIM-004": "amount",       # international daily limit → reduce amount
    "LIM-005": "amount",       # CTR threshold → reduce below threshold
    "LIM-006": "amount",       # high-risk single limit → reduce amount
    "ACC-001": "amount",       # insufficient balance → reduce amount
    "APPR-001": "amount",      # maker-checker threshold → reduce below threshold
    "APPR-003": "amount",      # high-risk approval threshold → reduce amount
    "REP-002": "amount",       # large trade report → reduce below $100k
    # AML-003 (rapid multi-beneficiary) removed: triggered by beneficiary
    #   newness + count, not amount. Not parameter-fixable.
    # AML-004 (high-risk jurisdiction) removed: triggered by beneficiary
    #   jurisdiction attribute, not amount. Not parameter-fixable.
    # SUIT-003 (complex products) removed: checks is_complex_product and
    #   appropriateness_test_passed booleans, not amount. Not parameter-fixable.
    #   (SUIT-005 concentration limit IS amount-fixable but uses check_concentration.)
}

# Violations where inserting a prerequisite action can fix the issue.
# Maps inv_id -> (prerequisite action_type, description).
PRECONDITION_REPAIRABLE: dict[str, tuple[str, str]] = {
    "KYC-001": ("KYCRefresh", "Call KYCRefresh for this client, then resubmit the transfer."),
    "KYC-002": ("KYCRefresh", "Complete Enhanced Due Diligence (EDD) via KYCRefresh, then resubmit."),
    "KYC-003": ("KYCRefresh", "KYC is stale. Call KYCRefresh to re-verify, then resubmit."),
    "KYC-004": ("KYCRefresh", "PEP requires EDD. Call KYCRefresh to complete EDD, then resubmit."),
    "KYC-005": ("KYCRefresh", "Client onboarding incomplete. Call KYCRefresh, then resubmit."),
    "KYC-006": ("KYCRefresh", "Source of wealth not collected. Call KYCRefresh, then resubmit."),
    "CTR-001": ("file_ctr", "File CTR before completing this withdrawal."),
    "SAR-002": ("file_sar", "File SAR to clear the hold, then resubmit the transfer."),
    "SAR-003": ("file_sar", "Complete SAR review before proceeding."),
}

# Violations that cannot be repaired by parameter/precondition change.
# These require external intervention (compliance team, account unfreezing, etc.)
NOT_REPAIRABLE: set[str] = {
    "AML-001",   # sanctioned beneficiary — must reject, no parameter fix
    "AML-002",   # structuring pattern already detected — must file SAR, not retry
    "AML-003",   # rapid multi-beneficiary — triggered by count/newness, not amount
    "AML-004",   # high-risk jurisdiction — triggered by beneficiary attribute, not amount
    "AML-005",   # round-dollar below threshold — requires review, not parameter fix
    "AML-006",   # shell company — enhanced review required, not parameter fix
    "ACC-002",   # account frozen/closed — requires external action
    "ACC-003",   # pending transactions blocking close — requires external resolution
    "ACC-004",   # status change requires dual approval — requires human approval
    "SUIT-001",  # risk profile not completed — requires client assessment
    "SUIT-002",  # risk tolerance mismatch — requires reassessment
    "SUIT-003",  # complex product appropriateness — requires client test (booleans, not amount)
    "SUIT-004",  # margin agreement missing — requires signed agreement
    "SUIT-005",  # concentration limit — requires portfolio rebalancing, not parameter fix
    "SUIT-007",  # insider trading restriction — legal restriction, no parameter fix
    "SUIT-008",  # investment objective misalignment — requires reassessment
    "ACC-005",   # source of funds documentation — requires external document
    "ENT-001",   # beneficial owner verification — requires external verification
    "SLA-001",   # SLA bypass — policy violation, not parameter fixable
    "REP-001",   # reporting fields incomplete — requires data completion
    "REP-003",   # record retention — process requirement
    "SES-001",   # reauth timeout — requires re-authentication
    "SES-002",   # max steps exceeded — session limit
    "SES-003",   # client consent — requires explicit consent
}


@dataclass
class CounterfactualResult:
    """Result of counterfactual repair generation for a single violation."""
    inv_id: str
    fixable: str  # "parameter" | "precondition" | "none"
    suggested_fix: str = ""
    suggested_args: dict | None = None        # modified args that pass verification
    suggested_prerequisite: tuple[str, str] | None = None  # (action_type, description)
    search_iterations: int = 0                 # how many verification attempts were tried
    search_time_ms: float = 0.0

    def format_feedback(self) -> str:
        if self.fixable == "none":
            return f"[{self.inv_id}] Not auto-repairable. Escalate to human review."
        if self.fixable == "parameter" and self.suggested_fix:
            return f"[{self.inv_id}] Suggested fix: {self.suggested_fix}"
        if self.fixable == "precondition" and self.suggested_prerequisite:
            return f"[{self.inv_id}] Suggested prerequisite: {self.suggested_prerequisite[1]}"
        return f"[{self.inv_id}] No suggestion available."


@dataclass
class CounterfactualBundle:
    """Aggregated counterfactual results for all violations in a single action."""
    results: list[CounterfactualResult] = field(default_factory=list)
    has_any_fixable: bool = False
    primary_fix: str = ""  # the most actionable suggestion, formatted for LLM injection

    def build_feedback(self) -> str:
        """Build a single feedback string for injection into LLM context."""
        if not self.results:
            return ""
        lines = ["[OntoSentinel Counterfactual Guidance]"]
        any_fix = False
        for r in self.results:
            if r.fixable != "none":
                any_fix = True
                lines.append(f"  • {r.format_feedback()}")
            else:
                lines.append(f"  • {r.format_feedback()}")
        if any_fix:
            lines.append("\nRevise your action based on the suggestions above and resubmit.")
        else:
            lines.append("\nNone of the violations are auto-repairable. Escalate to human review.")
        self.has_any_fixable = any_fix
        self.primary_fix = "\n".join(lines)
        return self.primary_fix


# ── Counterfactual search engine ────────────────────────────────────────────

class CounterfactualEngine:
    """Generates counterfactual repair suggestions using rule-based verification."""

    # Binary search config for parameter repair
    MAX_BINARY_SEARCH_ITERS = 8
    # How much to reduce amount by in each step (fraction)
    INITIAL_REDUCTION_RATIO = 0.5

    def __init__(self, abox: ABox):
        self.abox = abox

    def generate(self, inv_id: str, action_type: str, args: dict,
                 violations: list, all_violations: list) -> CounterfactualResult:
        """Generate counterfactual for a single violation.

        Args:
            inv_id: The invariant ID that was violated.
            action_type: The action type that was attempted.
            args: The original action arguments.
            violations: The Violation objects from this action.
            all_violations: All violations (for multi-violation awareness).
        """
        import time
        t0 = time.time()

        # Classify repairability
        if inv_id in NOT_REPAIRABLE:
            return CounterfactualResult(
                inv_id=inv_id, fixable="none",
                search_time_ms=(time.time() - t0) * 1000,
            )

        if inv_id in PRECONDITION_REPAIRABLE:
            prereq = PRECONDITION_REPAIRABLE[inv_id]
            return CounterfactualResult(
                inv_id=inv_id,
                fixable="precondition",
                suggested_prerequisite=prereq,
                suggested_fix=prereq[1],
                search_time_ms=(time.time() - t0) * 1000,
            )

        if inv_id in PARAMETER_REPAIRABLE:
            param_key = PARAMETER_REPAIRABLE[inv_id]
            result = self._search_parameter(inv_id, action_type, args, param_key)
            result.search_time_ms = (time.time() - t0) * 1000
            return result

        # Unknown violation — default to not repairable
        return CounterfactualResult(
            inv_id=inv_id, fixable="none",
            search_time_ms=(time.time() - t0) * 1000,
        )

    def _search_parameter(self, inv_id: str, action_type: str,
                          args: dict, param_key: str) -> CounterfactualResult:
        """Binary search for a compliant parameter value.

        Strategy:
        1. Try reducing by 50%, then binary search between 0 and original.
        2. Each candidate is verified by running ALL applicable invariants
           on the hypothetical projected state (same invariant checks SCP uses).
        """
        original_value = args.get(param_key, 0)
        if not isinstance(original_value, (int, float)) or original_value <= 0:
            return CounterfactualResult(inv_id=inv_id, fixable="none")

        best_fix = None
        iterations = 0

        # Binary search: find the maximum value that passes all checks
        lo = 0.0
        hi = float(original_value)

        for i in range(self.MAX_BINARY_SEARCH_ITERS):
            iterations += 1
            mid = (lo + hi) / 2.0

            # Round to nearest dollar for cleanliness
            mid = round(mid)

            if mid <= 0:
                break

            # Build candidate args
            candidate_args = dict(args)
            candidate_args[param_key] = mid

            # Verify candidate against ALL applicable invariants (not just the
            # violated one — reducing amount might not fix a KYC issue)
            if self._verify_candidate(action_type, candidate_args):
                best_fix = mid
                lo = mid  # try higher
            else:
                hi = mid  # try lower

        if best_fix is not None:
            suggested_args = dict(args)
            suggested_args[param_key] = best_fix
            suggested_fix = (
                f"Reduce {param_key} from ${original_value:,.0f} to ≤${best_fix:,.0f} "
                f"to satisfy {inv_id}."
            )
            return CounterfactualResult(
                inv_id=inv_id,
                fixable="parameter",
                suggested_fix=suggested_fix,
                suggested_args=suggested_args,
                search_iterations=iterations,
            )

        return CounterfactualResult(
            inv_id=inv_id, fixable="none",
            search_iterations=iterations,
        )

    def _verify_candidate(self, action_type: str, args: dict) -> bool:
        """Verify a candidate action against all applicable invariants.

        Uses the same check functions as SCP.verify() — this is the rule-based
        verification that ensures the suggestion is ontologically grounded.
        """
        # Ensure session exists (in case counterfactual runs before env sets it)
        if self.abox.session is None:
            from src.scp.state import SessionState
            self.abox.session = SessionState(session_id="cf_verify")

        # Build hypothetical projected state
        projected = self.abox.apply_action(action_type, args)

        # Get all applicable invariants for this action type
        applicable = get_invariants_for_action(action_type)

        for inv in applicable:
            fn = CHECK_FNS.get(inv["check"])
            if fn is None:
                continue
            try:
                ok, _ = fn(args, projected)
                if not ok:
                    return False
            except Exception as e:
                # If a check fails to run (e.g., missing state), log and
                # treat conservatively as failed rather than silently passing
                import logging
                logging.getLogger(__name__).warning(
                    "Counterfactual check %s raised %s for action %s args %s: %s",
                    inv.get("id", "?"), type(e).__name__, action_type, args, e,
                )
                return False

        return True

    def generate_bundle(self, violations: list, action_type: str,
                        args: dict) -> CounterfactualBundle:
        """Generate counterfactual suggestions for all violations in a single action.

        Args:
            violations: List of Violation objects from SCP.verify().
            action_type: The action type that was attempted.
            args: The original action arguments.
        """
        bundle = CounterfactualBundle()

        for v in violations:
            result = self.generate(
                inv_id=v.inv_id,
                action_type=action_type,
                args=args,
                violations=violations,
                all_violations=violations,
            )
            bundle.results.append(result)

        bundle.build_feedback()
        return bundle
