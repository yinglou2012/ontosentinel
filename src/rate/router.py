"""RATE: Risk-Aware Tiered Execution router.

Computes linear risk score ρ = w1·φ_rev + w2·φ_sens + w3·φ_thresh + w4·φ_crit
Routes to AUTO / APPROVE / REJECT tiers.

Weights and thresholds are deployment-calibrated (not universal constants).
Financial defaults per SR 11-7 / maker-checker best practices.
"""

from __future__ import annotations
from dataclasses import dataclass
import math


@dataclass
class RATEResult:
    rho: float
    phi_rev: float
    phi_sens: float
    phi_thresh: float
    phi_crit: float
    tier: str        # "AUTO" / "APPROVE" / "REJECT"
    reason: str


class RATERouter:
    def __init__(self, weights: dict | None = None, thresholds: dict | None = None):
        w = weights or {}
        self.w_rev   = w.get("phi_rev",   0.25)
        self.w_sens  = w.get("phi_sens",  0.20)
        self.w_thresh = w.get("phi_thresh", 0.35)
        self.w_crit  = w.get("phi_crit",  0.20)
        t = thresholds or {}
        self.theta_auto = t.get("theta_auto", 0.30)
        self.theta_appr = t.get("theta_appr", 0.85)

    def score(self, action_type: str, args: dict, abox, revision_round: int = 0,
              violations_before_commit: list | None = None) -> RATEResult:
        """Compute ρ and route to tier."""
        phi_rev   = self._phi_rev(revision_round)
        phi_sens  = self._phi_sens(action_type, args, abox)
        phi_thresh = self._phi_thresh(action_type, args, abox)
        phi_crit  = self._phi_crit(action_type, args, abox)

        rho = (self.w_rev * phi_rev + self.w_sens * phi_sens
               + self.w_thresh * phi_thresh + self.w_crit * phi_crit)
        rho = min(max(rho, 0.0), 1.0)

        if rho <= self.theta_auto:
            tier = "AUTO"
            reason = f"ρ={rho:.2f} ≤ θ_auto={self.theta_auto}: low risk, auto-execute"
        elif rho <= self.theta_appr:
            tier = "APPROVE"
            reason = f"ρ={rho:.2f} in ({self.theta_auto},{self.theta_appr}]: requires maker-checker approval"
        else:
            tier = "REJECT"
            reason = f"ρ={rho:.2f} > θ_appr={self.theta_appr}: high risk, reject"

        return RATEResult(
            rho=rho, phi_rev=phi_rev, phi_sens=phi_sens,
            phi_thresh=phi_thresh, phi_crit=phi_crit,
            tier=tier, reason=reason,
        )

    # ── Factor computations ──────────────────────────────────────────────

    def _phi_rev(self, rev_round: int) -> float:
        """Revision-round factor: 0 on first pass, grows with revisions.
        φ_rev = min(1, r/R) where r = revision round, R = max rounds (3)."""
        R = 3
        return min(1.0, rev_round / R)

    def _phi_sens(self, action_type: str, args: dict, abox) -> float:
        """Object-sensitivity factor based on beneficiary/client risk.
        0 = normal, 1 = critical sensitivity (sanctioned/PEP/high-risk jur)."""
        score = 0.0
        # Beneficiary checks
        bene_id = args.get("to_entity", "")
        bene = abox.beneficiaries.get(bene_id)
        if bene:
            if bene.is_sanctioned:
                return 1.0   # maximum sensitivity
            if bene.is_pep:
                score = max(score, 0.7)
            if bene.risk_jurisdiction:
                score = max(score, 0.6)
            if bene.entity_type == "SHELL":
                score = max(score, 0.8)
            if bene.is_new:
                score = max(score, 0.3)
        # Client risk
        from_acct = args.get("from_account", "") or args.get("account_id", "")
        acct = abox.accounts.get(from_acct)
        if acct:
            client = abox.clients.get(acct.client_id)
            if client:
                if client.is_pep:
                    score = max(score, 0.7)
                if client.risk_rating == "HIGH":
                    score = max(score, 0.5)
                if client.risk_rating == "MEDIUM":
                    score = max(score, 0.2)
        # International wires slightly higher sensitivity
        if action_type == "InternationalWire":
            score = max(score, 0.35)
        return score

    def _phi_thresh(self, action_type: str, args: dict, abox) -> float:
        """Threshold-proximity factor: how close to the regulatory/limit boundary.
        Uses power-law scaling: (amount/limit)^0.7 to weight near-threshold actions."""
        amount = args.get("amount", 0)
        from_acct = args.get("from_account", "") or args.get("account_id", "")
        acct = abox.accounts.get(from_acct)
        if acct is None:
            return 0.0

        # Determine applicable limit
        if action_type == "InternationalWire":
            limit = abox.intl_daily_limit
        else:
            limit = abox.daily_limit

        # Client risk reduces effective limit
        client = abox.clients.get(acct.client_id)
        if client and client.risk_rating == "HIGH":
            limit *= 0.5

        projected_total = acct.daily_transfer_total + amount
        if limit <= 0:
            return 1.0
        ratio = projected_total / limit
        ratio = min(ratio, 1.5)   # cap at 1.5 to avoid runaway

        # Power scaling: sub-linear to amplify near-threshold; take the max
        # of daily-proximity and single-limit-proximity so either being close
        # escalates risk (fixes bug where single_ratio was dead code due to
        # redundant min/max nesting).
        single_ratio = amount / abox.single_limit
        phi = max(ratio ** 0.7, min(single_ratio ** 0.7, 1.0))
        return min(phi, 1.0)

    def _phi_crit(self, action_type: str, args: dict, abox) -> float:
        """Dependency-criticality / aggregate severity factor.
        Captures how many constraints are already tense in the current trace."""
        score = 0.0
        from_acct = args.get("from_account", "")
        acct = abox.accounts.get(from_acct)
        amount = args.get("amount", 0)
        if acct is None:
            return 0.0

        # How many recent transfers in structuring window
        window_start = abox.current_date - __import__("datetime").timedelta(hours=24)
        recent_24h = [t for t in acct.recent_transfers if t["ts"] >= window_start]
        if len(recent_24h) >= 2:
            score += 0.3 * min(len(recent_24h) / 3, 1.0)
        # SAR hold active
        if abox.session.sar_hold_active:
            score += 0.4
        # High risk rating
        client = abox.clients.get(acct.client_id)
        if client:
            if client.risk_rating == "HIGH":
                score += 0.25
            if client.is_pep:
                score += 0.2
        # Large relative to balance
        if acct.balance > 0 and amount / acct.balance > 0.5:
            score += 0.15
        # Near approval threshold flow
        daily_ratio = acct.daily_transfer_total / abox.daily_limit
        if daily_ratio > 0.6:
            score += 0.2 * daily_ratio
        return min(score, 1.0)
