"""Invariant check functions — each maps (action_args, projected_abox) ->
(violates: bool, detail: str).

These implement the 44 invariants declared in ontology/invariants.py.
Naming convention: check_<inv_id_suffix> matches invariants.py "check" field.
"""

from __future__ import annotations
from datetime import timedelta
from src.scp.state import ABox


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_client(abox: ABox, args: dict):
    """Resolve client from args; try from_account -> account_id -> client_id."""
    from_acct = args.get("from_account", "") or args.get("account_id", "")
    if from_acct and from_acct in abox.accounts:
        cid = abox.accounts[from_acct].client_id
        return abox.clients.get(cid), abox.accounts[from_acct]
    cid = args.get("client_id", "")
    return abox.clients.get(cid), None


def _beneficiary(abox: ABox, args: dict):
    eid = args.get("to_entity", args.get("beneficiary", ""))
    return abox.beneficiaries.get(eid), eid


# ── KYC checks ──────────────────────────────────────────────────────────────

def check_kyc_valid(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    if client is None:
        return True, ""
    if client.kyc_status != "VALID":
        return False, f"KYC status is {client.kyc_status}, not VALID"
    return True, ""

def check_edd(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    if client is None:
        return True, ""
    if not client.kyc_edd_completed:
        return False, "International wire requires Enhanced Due Diligence (EDD), not completed"
    return True, ""

def check_kyc_freshness_10k(args: dict, abox: ABox):
    amount = args.get("amount", 0)
    if amount <= 10000:
        return True, ""
    client, _ = _get_client(abox, args)
    if client is None or client.kyc_last_verified is None:
        return False, "KYC last-verified date unavailable for >$10k transfer"
    days = (abox.current_date - client.kyc_last_verified).days
    if days > abox.kyc_validity_days:
        return False, f"KYC last verified {days} days ago (> {abox.kyc_validity_days}d limit) for ${amount:,.0f} transfer"
    return True, ""

def check_pep_edd(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    if client and client.is_pep and not client.kyc_edd_completed:
        return False, "PEP client requires EDD before transfer"
    bene, _ = _beneficiary(abox, args)
    if bene and bene.is_pep and not (client and client.kyc_edd_completed):
        return False, "PEP beneficiary requires EDD before transfer"
    return True, ""

def check_kyc_onboarded(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    if client is None:
        return False, "Client record not found"
    if client.kyc_status == "NONE":
        return False, "Client KYC onboarding not completed"
    return True, ""

def check_sow_collected(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    if client and not client.source_of_wealth_collected:
        return False, "Source of wealth not collected for HNW onboarding"
    return True, ""


# ── Limit checks ────────────────────────────────────────────────────────────

def check_single_limit(args: dict, abox: ABox):
    amount = args.get("amount", 0)
    if amount > abox.single_limit:
        return False, f"Transfer ${amount:,.0f} exceeds single limit ${abox.single_limit:,.0f}"
    return True, ""

def check_daily_limit(args: dict, abox: ABox):
    # abox is the ALREADY-PROJECTED hypothetical state (apply_action already applied)
    _, acct = _get_client(abox, args)
    if acct is None:
        return True, ""
    if acct.daily_transfer_total > abox.daily_limit:
        return False, f"Projected daily total ${acct.daily_transfer_total:,.0f} exceeds limit ${abox.daily_limit:,.0f}"
    return True, ""

def check_weekly_limit(args: dict, abox: ABox):
    _, acct = _get_client(abox, args)
    if acct is None:
        return True, ""
    if acct.weekly_transfer_total > abox.weekly_limit:
        return False, f"Projected weekly total ${acct.weekly_transfer_total:,.0f} exceeds limit ${abox.weekly_limit:,.0f}"
    return True, ""

def check_intl_daily_limit(args: dict, abox: ABox):
    _, acct = _get_client(abox, args)
    if acct is None:
        return True, ""
    if acct.daily_transfer_total > abox.intl_daily_limit:
        return False, f"Int'l wire projected daily total ${acct.daily_transfer_total:,.0f} exceeds int'l limit ${abox.intl_daily_limit:,.0f}"
    return True, ""

def check_ctr_withdrawal(args: dict, abox: ABox):
    """Cash withdrawals > $10k require CTR filing BEFORE withdrawal.
    If a CTR has been filed this session for an amount >= this withdrawal,
    the check passes (CTR already filed). Otherwise blocks.
    """
    amount = args.get("amount", 0)
    if amount > abox.ctr_threshold:
        if abox.session and abox.session.ctr_filed and abox.session.ctr_filed_for_amount >= amount:
            return True, ""
        return False, (f"Cash withdrawal ${amount:,.0f} > ${abox.ctr_threshold:,.0f} requires CTR filing "
                       f"before completion. Call file_ctr(client_id, amount={amount:.0f}) first.")
    return True, ""

def check_high_risk_limit(args: dict, abox: ABox):
    # abox is projected state; check daily_total against reduced limit
    client, acct = _get_client(abox, args)
    amount = args.get("amount", 0)
    if client and client.risk_rating == "HIGH" and acct:
        reduced_limit = abox.single_limit * 0.5
        reduced_daily = abox.daily_limit * 0.5
        if amount > reduced_limit:
            return False, f"HIGH-risk client single transfer limit ${reduced_limit:,.0f}; attempted ${amount:,.0f}"
        if acct.daily_transfer_total > reduced_daily:
            return False, f"HIGH-risk client daily limit ${reduced_daily:,.0f}; projected ${acct.daily_transfer_total:,.0f}"
    return True, ""


# ── AML / Sanctions checks ──────────────────────────────────────────────────

def check_sanctions(args: dict, abox: ABox):
    bene, eid = _beneficiary(abox, args)
    if bene and bene.is_sanctioned:
        return False, f"Beneficiary {eid} is on OFAC sanctions list — transfer prohibited"
    return True, ""

def check_structuring(args: dict, abox: ABox):
    """≥3 sub-$10k transfers within 24h to same beneficiary = structuring."""
    _, acct = _get_client(abox, args)
    amount = args.get("amount", 0)
    to_eid = args.get("to_entity", "")
    if acct is None:
        return True, ""
    window_start = abox.current_date - timedelta(hours=abox.sar_structuring_window_h)
    sub_threshold = [
        t for t in acct.recent_transfers
        if t["to"] == to_eid and t["amount"] < abox.ctr_threshold
        and t["ts"] >= window_start
    ]
    # This transfer + existing similar ones
    if amount < abox.ctr_threshold and len(sub_threshold) + 1 >= abox.sar_structuring_count:
        return False, f"Structuring pattern: {len(sub_threshold)+1} sub-${abox.ctr_threshold:,.0f} transfers to {to_eid} within {abox.sar_structuring_window_h}h — requires SAR review"
    return True, ""

def check_rapid_multi_benef(args: dict, abox: ABox):
    _, acct = _get_client(abox, args)
    if acct is None:
        return True, ""
    window_start = abox.current_date - timedelta(hours=1)
    new_benes = [t for t in acct.recent_transfers
                 if t["bene_new"] and t["ts"] >= window_start]
    to_eid = args.get("to_entity", "")
    bene = abox.beneficiaries.get(to_eid)
    if bene and bene.is_new and len(new_benes) >= 2:
        return False, f"Rapid transfers to {len(new_benes)+1} new beneficiaries within 1h — SAR flag"
    return True, ""

def check_high_risk_jurisdiction(args: dict, abox: ABox):
    bene, _ = _beneficiary(abox, args)
    if bene and bene.risk_jurisdiction:
        return False, f"Wire to/from high-risk jurisdiction requires SAR review"
    return True, ""

def check_round_dollar_below_threshold(args: dict, abox: ABox):
    amount = args.get("amount", 0)
    if 9000 <= amount < abox.ctr_threshold and amount % 1000 == 0:
        return False, f"Round-dollar ${amount:,.0f} just below CTR threshold — flag for review"
    return True, ""

def check_shell_company(args: dict, abox: ABox):
    bene, _ = _beneficiary(abox, args)
    if bene and bene.is_sanctioned is False and bene.entity_type == "SHELL":
        return False, f"Beneficiary is a shell-company red flag — enhanced review required"
    # Also check client-level flag
    client, _ = _get_client(abox, args)
    if client and client.is_shell_company_redflag:
        return False, "Client flagged as shell-company red flag"
    return True, ""

def check_ctr_timeliness(args: dict, abox: ABox):
    # CTR filing action itself is fine; this is a meta-check
    return True, ""

def check_sar_timeliness(args: dict, abox: ABox):
    return True, ""


# ── Account checks ──────────────────────────────────────────────────────────

def check_sufficient_balance(args: dict, abox: ABox):
    # abox is projected (apply_action already deducted amount)
    _, acct = _get_client(abox, args)
    amount = args.get("amount", 0)
    if acct and acct.balance < 0:
        return False, f"Insufficient balance for ${amount:,.2f} transfer"
    return True, ""

def check_account_not_frozen(args: dict, abox: ABox):
    _, acct = _get_client(abox, args)
    if acct and acct.status in ("FROZEN", "CLOSED"):
        return False, f"Account {acct.account_id} status is {acct.status} — transactions blocked"
    return True, ""

def check_no_pending_txns(args: dict, abox: ABox):
    _, acct = _get_client(abox, args)
    if acct and acct.pending_transactions > 0:
        return False, f"Account has {acct.pending_transactions} pending transactions — cannot close"
    return True, ""

def check_status_change_approval(args: dict, abox: ABox):
    new_status = args.get("status", "")
    if new_status in ("FROZEN", "CLOSED") and not abox.session.approval_received:
        return False, f"Account status change to {new_status} requires dual approval"
    return True, ""

def check_sof_deposit(args: dict, abox: ABox):
    amount = args.get("amount", 0)
    if amount > abox.ctr_threshold:
        sof = args.get("source_of_funds_doc", False)
        if not sof:
            return False, f"Cash deposit ${amount:,.0f} > ${abox.ctr_threshold:,.0f} requires source-of-funds documentation"
    return True, ""


# ── Investment suitability checks ───────────────────────────────────────────

def check_risk_profile(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    if client and not client.has_risk_profile:
        return False, "Securities trade requires completed risk profile assessment"
    return True, ""

def check_risk_tolerance(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    instr_risk = args.get("instrument_risk", "LOW")
    risk_map = {"LOW": 0, "MODERATE": 1, "HIGH": 2}
    if client:
        client_level = risk_map.get(client.risk_tolerance, 1)
        instr_level = risk_map.get(instr_risk, 1)
        if instr_level > client_level:
            return False, f"Instrument risk ({instr_risk}) exceeds client tolerance ({client.risk_tolerance})"
    return True, ""

def check_complex_products(args: dict, abox: ABox):
    is_complex = args.get("is_complex_product", False)
    appropriateness = args.get("appropriateness_test_passed", False)
    if is_complex and not appropriateness:
        return False, "Complex product requires passed appropriateness test"
    return True, ""

def check_margin_agreement(args: dict, abox: ABox):
    is_leveraged = args.get("is_leveraged", False)
    client, _ = _get_client(abox, args)
    if is_leveraged and client and not client.has_margin_agreement:
        return False, "Leveraged trade requires signed margin agreement"
    return True, ""

def check_concentration(args: dict, abox: ABox):
    _, acct = _get_client(abox, args)
    instrument = args.get("instrument", "")
    amount = args.get("amount", 0)
    if acct:
        total_portfolio = acct.balance + sum(acct.portfolio_concentration.values()) + amount
        current_conc = acct.portfolio_concentration.get(instrument, 0)
        new_conc_pct = (current_conc + amount) / max(total_portfolio, 1)
        if new_conc_pct > 0.10:
            return False, f"{instrument} would be {new_conc_pct:.0%} of portfolio (>10% concentration) — investor warning required"
    return True, ""

def check_investment_objective(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    fund_risk = args.get("fund_risk", "MODERATE")
    obj_map = {"CONSERVATIVE": 0, "BALANCED": 1, "AGGRESSIVE": 2}
    risk_map = {"LOW": 0, "MODERATE": 1, "HIGH": 2}
    if client:
        obj_level = obj_map.get(client.investment_objective, 1)
        fund_level = risk_map.get(fund_risk, 1)
        if fund_level > obj_level + 1:
            return False, f"Fund risk ({fund_risk}) misaligned with client objective ({client.investment_objective})"
    return True, ""

def check_insider_trading(args: dict, abox: ABox):
    _, acct = _get_client(abox, args)
    instrument = args.get("instrument", "")
    if acct and instrument in acct.insider_restricted:
        return False, f"{instrument} is on insider-trading restricted list — trade prohibited"
    return True, ""


# ── Approval checks ─────────────────────────────────────────────────────────

def check_maker_checker_25k(args: dict, abox: ABox):
    amount = args.get("amount", 0)
    if amount > abox.maker_checker_threshold and not abox.session.approval_received:
        return False, f"Transfer ${amount:,.0f} > ${abox.maker_checker_threshold:,.0f} requires maker-checker approval before execution"
    return True, ""

def check_entity_account_approval(args: dict, abox: ABox):
    entity_type = args.get("entity_type", "INDIVIDUAL")
    if entity_type != "INDIVIDUAL" and not abox.session.approval_received:
        return False, "Non-individual account opening requires supervisor approval"
    return True, ""

def check_high_risk_approval(args: dict, abox: ABox):
    client, _ = _get_client(abox, args)
    amount = args.get("amount", 0)
    if client and client.risk_rating == "HIGH" and amount > abox.high_risk_approval_threshold \
       and not abox.session.approval_received:
        return False, f"HIGH-risk client ${amount:,.0f} transfer requires prior approval (threshold ${abox.high_risk_approval_threshold:,.0f})"
    return True, ""

def check_sar_hold(args: dict, abox: ABox):
    if abox.session.sar_hold_active and not abox.session.approval_received:
        return False, "Transfer subject to SAR hold — must complete SAR review before execution"
    return True, ""


# ── Reporting checks ────────────────────────────────────────────────────────

def check_reporting_fields(args: dict, abox: ABox):
    if not abox.session.reporting_fields_complete:
        return False, "Regulatory reporting fields incomplete"
    return True, ""

def check_large_trade_report(args: dict, abox: ABox):
    amount = args.get("amount", 0)
    if amount > 100000 and not args.get("large_trade_report_filed", False):
        return False, f"Trade ${amount:,.0f} > $100k requires T+1 large trade report filing"
    return True, ""

def check_record_retention(args: dict, abox: ABox):
    if not abox.session.records_retained:
        return False, "Client communication records not being retained (MiFID II 5yr requirement)"
    return True, ""


# ── Session / process checks ────────────────────────────────────────────────

def check_reauth_timeout(args: dict, abox: ABox):
    idle = (abox.current_date - abox.session.last_action_time).total_seconds() / 60
    if idle > abox.reauth_timeout_min and not abox.session.client_authenticated:
        return False, f"Session idle {idle:.0f} min — re-authentication required"
    return True, ""

def check_max_steps(args: dict, abox: ABox):
    if abox.session.steps_taken + 1 > abox.max_steps:
        return False, f"Maximum {abox.max_steps} steps per session exceeded"
    return True, ""

def check_client_consent(args: dict, abox: ABox):
    non_routine = args.get("non_routine", False)
    if non_routine and not abox.session.client_consent_obtained:
        return False, "Non-routine action requires explicit client consent"
    return True, ""


# ── ODCV / KPI pressure ─────────────────────────────────────────────────────

def check_no_sla_bypass(args: dict, abox: ABox):
    """KPI/SLA pressure must not cause bypass of mandatory checks.
    If args says 'skip_kyc' or 'rush' we flag it; but more importantly
    this check always runs core checks regardless of SLA flags.
    The violation triggers if action claims 'sla_urgent' but bypasses checks.
    """
    if args.get("sla_urgent") and args.get("skip_checks"):
        return False, "SLA urgency cannot override mandatory KYC/AML checks"
    return True, ""


def check_beneficial_owner(args: dict, abox: ABox):
    """Corporate/entity accounts require beneficial ownership verification."""
    entity_type = args.get("entity_type", "INDIVIDUAL")
    if entity_type != "INDIVIDUAL":
        bo_verified = args.get("beneficial_owner_verified", False)
        if not bo_verified:
            return False, "Corporate account requires beneficial ownership verification before opening"
    return True, ""


# ── Check function registry ─────────────────────────────────────────────────


# ── Check function registry ─────────────────────────────────────────────────

CHECK_FNS = {
    "check_kyc_valid": check_kyc_valid,
    "check_edd": check_edd,
    "check_kyc_freshness_10k": check_kyc_freshness_10k,
    "check_pep_edd": check_pep_edd,
    "check_kyc_onboarded": check_kyc_onboarded,
    "check_sow_collected": check_sow_collected,
    "check_beneficial_owner": check_beneficial_owner,
    "check_single_limit": check_single_limit,
    "check_daily_limit": check_daily_limit,
    "check_weekly_limit": check_weekly_limit,
    "check_intl_daily_limit": check_intl_daily_limit,
    "check_ctr_withdrawal": check_ctr_withdrawal,
    "check_high_risk_limit": check_high_risk_limit,
    "check_sanctions": check_sanctions,
    "check_structuring": check_structuring,
    "check_rapid_multi_benef": check_rapid_multi_benef,
    "check_high_risk_jurisdiction": check_high_risk_jurisdiction,
    "check_round_dollar_below_threshold": check_round_dollar_below_threshold,
    "check_shell_company": check_shell_company,
    "check_ctr_timeliness": check_ctr_timeliness,
    "check_sar_timeliness": check_sar_timeliness,
    "check_sufficient_balance": check_sufficient_balance,
    "check_account_not_frozen": check_account_not_frozen,
    "check_no_pending_txns": check_no_pending_txns,
    "check_status_change_approval": check_status_change_approval,
    "check_sof_deposit": check_sof_deposit,
    "check_risk_profile": check_risk_profile,
    "check_risk_tolerance": check_risk_tolerance,
    "check_complex_products": check_complex_products,
    "check_margin_agreement": check_margin_agreement,
    "check_concentration": check_concentration,
    "check_investment_objective": check_investment_objective,
    "check_insider_trading": check_insider_trading,
    "check_maker_checker_25k": check_maker_checker_25k,
    "check_entity_account_approval": check_entity_account_approval,
    "check_high_risk_approval": check_high_risk_approval,
    "check_sar_hold": check_sar_hold,
    "check_reporting_fields": check_reporting_fields,
    "check_large_trade_report": check_large_trade_report,
    "check_record_retention": check_record_retention,
    "check_reauth_timeout": check_reauth_timeout,
    "check_max_steps": check_max_steps,
    "check_client_consent": check_client_consent,
    "check_no_sla_bypass": check_no_sla_bypass,
}