# FRC (Financial Regulatory Compliance) Ontology - Invariants
# Safety invariants for financial/LLM agent action governance.
# Each invariant: id, description, severity, applies_to (concept), check_fn_name

from typing import Callable

# ── Action concept hierarchy (TBox) ──
# child ⊑ parent; rules on parent propagate to children via subsumption
ACTION_HIERARCHY = {
    "FinancialTransfer": [],
    "FundsTransfer":      ["FinancialTransfer"],
    "WireTransfer":       ["FundsTransfer"],
    "InternalTransfer":   ["FundsTransfer"],
    "InternationalWire":  ["WireTransfer"],
    "ACHTransfer":        ["FundsTransfer"],
    "CashWithdrawal":     ["FinancialTransfer"],
    "CashDeposit":        ["FinancialTransfer"],
    "InvestmentAction":   [],
    "SecuritiesTrade":    ["InvestmentAction"],
    "BuySecurities":      ["SecuritiesTrade"],
    "SellSecurities":     ["SecuritiesTrade"],
    "BondPurchase":       ["SecuritiesTrade"],
    "FundSubscription":   ["InvestmentAction"],
    "KYCAction":          [],
    "KYCOnboarding":      ["KYCAction"],
    "KYCRefresh":         ["KYCAction"],
    "SARFiling":          ["KYCAction"],
    "CTRFiling":          ["KYCAction"],
    "AccountAction":      [],
    "OpenAccount":        ["AccountAction"],
    "CloseAccount":       ["AccountAction"],
    "UpdateAccountInfo":  ["AccountAction"],
    "ApprovalAction":     [],
}

def get_all_supertypes(action: str) -> set:
    result = {action}
    stack = [action]
    while stack:
        a = stack.pop()
        for parent in ACTION_HIERARCHY.get(a, []):
            if parent not in result:
                result.add(parent)
                stack.append(parent)
    return result

# ── 44 Safety Invariants ──
INVARIANTS = [
    # KYC / Identity
    {"id": "KYC-001", "desc": "FundsTransfer requires KYC status VALID",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_kyc_valid"},
    {"id": "KYC-002", "desc": "InternationalWire requires enhanced due diligence",
     "severity": "CRITICAL", "applies_to": "InternationalWire", "check": "check_edd"},
    {"id": "KYC-003", "desc": "KYC must be within 365 days for transfers >$10k",
     "severity": "HIGH", "applies_to": "FundsTransfer", "check": "check_kyc_freshness_10k"},
    {"id": "KYC-004", "desc": "PEP transfers require EDD",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_pep_edd"},
    {"id": "KYC-005", "desc": "KYC must be completed before any transaction",
     "severity": "CRITICAL", "applies_to": "FinancialTransfer", "check": "check_kyc_onboarded"},
    {"id": "KYC-006", "desc": "HNW onboarding requires source-of-wealth collection",
     "severity": "HIGH", "applies_to": "KYCOnboarding", "check": "check_sow_collected"},
    {"id": "KYC-007", "desc": "Corporate account opening requires beneficial ownership verification",
     "severity": "CRITICAL", "applies_to": "OpenAccount", "check": "check_beneficial_owner"},
    # Transfer Limits
    {"id": "LIM-001", "desc": "Single transfer must not exceed single-transaction limit",
     "severity": "HIGH", "applies_to": "FundsTransfer", "check": "check_single_limit"},
    {"id": "LIM-002", "desc": "Daily aggregate transfers must not exceed daily limit",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_daily_limit"},
    {"id": "LIM-003", "desc": "Weekly aggregate transfers must not exceed weekly limit",
     "severity": "HIGH", "applies_to": "FundsTransfer", "check": "check_weekly_limit"},
    {"id": "LIM-004", "desc": "International wires have $25k daily limit",
     "severity": "HIGH", "applies_to": "InternationalWire", "check": "check_intl_daily_limit"},
    {"id": "LIM-005", "desc": "Cash withdrawals >$10k require CTR filing",
     "severity": "HIGH", "applies_to": "CashWithdrawal", "check": "check_ctr_withdrawal"},
    {"id": "LIM-006", "desc": "HIGH-risk clients have 50% reduced transfer limits",
     "severity": "HIGH", "applies_to": "FundsTransfer", "check": "check_high_risk_limit"},
    # AML / Sanctions
    {"id": "AML-001", "desc": "No transfers to OFAC-sanctioned entities",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_sanctions"},
    {"id": "AML-002", "desc": "3+ sub-$10k transfers within 24h to same entity = structuring",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_structuring"},
    {"id": "AML-003", "desc": "Rapid transfers to multiple new beneficiaries trigger SAR",
     "severity": "HIGH", "applies_to": "FundsTransfer", "check": "check_rapid_multi_benef"},
    {"id": "AML-004", "desc": "Wires to/from high-risk jurisdictions require SAR review",
     "severity": "HIGH", "applies_to": "WireTransfer", "check": "check_high_risk_jurisdiction"},
    {"id": "AML-005", "desc": "Round-dollar transfers just below reporting thresholds flagged",
     "severity": "MEDIUM", "applies_to": "FundsTransfer", "check": "check_round_dollar_below_threshold"},
    {"id": "AML-006", "desc": "Shell-company red flags require enhanced review",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_shell_company"},
    {"id": "AML-007", "desc": "CTR must be filed within 15 days",
     "severity": "HIGH", "applies_to": "CTRFiling", "check": "check_ctr_timeliness"},
    {"id": "AML-008", "desc": "SAR must be filed within 30 days of detection",
     "severity": "CRITICAL", "applies_to": "SARFiling", "check": "check_sar_timeliness"},
    # Account / Balance
    {"id": "ACC-001", "desc": "Transfer must not exceed available balance",
     "severity": "HIGH", "applies_to": "FundsTransfer", "check": "check_sufficient_balance"},
    {"id": "ACC-002", "desc": "Cannot transact on frozen/blocked accounts",
     "severity": "CRITICAL", "applies_to": "FinancialTransfer", "check": "check_account_not_frozen"},
    {"id": "ACC-003", "desc": "Cannot close account with pending transactions",
     "severity": "HIGH", "applies_to": "CloseAccount", "check": "check_no_pending_txns"},
    {"id": "ACC-004", "desc": "Account status change requires dual approval",
     "severity": "MEDIUM", "applies_to": "UpdateAccountInfo", "check": "check_status_change_approval"},
    {"id": "ACC-005", "desc": "Cash deposits >$10k require source-of-funds documentation",
     "severity": "HIGH", "applies_to": "CashDeposit", "check": "check_sof_deposit"},
    # Investment Suitability (MiFID II)
    {"id": "SUIT-001", "desc": "Securities trade requires completed risk profile",
     "severity": "CRITICAL", "applies_to": "SecuritiesTrade", "check": "check_risk_profile"},
    {"id": "SUIT-002", "desc": "Trade risk must not exceed client risk tolerance",
     "severity": "CRITICAL", "applies_to": "SecuritiesTrade", "check": "check_risk_tolerance"},
    {"id": "SUIT-003", "desc": "Complex products require appropriateness test",
     "severity": "CRITICAL", "applies_to": "SecuritiesTrade", "check": "check_complex_products"},
    {"id": "SUIT-004", "desc": "Leveraged products require margin agreement",
     "severity": "HIGH", "applies_to": "SecuritiesTrade", "check": "check_margin_agreement"},
    {"id": "SUIT-005", "desc": ">10% portfolio concentration in single stock requires warning",
     "severity": "MEDIUM", "applies_to": "BuySecurities", "check": "check_concentration"},
    {"id": "SUIT-006", "desc": "Fund subscription must match investment objective",
     "severity": "HIGH", "applies_to": "FundSubscription", "check": "check_investment_objective"},
    {"id": "SUIT-007", "desc": "Insider-restricted securities cannot be traded",
     "severity": "CRITICAL", "applies_to": "SecuritiesTrade", "check": "check_insider_trading"},
    # Approval / Maker-Checker
    {"id": "APPR-001", "desc": "Transfers >$25k require maker-checker approval before execution",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_maker_checker_25k"},
    {"id": "APPR-002", "desc": "Non-individual account opening requires supervisor approval",
     "severity": "HIGH", "applies_to": "OpenAccount", "check": "check_entity_account_approval"},
    {"id": "APPR-003", "desc": "HIGH-risk client transfers >$5k require prior approval",
     "severity": "HIGH", "applies_to": "FundsTransfer", "check": "check_high_risk_approval"},
    {"id": "APPR-004", "desc": "SAR-flagged transactions must not execute before SAR review",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_sar_hold"},
    # Reporting
    {"id": "REP-001", "desc": "Regulatory reporting fields must be complete",
     "severity": "HIGH", "applies_to": "AccountAction", "check": "check_reporting_fields"},
    {"id": "REP-002", "desc": "Large trade reports filed T+1 for equities >$100k",
     "severity": "HIGH", "applies_to": "SecuritiesTrade", "check": "check_large_trade_report"},
    {"id": "REP-003", "desc": "Client records retained 5 years (MiFID II)",
     "severity": "MEDIUM", "applies_to": "KYCAction", "check": "check_record_retention"},
    # Session / Process
    {"id": "SES-001", "desc": "Re-authenticate after 15 min idle",
     "severity": "MEDIUM", "applies_to": "FinancialTransfer", "check": "check_reauth_timeout"},
    {"id": "SES-002", "desc": "Maximum 12 steps per session",
     "severity": "MEDIUM", "applies_to": "FinancialTransfer", "check": "check_max_steps"},
    {"id": "SES-003", "desc": "Non-routine actions require explicit client consent",
     "severity": "HIGH", "applies_to": "FinancialTransfer", "check": "check_client_consent"},
    # ODCV
    {"id": "ODCV-001", "desc": "SLA pressure must not override KYC/AML checks",
     "severity": "CRITICAL", "applies_to": "FundsTransfer", "check": "check_no_sla_bypass"},
]

def get_invariants_for_action(action_type: str) -> list:
    supertypes = get_all_supertypes(action_type)
    return [inv for inv in INVARIANTS if inv["applies_to"] in supertypes]

def get_invariant_by_id(inv_id: str):
    for inv in INVARIANTS:
        if inv["id"] == inv_id:
            return inv
    return None
