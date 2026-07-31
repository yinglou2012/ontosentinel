"""ABox state representation and hypothetical state projection.

The ABox stores concrete facts about clients, accounts, and session state.
SCP maintains a ground-truth ABox independent of the LLM's attention, and
constructs hypothetical ABox copies for 'what-if' projection before execution.
"""

from __future__ import annotations
import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


@dataclass
class ClientState:
    """Per-client state (persistent across steps)."""
    client_id: str
    name: str = ""
    kyc_status: str = "VALID"               # VALID / EXPIRED / PENDING / NONE
    kyc_last_verified: datetime | None = None
    kyc_edd_completed: bool = False         # Enhanced Due Diligence
    risk_rating: str = "LOW"                # LOW / MEDIUM / HIGH / PEP
    is_pep: bool = False
    is_shell_company_redflag: bool = False
    source_of_wealth_collected: bool = True
    investment_objective: str = "BALANCED"  # CONSERVATIVE / BALANCED / AGGRESSIVE
    risk_tolerance: str = "MODERATE"        # LOW / MODERATE / HIGH
    has_margin_agreement: bool = False
    has_risk_profile: bool = True


@dataclass
class AccountState:
    account_id: str
    client_id: str
    balance: float = 0.0
    currency: str = "USD"
    status: str = "ACTIVE"                 # ACTIVE / FROZEN / CLOSED
    daily_transfer_total: float = 0.0
    daily_transfer_date: str = ""          # YYYY-MM-DD
    weekly_transfer_total: float = 0.0
    recent_transfers: list[dict] = field(default_factory=list)
    # recent_transfers items: {"to": str, "amount": float, "ts": datetime, "bene_new": bool}
    pending_transactions: int = 0
    portfolio_concentration: dict[str, float] = field(default_factory=dict)
    insider_restricted: list[str] = field(default_factory=list)


@dataclass
class BeneficiaryState:
    entity_id: str
    name: str = ""
    is_sanctioned: bool = False
    is_pep: bool = False
    risk_jurisdiction: bool = False   # high-risk jurisdiction
    is_new: bool = False              # first-time beneficiary
    entity_type: str = "INDIVIDUAL"   # INDIVIDUAL / CORPORATE / SHELL


@dataclass
class SessionState:
    """Per-scenario session state."""
    session_id: str
    start_time: datetime = field(default_factory=datetime.now)
    last_action_time: datetime = field(default_factory=datetime.now)
    steps_taken: int = 0
    client_consent_obtained: bool = False
    client_authenticated: bool = True
    sar_hold_active: bool = False
    pending_approval: bool = False
    approval_received: bool = False
    ctr_filed: bool = False          # CTR filed for current cash txn
    sar_filed: bool = False          # SAR filed for current suspicious activity
    ctr_filed_for_amount: float = 0  # amount the pending CTR covers
    kpi_pressure: bool = False
    reporting_fields_complete: bool = True
    records_retained: bool = True


class ABox:
    """Assertional Box: concrete world state."""

    def __init__(self):
        self.clients: dict[str, ClientState] = {}
        self.accounts: dict[str, AccountState] = {}
        self.beneficiaries: dict[str, BeneficiaryState] = {}
        self.session: SessionState | None = None
        self.current_date: datetime = datetime(2025, 6, 15)
        # Transfer limits (configurable)
        self.single_limit: float = 50000.0
        self.daily_limit: float = 50000.0
        self.weekly_limit: float = 200000.0
        self.intl_daily_limit: float = 25000.0
        self.ctr_threshold: float = 10000.0
        self.sar_structuring_count: int = 3
        self.sar_structuring_window_h: int = 24
        self.maker_checker_threshold: float = 25000.0
        self.high_risk_approval_threshold: float = 5000.0
        self.kyc_validity_days: int = 365
        self.reauth_timeout_min: int = 15
        self.max_steps: int = 12

    def clone(self) -> "ABox":
        """Deep copy for hypothetical reasoning."""
        return copy.deepcopy(self)

    @classmethod
    def from_scenario(cls, scenario: dict) -> "ABox":
        """Initialize ABox from scenario definition."""
        abox = cls()
        abox.current_date = datetime.fromisoformat(
            scenario.get("current_date", "2025-06-15T10:00:00"))
        abox.session = SessionState(
            session_id=scenario.get("scenario_id", "unknown"),
            start_time=abox.current_date,
            last_action_time=abox.current_date,
            kpi_pressure=scenario.get("kpi_pressure", False),
            client_authenticated=scenario.get("client_authenticated", True),
            client_consent_obtained=scenario.get("client_consent", False),
        )
        # Load limits from scenario if provided
        for key in ["single_limit", "daily_limit", "maker_checker_threshold"]:
            if key in scenario:
                setattr(abox, key, scenario[key])
        # Load clients
        for c in scenario.get("clients", []):
            kyc_date = None
            if c.get("kyc_last_verified"):
                kyc_date = datetime.fromisoformat(c["kyc_last_verified"])
            abox.clients[c["client_id"]] = ClientState(
                client_id=c["client_id"],
                name=c.get("name", ""),
                kyc_status=c.get("kyc_status", "VALID"),
                kyc_last_verified=kyc_date,
                kyc_edd_completed=c.get("kyc_edd_completed", False),
                risk_rating=c.get("risk_rating", "LOW"),
                is_pep=c.get("is_pep", False),
                is_shell_company_redflag=c.get("is_shell_company", False),
                source_of_wealth_collected=c.get("sow_collected", True),
                investment_objective=c.get("investment_objective", "BALANCED"),
                risk_tolerance=c.get("risk_tolerance", "MODERATE"),
                has_margin_agreement=c.get("margin_agreement", False),
                has_risk_profile=c.get("has_risk_profile", True),
            )
        # Load accounts
        for a in scenario.get("accounts", []):
            abox.accounts[a["account_id"]] = AccountState(
                account_id=a["account_id"],
                client_id=a["client_id"],
                balance=a.get("balance", 100000.0),
                currency=a.get("currency", "USD"),
                status=a.get("status", "ACTIVE"),
                daily_transfer_total=a.get("daily_total", 0.0),
                weekly_transfer_total=a.get("weekly_total", 0.0),
                daily_transfer_date=abox.current_date.strftime("%Y-%m-%d"),
                portfolio_concentration=a.get("concentration", {}),
                insider_restricted=a.get("insider_restricted", []),
                pending_transactions=a.get("pending_transactions", 0),
            )
        # Load beneficiaries
        for b in scenario.get("beneficiaries", []):
            abox.beneficiaries[b["entity_id"]] = BeneficiaryState(
                entity_id=b["entity_id"],
                name=b.get("name", ""),
                is_sanctioned=b.get("sanctioned", False),
                is_pep=b.get("pep", False),
                risk_jurisdiction=b.get("high_risk_jurisdiction", False),
                is_new=b.get("new_beneficiary", False),
                entity_type=b.get("entity_type", "INDIVIDUAL"),
            )
        return abox

    def apply_action(self, action_type: str, args: dict) -> "ABox":
        """Project action effects onto a *copy* of this ABox (hypothetical).
        Returns the projected ABox; does NOT mutate self."""
        proj = self.clone()
        proj.session.last_action_time = proj.current_date
        proj.session.steps_taken += 1

        if action_type in ("FundsTransfer", "WireTransfer", "InternationalWire",
                           "ACHTransfer", "InternalTransfer"):
            acct = proj.accounts.get(args.get("from_account", ""))
            amount = args.get("amount", 0)
            to_entity = args.get("to_entity", "")
            if acct:
                acct.balance -= amount
                acct.daily_transfer_total += amount
                acct.weekly_transfer_total += amount
                acct.recent_transfers.append({
                    "to": to_entity, "amount": amount,
                    "ts": proj.current_date,
                    "bene_new": proj.beneficiaries.get(to_entity, BeneficiaryState(entity_id=to_entity)).is_new,
                })

        elif action_type == "CashWithdrawal":
            acct = proj.accounts.get(args.get("from_account", ""))
            amount = args.get("amount", 0)
            if acct:
                acct.balance -= amount
                acct.daily_transfer_total += amount

        elif action_type == "CashDeposit":
            acct = proj.accounts.get(args.get("to_account", ""))
            amount = args.get("amount", 0)
            if acct:
                acct.balance += amount

        elif action_type in ("BuySecurities", "BondPurchase"):
            acct = proj.accounts.get(args.get("from_account", ""))
            amount = args.get("amount", 0)
            if acct:
                acct.balance -= amount
                instrument = args.get("instrument", "")
                acct.portfolio_concentration[instrument] = \
                    acct.portfolio_concentration.get(instrument, 0) + amount

        elif action_type == "SellSecurities":
            acct = proj.accounts.get(args.get("to_account", ""))
            amount = args.get("amount", 0)
            if acct:
                acct.balance += amount

        elif action_type == "KYCRefresh":
            cid = args.get("client_id", "")
            client = proj.clients.get(cid)
            if client:
                client.kyc_status = "VALID"
                client.kyc_last_verified = proj.current_date

        elif action_type == "CTRFiling":
            proj.session.ctr_filed = True
            proj.session.ctr_filed_for_amount = args.get("amount", 0)

        elif action_type == "SARFiling":
            proj.session.sar_filed = True

        elif action_type == "ApprovalAction":
            proj.session.approval_received = True
            proj.session.pending_approval = False

        elif action_type == "KYCOnboarding":
            cid = args.get("client_id", "")
            client = proj.clients.get(cid)
            if client:
                client.kyc_status = "VALID"
                client.kyc_last_verified = proj.current_date
                client.source_of_wealth_collected = args.get("sow_collected", True)

        elif action_type == "OpenAccount":
            aid = args.get("account_id", "")
            cid = args.get("client_id", "")
            if aid and aid not in proj.accounts:
                proj.accounts[aid] = AccountState(
                    account_id=aid, client_id=cid, balance=0.0, status="ACTIVE",
                    daily_transfer_date=proj.current_date.strftime("%Y-%m-%d"),
                )

        elif action_type == "CloseAccount":
            aid = args.get("account_id", "") or args.get("from_account", "")
            if aid and aid in proj.accounts:
                proj.accounts[aid].status = "CLOSED"

        return proj