# OntoSentinel: Ontology-Guarded LLM Agents for Financial Compliance

OntoSentinel is a middleware layer that enforces action admissibility for LLM-based
agents in financial services. It combines an OWL 2 EL ontology (the **FRC
ontology**—Financial Regulatory Compliance, 38 classes, 44 invariants) with a
**Semantic Compliance Pipeline (SCP)** that verifies every agent action against
ontological constraints before execution. When violations are detected,
OntoSentinel generates **counterfactual repair suggestions** via binary search
over action parameters and precondition insertion, enabling the LLM to self-correct.

This repository accompanies the paper:
> *OntoSentinel: Enforcing Action Admissibility for LLM Agents in Complex Interactive Environments* (under review).

---

## Repository Structure

```
ontosentinel/
├── src/
│   ├── scp/                  # Semantic Compliance Pipeline
│   │   ├── engine.py         # SCP verifier: ELK reasoning + SHACL + invariant checks
│   │   ├── checks.py         # 44 invariant check functions (FIXED_CHECKS registry)
│   │   ├── counterfactual.py # Counterfactual repair engine (binary search, precondition)
│   │   ├── finvault_checks.py# FinVault-specific invariant checks
│   │   └── state.py          # ABox / SessionState — ELK-backed knowledge base
│   ├── runner/
│   │   ├── executor.py       # Scenario executor with 6 ablation methods
│   │   ├── env.py            # Environment state simulation
│   │   ├── finvault_adapter.py    # FinVault environment adapter
│   │   ├── finvault_runner.py     # FinVault experiment runner
│   │   └── llamafirewall_guardrail.py  # LlamaFirewall baseline integration
│   ├── apat/
│   │   └── audit.py          # APAT — Audit Provenance & Accountability Trail
│   ├── rate/
│   │   └── router.py         # RATE — Risk-Aware Tiered Escalation router
│   ├── eval/
│   │   └── metrics.py        # SVR, CVR, DVR, TCR, FPR, Remediation Rate
│   └── llm.py                # LLM API client (OpenAI-compatible endpoint)
├── ontology/
│   ├── invariants.py         # FRC ontology: 38 classes, 44 invariants (OWL 2 EL)
│   └── finvault_invariants.py# FinVault ontology extension
├── scenarios/
│   ├── benign/               # 101 benign financial scenarios
│   └── traps/                # 39 adversarial trap scenarios
│       ├── single_step/      # Single-step violation traps (10)
│       ├── drift/            # Context drift traps (13)
│       ├── threshold/        # Threshold evasion traps (9)
│       └── odcv/             # Out-of-distribution concept violation traps (7)
├── scripts/
│   ├── scenario_worker.py    # Per-scenario subprocess worker
│   ├── generate_scenarios.py # Scenario generator
│   └── analyze.py            # Results analysis
├── configs/
│   └── default.yaml          # RATE weights, SCP settings, environment config
├── run_experiment.py         # Single-seed experiment runner
├── run_multi_seed.py         # Multi-seed experiment orchestrator
├── run_multi_seed.ps1        # PowerShell wrapper for multi-seed runs
├── requirements.txt
└── .env.example              # Environment variable template
```

---

## Key Components

### 1. FRC Ontology (OWL 2 EL, 38 Classes, 44 Invariants)

The Financial Regulatory Compliance ontology is defined in `ontology/invariants.py`.
It models financial entities (Client, Account, Transaction, Beneficiary, etc.) and
encodes regulatory constraints as OWL 2 EL class expressions. The 44 invariants
span seven compliance domains:

| Domain | Invariants | Example |
|--------|-----------|---------|
| KYC (Know Your Customer) | 6 | KYC must be current (< 365 days) for any transaction |
| AML (Anti-Money Laundering) | 8 | No structuring (3+ transactions < $10K in 24h) |
| SUIT (Suitability) | 7 | Complex products require appropriateness test |
| LIM (Limits) | 6 | Single transfer ≤ $50K, daily aggregate ≤ $50K |
| SAN (Sanctions) | 5 | No transactions with sanctioned entities |
| FRAUD | 5 | Velocity checks, unusual pattern detection |
| DISCLOSURE | 4 | Fee disclosure, risk acknowledgment required |
| ODCV (OOD Concept Violation) | 3 | Out-of-distribution concept detection |

### 2. SCP — Semantic Compliance Pipeline

`src/scp/engine.py` implements the verification pipeline:
1. **ELK Reasoning**: OWL 2 EL subsumption to determine which invariants apply to the action
2. **SHACL Validation**: Numeric and temporal constraint checking (amount thresholds, date windows)
3. **Invariant Check Functions**: 44 domain-specific Python check functions registered in `FIXED_CHECKS`

The verifier returns `(allowed, violations, feedback)` for each action.

### 3. RATE — Risk-Aware Tiered Escalation

`src/rate/router.py` computes a composite risk score ρ ∈ [0, 1] from four factors:
- φ_rev (0.25): Revision round count
- φ_sens (0.20): Entity sensitivity (PEP, sanctions)
- φ_thresh (0.35): Threshold proximity
- φ_crit (0.20): Dependency criticality

Routing: ρ ≤ 0.30 → AUTO (allow), 0.30 < ρ ≤ 0.85 → APPROVAL (escalate), ρ > 0.85 → REJECT.

### 4. APAT — Audit Provenance & Accountability Trail

`src/apat/audit.py` generates SHA-256 hashed audit trails for every action,
including SCP verdicts, RATE scores, and counterfactual suggestions.

### 5. Counterfactual Repair Engine

`src/scp/counterfactual.py` classifies each violation as:
- **Parameter-fixable**: Adjust action parameters (amount, quantity) via binary search to find the
  maximum safe value, then propose a concrete suggestion to the LLM.
- **Precondition-fixable**: Missing prerequisites (KYC, agreement). Insert the required preparatory
  action into the suggestion.
- **Not fixable**: Violations that cannot be resolved through parameter or precondition changes.

### 6. HS-FinBench Scenarios

140 scenarios with step-by-step action traces:
- **101 benign**: Standard financial operations (transfers, withdrawals, securities trades)
- **39 traps**: Adversarial scenarios designed to probe compliance boundaries

### 7. FinVault Adapter

`src/runner/finvault_adapter.py` and `src/runner/finvault_runner.py` map FinVault's
proprietary action space to OntoSentinel's ontology, enabling cross-benchmark evaluation.

### 8. LlamaFirewall Baseline

`src/runner/llamafirewall_guardrail.py` integrates the LlamaFirewall AlignmentCheck
scanner for baseline comparison, using the same LLM backend for fairness.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/anonymous-for-review/ontosentinel.git
cd ontosentinel

# Install dependencies (Python 3.10+)
pip install -r requirements.txt

# Configure API credentials
cp .env.example .env
# Edit .env with your API key and endpoint
```

### Requirements

- Python 3.10+
- OpenAI-compatible LLM endpoint (DeepSeek V3, Qwen, or any model with tool-calling support)
- ELK reasoner (included via `owlready2`)

---

## Reproducing Results

### Single Method, Single Seed

```bash
python run_experiment.py \
  --model deepseek-v3-1-terminus \
  --method full \
  --seed 42 \
  --max-steps 15 \
  --output results/results_seed42.json \
  --verbose
```

### All Six Ablation Methods

The six methods correspond to progressively enabling components:

| Method | SCP | RATE | APAT | Counterfactual | Description |
|--------|-----|------|------|---------------|-------------|
| `none` | — | — | — | — | Unconstrained LLM baseline |
| `react_p` | — | — | — | — | ReAct prompting only |
| `ipc` | — | — | — | — | In-context policy prompting |
| `sre` | — | — | — | — | Self-reflection with error feedback |
| `scp_only` | ✓ | — | ✓ | — | SCP verification + audit, no RATE |
| `full` | ✓ | ✓ | ✓ | — | Full pipeline (SCP + RATE + APAT) |
| `cf_full` | ✓ | ✓ | ✓ | ✓ | Full pipeline + counterfactual repair |
| `llamafirewall` | — | — | — | — | LlamaFirewall AlignmentCheck baseline |

```bash
for method in none react_p ipc sre scp_only full cf_full; do
  python run_experiment.py \
    --model deepseek-v3-1-terminus \
    --method $method \
    --seed 42 \
    --max-steps 15 \
    --output results/results_${method}_seed42.json \
    --verbose
done
```

### Multi-Seed Robustness

```bash
python run_multi_seed.py \
  --model deepseek-v3-1-terminus \
  --seeds 42 123 456 \
  --max-steps 15 \
  --output results/summary_multi_seed.json
```

Or via PowerShell:

```powershell
.\run_multi_seed.ps1 -Seeds 42,123,456,789,2024
```

### Computing Metrics

```bash
python -c "
from src.eval.metrics import compute_metrics, print_results_table
from types import SimpleNamespace
import json

results = json.load(open('results/results_full_seed42.json'))
all_metrics = []
for method, data in results.items():
    objs = [SimpleNamespace(**v) for v in data['scenarios'].values()]
    all_metrics.append(compute_metrics(method, objs))
print_results_table(all_metrics)
"
```

---

## Extending to 8+ Seeds

The experiment runner supports arbitrary seed counts for robustness checks:

```bash
python run_multi_seed.py \
  --model deepseek-v3-1-terminus \
  --seeds 42 123 456 789 2024 101 202 303 \
  --max-steps 15 \
  --output results/summary_8seeds.json
```

Each seed runs in parallel via subprocess workers. Results are saved per-seed
and aggregated into a summary JSON.

---

## Configuration

Edit `configs/default.yaml` to adjust:

- **RATE weights**: `rate.weights.*` — domain-specific risk factors
- **RATE thresholds**: `rate.thresholds.theta_auto` / `theta_appr`
- **SCP settings**: `scp.use_shacl`, `scp.elk_timeout_ms`
- **Environment**: `env.daily_transfer_limit`, `env.kyc_validity_days`, etc.
- **Experiment**: `experiment.seeds`, `experiment.max_steps_per_scenario`

---

## Results Format

Each result JSON contains per-scenario data:

```json
{
  "full": {
    "scenarios": {
      "T-SS-001": {
        "id": "T-SS-001",
        "category": "trap/single_step",
        "violations": 0,
        "completed": true,
        "steps": 5,
        "total_actions": 3,
        "cf_stats": {
          "total_violations": 1,
          "parameter_fixable": 0,
          "precondition_fixable": 1,
          "not_fixable": 0,
          "suggestions_generated": 1,
          "suggestions_adopted": 1
        },
        "step_details": [
          {
            "step": 1,
            "tool_name": "transfer",
            "action_type": "FundsTransfer",
            "executed": true,
            "violation_ids": [],
            "violation_severity": []
          }
        ]
      }
    }
  }
}
```

### Metrics

| Metric | Definition |
|--------|-----------|
| **SVR** ↓ | Scenario Violation Rate: fraction of actions where violations executed |
| **CVR** ↓ | Critical Violation Rate: CRITICAL-severity violations executed |
| **DVR** ↓ | Drift Violation Rate: drift-trap scenarios with violations |
| **TCR** ↑ | Task Completion Rate: fraction of scenarios completed |
| **FPR** ↓ | False Positive Rate: benign actions incorrectly flagged |
| **Approval** | Fraction of actions routed through approval escalation |
| **Remediation** ↑ | Trap scenarios where LLM self-corrected via corrective action |

---

## Citation

If you use OntoSentinel in your research, please cite:

```bibtex
@inproceedings{ontosentinel2026,
  title     = {OntoSentinel: Enforcing Action Admissibility for {LLM} Agents in Complex Interactive Environments},
  author    = {Anonymous},
  booktitle = {Findings of the Association for Computational Linguistics: ACL 2026},
  year      = {2026},
}
```

---

## License

This repository is made available for research and review purposes.
A final license will be added upon publication.
