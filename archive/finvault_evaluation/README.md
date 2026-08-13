# FinVault Cross-Benchmark Evaluation (Archived)

This directory contains a completed cross-benchmark evaluation of
OntoSentinel on the FinVault benchmark (arXiv:2601.07853). FinVault
was subsequently withdrawn from arXiv. The evaluation is archived here
as evidence of cross-benchmark generalizability.

## What was done

- Adapted OntoSentinel's SCP to FinVault's 31 financial scenarios
- Mapped 68 FinVault tool names to OntoSentinel action types
- Created 86 invariant check functions aligned with FinVault's
  VulnerabilityChecker
- Ran 6-method progressive ablation across 2 seeds

## Key finding

OntoSentinel reduced the safety violation rate on FinVault's 31
scenarios from 8.4% to 5.3%, confirming that the middleware
generalizes beyond its own HS-FinBench benchmark. The residual
violations were due to FinVault's post-hoc VulnerabilityChecker
detecting violations that OntoSentinel's pre-execution invariants
were not designed to catch (e.g., content-level safety issues out of
scope for action-compliance verification).

## Why archived

FinVault (arXiv:2601.07853) was withdrawn by its authors. The
evaluation results are therefore not included in the main paper but
are preserved here for transparency.

## Files

- `finvault_adapter.py` — FinVaultAdapter class, 68 tool-to-action
  mappings, integration with SCP engine
- `finvault_runner.py` — Standalone experiment runner for FinVault
  benchmark evaluation
- `finvault_checks.py` — 86 check functions for FinVault-specific
  invariants
- `finvault_invariants.py` — 90 safety invariants, 51 action
  concepts mapped to FinVault's 25 vulnerable scenarios
- `ADAPTER_README.md` — Original adapter documentation