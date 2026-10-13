"""Tier configuration: rounds, budgets, families, receipt lifetimes.

Budgets are design targets pending calibration by the evaluation harness
(docs/protocol.md section 2.1). A fixed server-side network allowance is
added to each round budget; client-asserted latency is never used.
"""

from __future__ import annotations

from dataclasses import dataclass

from poac.protocol.models import CapabilityTier

NETWORK_ALLOWANCE_MS = 2_000


@dataclass(frozen=True)
class TierConfig:
    rounds: int
    families: tuple[str, ...]
    time_budget_ms: int
    difficulty: int
    receipt_ttl_s: int

    @property
    def round_deadline_ms(self) -> int:
        return self.time_budget_ms + NETWORK_ALLOWANCE_MS

    @property
    def session_deadline_ms(self) -> int:
        return self.rounds * self.round_deadline_ms + 5_000


TIERS: dict[CapabilityTier, TierConfig] = {
    CapabilityTier.C0: TierConfig(
        rounds=1, families=("code", "data"), time_budget_ms=60_000,
        difficulty=0, receipt_ttl_s=3_600,
    ),
    CapabilityTier.C1: TierConfig(
        rounds=3, families=("nlu", "logic", "data"), time_budget_ms=20_000,
        difficulty=1, receipt_ttl_s=3_600,
    ),
    CapabilityTier.C2: TierConfig(
        rounds=4, families=("nlu", "code", "logic", "data", "diagram"),
        time_budget_ms=20_000, difficulty=2, receipt_ttl_s=300,
    ),
    CapabilityTier.C3: TierConfig(
        rounds=6, families=("nlu", "code", "logic", "data", "diagram"),
        time_budget_ms=15_000, difficulty=3, receipt_ttl_s=300,
    ),
    # formal tier: Lean-kernel-validated proofs. Larger budgets because the
    # prover must author whole tactic blocks. Only offered when the verifier
    # host has the pinned Lean toolchain (feature-flagged in the app).
    CapabilityTier.C4: TierConfig(
        rounds=3, families=("proof",), time_budget_ms=40_000,
        difficulty=3, receipt_ttl_s=300,
    ),
}

KERNEL_FAMILIES = frozenset({"proof"})


def tier_requires_kernel(config: TierConfig) -> bool:
    return any(f in KERNEL_FAMILIES for f in config.families)
