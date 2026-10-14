"""Session state records and their JSON (de)serialization.

Kept separate from the orchestrator so persistent stores can round-trip
sessions without importing orchestration logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import TypeAdapter

from poac.protocol.models import CapabilityTier, Challenge, HolderJwk, IdentityTier
from poac.sessions.config import TIERS, TierConfig

_CHALLENGE = TypeAdapter(Challenge)


@dataclass
class RoundState:
    family: str
    expected_answer: str
    nonce: str
    issued_at: float
    chain_material: str
    payload: object = None  # kernel-validated families need the payload
    validating: bool = False


@dataclass
class Session:
    session_id: str
    tier: CapabilityTier
    config: TierConfig
    holder_jwk: HolderJwk | None
    created_at: float
    status: str = "active"  # active | passed | failed
    current_round: int = 0  # last issued round index (1-based)
    round_state: RoundState | None = None
    families: list[str] = field(default_factory=list)
    latencies_ms: list[int] = field(default_factory=list)
    prev_answer_hash: bytes = b"\x00" * 32

    @property
    def identity_tier(self) -> IdentityTier:
        return IdentityTier.I1 if self.holder_jwk is not None else IdentityTier.I0

    @property
    def expires_at(self) -> float:
        """When a store may drop this session (deadline + grace)."""
        return self.created_at + self.config.session_deadline_ms / 1000 + 60


def session_to_dict(s: Session) -> dict:
    rs = s.round_state
    return {
        "session_id": s.session_id,
        "tier": s.tier.value,
        "holder_jwk": s.holder_jwk.model_dump() if s.holder_jwk else None,
        "created_at": s.created_at,
        "status": s.status,
        "current_round": s.current_round,
        "families": list(s.families),
        "latencies_ms": list(s.latencies_ms),
        "prev_answer_hash": s.prev_answer_hash.hex(),
        "round_state": None
        if rs is None
        else {
            "family": rs.family,
            "expected_answer": rs.expected_answer,
            "nonce": rs.nonce,
            "issued_at": rs.issued_at,
            "chain_material": rs.chain_material,
            "payload": None if rs.payload is None else rs.payload.model_dump(),
            "validating": rs.validating,
        },
    }


def session_from_dict(d: dict) -> Session:
    tier = CapabilityTier(d["tier"])
    rs = d.get("round_state")
    round_state = None
    if rs is not None:
        round_state = RoundState(
            family=rs["family"],
            expected_answer=rs["expected_answer"],
            nonce=rs["nonce"],
            issued_at=rs["issued_at"],
            chain_material=rs["chain_material"],
            payload=None
            if rs["payload"] is None
            else _CHALLENGE.validate_python(rs["payload"]),
            validating=rs["validating"],
        )
    return Session(
        session_id=d["session_id"],
        tier=tier,
        config=TIERS[tier],
        holder_jwk=HolderJwk.model_validate(d["holder_jwk"]) if d["holder_jwk"] else None,
        created_at=d["created_at"],
        status=d["status"],
        current_round=d["current_round"],
        round_state=round_state,
        families=list(d["families"]),
        latencies_ms=list(d["latencies_ms"]),
        prev_answer_hash=bytes.fromhex(d["prev_answer_hash"]),
    )
