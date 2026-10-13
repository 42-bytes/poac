"""PoAC wire contracts.

Every request/response body is a strict Pydantic model: unknown fields are
rejected, unions are discriminated, and sizes are bounded. These models are
the single source of truth for the OpenAPI/JSON Schema published to agents.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "0.1.0"
SUITE_VERSION = "2026.09-proto"

MAX_ANSWER_CHARS = 2_000
# proof submissions are whole Lean tactic blocks, so they get a larger cap
MAX_PROOF_ANSWER_CHARS = 20_000


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CapabilityTier(str, Enum):
    C0 = "C0"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    # formal tier: fresh Lean propositions, validated by the Lean kernel.
    # Only offered when the verifier host has a pinned Lean toolchain.
    C4 = "C4"


class IdentityTier(str, Enum):
    I0 = "I0"
    I1 = "I1"
    I2 = "I2"
    I3 = "I3"


Family = Literal["nlu", "code", "logic", "data", "diagram", "proof"]

FAMILIES: tuple[str, ...] = ("nlu", "code", "logic", "data", "diagram", "proof")


class HolderJwk(StrictModel):
    """Ed25519 public JWK committed at session creation (RFC 8037)."""

    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    # base64url (no padding) of 32 bytes is always 43 characters.
    x: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]+$")
    kid: str | None = Field(default=None, max_length=128)


class SessionCreateRequest(StrictModel):
    tier: CapabilityTier
    holder_jwk: HolderJwk | None = None


# --- challenge payloads (discriminated on `family`) -----------------------


class NluChallenge(StrictModel):
    family: Literal["nlu"]
    narrative: str
    question: str


class CodeChallenge(StrictModel):
    family: Literal["code"]
    language: Literal["python"]
    source: str
    question: str


class LogicChallenge(StrictModel):
    family: Literal["logic"]
    statement: str
    question: str


class DataChallenge(StrictModel):
    family: Literal["data"]
    rows: list[dict[str, int | str]]
    instruction: str


class DiagramChallenge(StrictModel):
    family: Literal["diagram"]
    svg: str
    question: str


class ProofChallenge(StrictModel):
    """Formal-proof round: prove a fresh proposition in core Lean 4.

    The submission is the text after ``:=`` (typically a ``by`` tactic
    block). The verifier assembles ``{preamble}\\ntheorem poac_target :
    {proposition} := {submission}`` and accepts only if the Lean kernel
    checks it using no axioms beyond propext/Classical.choice/Quot.sound.
    """

    family: Literal["proof"]
    language: Literal["lean4"]
    lean_version: str
    preamble: str
    proposition: str
    instructions: str


Challenge = Annotated[
    Union[
        NluChallenge,
        CodeChallenge,
        LogicChallenge,
        DataChallenge,
        DiagramChallenge,
        ProofChallenge,
    ],
    Field(discriminator="family"),
]


class RoundChallenge(StrictModel):
    session_id: str
    round_index: int = Field(ge=1)
    rounds_total: int = Field(ge=1)
    challenge: Challenge
    nonce: str
    time_budget_ms: int = Field(gt=0)
    answer_format: str


class SessionCreatedResponse(StrictModel):
    session_id: str
    tier: CapabilityTier
    identity_tier: IdentityTier
    suite_version: str
    round: RoundChallenge


class RoundSubmitRequest(StrictModel):
    nonce: str = Field(max_length=128)
    # sized for proof submissions; short-answer families enforce the tighter
    # MAX_ANSWER_CHARS bound during validation
    answer: str = Field(max_length=MAX_PROOF_ANSWER_CHARS)


class FailureClass(str, Enum):
    timeout = "timeout"
    wrong_answer = "wrong_answer"
    protocol_violation = "protocol_violation"
    expired = "expired"


class NextRoundResponse(StrictModel):
    status: Literal["next"]
    round: RoundChallenge


class SessionPassedResponse(StrictModel):
    status: Literal["passed"]
    session_id: str
    capability_tier: CapabilityTier
    identity_tier: IdentityTier
    families: list[Family]
    latency_ms: list[int]
    receipt: str


class SessionFailedResponse(StrictModel):
    status: Literal["failed"]
    session_id: str
    failure: FailureClass
    round_index: int


RoundOutcome = Annotated[
    Union[NextRoundResponse, SessionPassedResponse, SessionFailedResponse],
    Field(discriminator="status"),
]


# --- portable presentation verification ------------------------------------


class VerifyNonceResponse(StrictModel):
    """One-shot nonce issued by the verifier for a forthcoming presentation."""

    nonce: str
    expires_in: int = Field(gt=0, description="seconds until the nonce expires")


class PresentationRequest(StrictModel):
    receipt: str = Field(max_length=8_192)
    kb_jwt: str = Field(max_length=4_096)
    audience: str = Field(max_length=512)
    nonce: str = Field(max_length=128)


class PresentationResult(StrictModel):
    valid: bool
    reason: str | None = None
    capability_tier: CapabilityTier | None = None
    identity_tier: IdentityTier | None = None
    holder_thumbprint: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None


# --- discovery manifest -----------------------------------------------------


class TierSpec(StrictModel):
    tier: CapabilityTier
    rounds: int
    time_budget_ms: int
    families: list[Family]
    receipt_ttl_s: int


class CapabilityManifest(StrictModel):
    protocol: Literal["poac"]
    version: str
    suite_version: str
    issuer: str
    sessions_endpoint: str
    verify_endpoint: str
    jwks_uri: str
    openapi_url: str
    tiers: list[TierSpec]
    honest_claims: str
