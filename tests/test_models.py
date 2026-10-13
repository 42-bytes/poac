"""Contract tests for the strict PoAC wire models."""

import pydantic
import pytest
from pydantic import TypeAdapter

from poac.protocol import models as m

VALID_X = "A" * 43  # base64url of 32 bytes is exactly 43 chars


def test_session_create_rejects_unknown_fields():
    with pytest.raises(pydantic.ValidationError):
        m.SessionCreateRequest.model_validate({"tier": "C1", "sneaky": 1})


def test_session_create_accepts_tier_and_optional_jwk():
    req = m.SessionCreateRequest.model_validate({"tier": "C2"})
    assert req.tier is m.CapabilityTier.C2 and req.holder_jwk is None

    req = m.SessionCreateRequest.model_validate(
        {"tier": "C1", "holder_jwk": {"kty": "OKP", "crv": "Ed25519", "x": VALID_X}}
    )
    assert req.holder_jwk is not None and req.holder_jwk.crv == "Ed25519"


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "EC", "crv": "Ed25519", "x": VALID_X},  # wrong kty
        {"kty": "OKP", "crv": "P-256", "x": VALID_X},  # wrong curve
        {"kty": "OKP", "crv": "Ed25519", "x": "short"},  # wrong length
        {"kty": "OKP", "crv": "Ed25519", "x": VALID_X, "d": "priv"},  # private part
    ],
)
def test_holder_jwk_rejects_non_ed25519_material(jwk):
    with pytest.raises(pydantic.ValidationError):
        m.HolderJwk.model_validate(jwk)


def test_challenge_union_discriminates_on_family():
    ta = TypeAdapter(m.Challenge)
    c = ta.validate_python(
        {"family": "logic", "statement": "s", "question": "q"}
    )
    assert isinstance(c, m.LogicChallenge)
    with pytest.raises(pydantic.ValidationError):
        ta.validate_python({"family": "logic", "narrative": "x", "question": "q"})
    with pytest.raises(pydantic.ValidationError):
        ta.validate_python({"family": "unknown", "question": "q"})


def test_round_submit_bounds_answer_size():
    # the wire cap is sized for proof submissions; short-answer families
    # enforce MAX_ANSWER_CHARS during validation instead
    m.RoundSubmitRequest.model_validate(
        {"nonce": "n", "answer": "a" * m.MAX_PROOF_ANSWER_CHARS}
    )
    with pytest.raises(pydantic.ValidationError):
        m.RoundSubmitRequest.model_validate(
            {"nonce": "n", "answer": "a" * (m.MAX_PROOF_ANSWER_CHARS + 1)}
        )


def test_round_outcome_discriminates_on_status():
    ta = TypeAdapter(m.RoundOutcome)
    out = ta.validate_python(
        {
            "status": "failed",
            "session_id": "s",
            "failure": "timeout",
            "round_index": 2,
        }
    )
    assert isinstance(out, m.SessionFailedResponse)
    assert out.failure is m.FailureClass.timeout


def test_models_export_json_schema():
    schema = m.SessionCreatedResponse.model_json_schema()
    assert "$defs" in schema
    # every challenge family present in the schema defs
    for name in ("NluChallenge", "CodeChallenge", "LogicChallenge", "DataChallenge", "DiagramChallenge"):
        assert name in schema["$defs"]
