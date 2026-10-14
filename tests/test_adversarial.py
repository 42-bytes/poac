"""Red-team suite: attacks the PoAC verifier the way an adversary would.

Complements the per-module suites (which prove the happy paths and the
documented rejections) by attempting the attacks a motivated adversary
would actually try, grouped by target:

1. challenge layer   — degenerate answers, normalization abuse;
2. session protocol  — cross-session material, index games, race probes;
3. credentials       — forgery, splicing, key substitution, rogue issuers;
4. proof kernel      — screen bypasses, source injection, obfuscation.

Every test here must FAIL the attack. A passing suite means: no attack
in this catalog yields a pass, a receipt, or a valid presentation.
"""

from __future__ import annotations

import base64
import json

import pytest
from joserfc import jwt
from joserfc.jwk import OKPKey

from poac.challenges import make_challenge
from poac.challenges.base import answers_match, normalize_answer
from poac.challenges.proof_check import check_proof, find_lean, screen_submission
from poac.credentials.issuer import (
    ALLOWED_ALG,
    EDDSA_REGISTRY,
    RECEIPT_TYP,
    ReceiptIssuer,
)
from poac.credentials.presentation import (
    KB_TYP,
    create_kb_jwt,
    receipt_hash,
    verify_presentation,
)
from poac.protocol.models import (
    CapabilityTier,
    FailureClass,
    HolderJwk,
    IdentityTier,
    SessionFailedResponse,
)
from poac.sessions.orchestrator import Orchestrator, SessionError

LEAN = find_lean()
needs_lean = pytest.mark.skipif(LEAN is None, reason="no Lean toolchain")

SHORT_ANSWER_FAMILIES = ("nlu", "code", "logic", "data", "diagram")
FALSE_PROP = "∀ n : Nat, n = n + 1"


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def orch(clock):
    return Orchestrator(
        ReceiptIssuer.generate(), server_secret=b"s" * 32, clock=clock, lean_bin=LEAN
    )


@pytest.fixture
def holder_key():
    return OKPKey.generate_key("Ed25519")


@pytest.fixture
def issuer():
    return ReceiptIssuer.generate(issuer_url="https://poac.test")


def _issue(issuer, holder_key, tier=CapabilityTier.C2, ttl=300):
    x = holder_key.as_dict(private=False)["x"]
    return issuer.issue(
        session_id="sess-adv",
        capability_tier=tier,
        identity_tier=IdentityTier.I1,
        families=["nlu", "logic"],
        latencies_ms=[900, 800],
        rounds_total=2,
        receipt_ttl_s=ttl,
        holder_jwk=HolderJwk(kty="OKP", crv="Ed25519", x=x),
    )


def _b64url_json(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _json_from_b64url(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# =========================================================================
# 1. Challenge layer
# =========================================================================


@pytest.mark.parametrize("family", SHORT_ANSWER_FAMILIES)
@pytest.mark.parametrize("difficulty", [0, 1, 2, 3])
def test_no_generator_ever_emits_a_degenerate_answer(family, difficulty):
    """A single empty/whitespace expected answer would make '' a skeleton key.

    answers_match('', '') is True by construction, so the security of the
    empty-submission rejection rests entirely on this property.
    """
    for i in range(10):
        gc = make_challenge(family, bytes([i]) * 32, difficulty)
        assert normalize_answer(gc.answer) != "", (
            f"{family} d{difficulty} seed {i} produced an empty answer"
        )


def test_normalization_only_collapses_case_and_whitespace():
    # must-not-match pairs an attacker would hope get over-normalized
    assert not answers_match("12", "1 2")
    assert not answers_match("-1", "1")
    assert not answers_match("a,b", "ab")
    assert not answers_match("route: a b", "route a b")
    # by-design equivalences (documented, not a vulnerability)
    assert answers_match("  YES\n", "yes")
    assert answers_match("a   b", "a b")


def test_empty_and_whitespace_submissions_always_fail(orch, clock):
    for evil in ("", "   \n\t "):
        created = orch.create_session(CapabilityTier.C1, None)
        clock.advance(0.5)
        outcome = orch.submit(
            created.session_id, 1, created.round.nonce, evil
        )
        assert isinstance(outcome, SessionFailedResponse)
        assert outcome.failure is FailureClass.wrong_answer


def test_oversized_answer_is_a_wrong_answer_not_an_error(orch, clock):
    """A 20k-char blob aimed at a short-answer round must fail cleanly."""
    created = orch.create_session(CapabilityTier.C1, None)
    clock.advance(0.5)
    outcome = orch.submit(
        created.session_id, 1, created.round.nonce, "x" * 19_000
    )
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.wrong_answer


# =========================================================================
# 2. Session protocol
# =========================================================================


def test_cross_session_nonce_swap_is_a_protocol_violation(orch, clock):
    a = orch.create_session(CapabilityTier.C1, None)
    b = orch.create_session(CapabilityTier.C1, None)
    clock.advance(0.5)
    outcome = orch.submit(a.session_id, 1, b.round.nonce, "whatever")
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.protocol_violation


@pytest.mark.parametrize("bad_index", [-1, 0, 2, 999_999_999])
def test_round_index_games_are_protocol_violations(orch, clock, bad_index):
    created = orch.create_session(CapabilityTier.C1, None)
    clock.advance(0.5)
    outcome = orch.submit(
        created.session_id, bad_index, created.round.nonce, "whatever"
    )
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.protocol_violation


def test_failed_session_cannot_be_resurrected(orch, clock):
    created = orch.create_session(CapabilityTier.C1, None)
    clock.advance(0.5)
    outcome = orch.submit(created.session_id, 1, created.round.nonce, "wrong!")
    assert isinstance(outcome, SessionFailedResponse)
    with pytest.raises(SessionError, match="no longer active"):
        orch.submit(created.session_id, 1, created.round.nonce, "wrong!")


def test_fresh_sessions_get_fresh_instances_no_retry_oracle(orch):
    """Failing and retrying must present a new instance, not a second guess
    at the same one — otherwise sessions become a free answer oracle."""
    dumps = {
        json.dumps(
            orch.create_session(CapabilityTier.C1, None).round.challenge.model_dump(),
            sort_keys=True,
        )
        for _ in range(3)
    }
    assert len(dumps) >= 2, "fresh sessions produced identical challenge instances"


def test_concurrent_submission_during_kernel_validation_is_rejected(orch, clock):
    """White-box: the `validating` flag must block a second submission racing
    the (slow, lock-free) kernel check for the same round."""
    created = orch.create_session(CapabilityTier.C1, None)
    session = orch.store.get(created.session_id)
    session.round_state.validating = True
    orch.store.put(session)
    with pytest.raises(SessionError, match="being validated"):
        orch.submit(created.session_id, 1, created.round.nonce, "answer")


# =========================================================================
# 3. Credential forgery
# =========================================================================


def test_attacker_signed_receipt_with_spoofed_kid_rejected(issuer, holder_key):
    """Copy the real issuer's kid into a receipt signed by the attacker's own
    key: kid lookup must not substitute for signature verification."""
    real_kid = issuer.jwks()["keys"][0]["kid"]
    attacker_key = OKPKey.generate_key("Ed25519")
    claims = {
        "iss": issuer.issuer_url,
        "sub": "poac-session",
        "jti": "sess-forged",
        "iat": 1_000_000,
        "exp": 99_999_999_999,
        "poac": {"capability_tier": "C4", "identity_tier": "I1"},
        "cnf": {"jkt": holder_key.thumbprint()},
    }
    header = {"alg": ALLOWED_ALG, "typ": RECEIPT_TYP, "kid": real_kid}
    forged = jwt.encode(header, claims, attacker_key, registry=EDDSA_REGISTRY)
    kb = create_kb_jwt(holder_key, forged, "aud", "n-kid")
    res = verify_presentation(forged, kb, "aud", "n-kid", issuer.jwks())
    assert not res.valid
    assert "signature" in (res.reason or "")


def test_receipt_claims_splice_tier_upgrade_rejected(issuer, holder_key):
    """Re-encode the payload segment with capability_tier upgraded to C4
    while keeping the original signature."""
    receipt = _issue(issuer, holder_key, tier=CapabilityTier.C1)
    header_seg, payload_seg, sig_seg = receipt.split(".")
    claims = _json_from_b64url(payload_seg)
    claims["poac"]["capability_tier"] = "C4"
    spliced = ".".join([header_seg, _b64url_json(claims), sig_seg])
    kb = create_kb_jwt(holder_key, spliced, "aud", "n-splice")
    res = verify_presentation(spliced, kb, "aud", "n-splice", issuer.jwks())
    assert not res.valid
    assert "signature" in (res.reason or "")


def test_kb_header_key_substitution_rejected(issuer, holder_key):
    """KB-JWT signed with the real holder key but advertising a different
    public key in the header (hoping the verifier trusts the header)."""
    import time as _time

    other = OKPKey.generate_key("Ed25519")
    receipt = _issue(issuer, holder_key)
    header = {
        "alg": ALLOWED_ALG,
        "typ": KB_TYP,
        "jwk": other.as_dict(private=False),  # lie about the key
    }
    claims = {
        "aud": "aud",
        "nonce": "n-sub",
        "iat": int(_time.time()),
        "receipt_hash": receipt_hash(receipt),
    }
    kb = jwt.encode(header, claims, holder_key, registry=EDDSA_REGISTRY)
    res = verify_presentation(receipt, kb, "aud", "n-sub", issuer.jwks())
    assert not res.valid
    assert "signature" in (res.reason or "")


def test_rogue_issuer_with_same_issuer_url_rejected(issuer, holder_key):
    """An attacker running their own PoAC instance mints a receipt with the
    same issuer URL string; it must fail against the real issuer's JWKS."""
    rogue = ReceiptIssuer.generate(issuer_url=issuer.issuer_url)
    rogue_receipt = _issue(rogue, holder_key, tier=CapabilityTier.C4)
    kb = create_kb_jwt(holder_key, rogue_receipt, "aud", "n-rogue")
    res = verify_presentation(rogue_receipt, kb, "aud", "n-rogue", issuer.jwks())
    assert not res.valid


def test_kb_with_wrong_typ_rejected(issuer, holder_key):
    import time as _time

    receipt = _issue(issuer, holder_key)
    header = {
        "alg": ALLOWED_ALG,
        "typ": "jwt",  # stripped/mislabeled typ
        "jwk": holder_key.as_dict(private=False),
    }
    claims = {
        "aud": "aud",
        "nonce": "n-typ",
        "iat": int(_time.time()),
        "receipt_hash": receipt_hash(receipt),
    }
    kb = jwt.encode(header, claims, holder_key, registry=EDDSA_REGISTRY)
    res = verify_presentation(receipt, kb, "aud", "n-typ", issuer.jwks())
    assert not res.valid
    assert "typ" in (res.reason or "")


# =========================================================================
# 4. Proof kernel (skipped without a Lean toolchain)
# =========================================================================


def test_screen_catches_newline_open_bypass():
    """`open ` (with space) was the original token; `open\\nNat in ...` slipped
    past it. The screen must reject any occurrence of `open`."""
    assert screen_submission("open\nNat in by intro n; omega") is not None
    assert screen_submission("by decide\nopen\nLean in rfl") is not None


@needs_lean
def test_open_bypass_cannot_prove_a_false_proposition():
    """Even if the screen were bypassed entirely, namespace opening must not
    let a false proposition through the kernel."""
    result = check_proof(
        LEAN, "", FALSE_PROP, "open\nClassical in by intro n; omega"
    )
    assert not result.ok


@needs_lean
def test_comment_injection_cannot_hide_the_axiom_audit():
    """An unterminated block comment would swallow `#print axioms poac_target`;
    the checker must fail closed (Lean errors on the unterminated comment,
    and a missing audit line is a rejection in its own right)."""
    result = check_proof(LEAN, "", "1 + 1 = 2", "by decide /-")
    assert not result.ok


@needs_lean
def test_trailing_declaration_injection_cannot_prove_the_target():
    """Splicing extra declarations after the proof term cannot help: they are
    elaborated after `poac_target`, so the target itself stays unproven."""
    result = check_proof(
        LEAN,
        "",
        FALSE_PROP,
        "by intro n; omega\n\ntheorem poac_extra : True := trivial",
    )
    assert not result.ok


@needs_lean
def test_zero_width_obfuscated_sorry_fails_closed():
    """`sor\\u200bry` evades the substring screen (no control chars, no
    literal 'sorry') but must die in the kernel as a parse error."""
    smuggled = "by exact sor\u200bry"
    assert screen_submission(smuggled) is None  # documents the screen gap
    result = check_proof(LEAN, "", "1 + 1 = 2", smuggled)
    assert not result.ok


@needs_lean
def test_proof_of_a_different_true_statement_is_not_accepted():
    """Proving something true but different from the target must not count:
    the submission is typed against the target proposition only."""
    gc = make_challenge("proof", b"\x0a" * 32, 1)
    # `Nat.zero_le n` proves `0 ≤ n`, not the generated inequality
    result = check_proof(
        LEAN, gc.payload.preamble, gc.payload.proposition,
        "fun n => Nat.zero_le n",
    )
    assert not result.ok
