"""Proof family: kernel validator security, C4 sessions, discovery gating.

Kernel-dependent tests are skipped when no Lean toolchain is present so the
suite still runs on hosts without one (the same condition under which the
verifier itself disables tier C4).
"""

import pytest
from fastapi.testclient import TestClient

from poac.api.app import create_app
from poac.challenges import make_challenge
from poac.challenges.proof_check import (
    check_proof,
    find_lean,
    screen_submission,
)
from poac.credentials.issuer import ReceiptIssuer
from poac.protocol.models import CapabilityTier, FailureClass
from poac.reference.solver import solve
from poac.sessions.orchestrator import Orchestrator, SessionError

LEAN = find_lean()
needs_lean = pytest.mark.skipif(LEAN is None, reason="no Lean toolchain")

SEED = b"\x05" * 32


# --- submission screen (no Lean needed) -------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "by sorry",
        "by exact sorryAx _ true",
        "by admit",
        "by decide\naxiom evil : False",
        "by decide\n#eval IO.println \"pwned\"",
        "by decide\nmacro \"boom\" : tactic => `(tactic| sorry)",
        "by decide\nset_option maxHeartbeats 0",
        "by decide\nunsafe def f : Nat := 0",
        "by native_decide",
        "by decide\nopen Lean in example : True := trivial",
        "by decide\nattribute [simp] Nat.add",
        "",
        "   \n  ",
        "by decide \x00",
        "x" * 30_000,
    ],
)
def test_screen_rejects_dangerous_submissions(bad):
    assert screen_submission(bad) is not None


def test_screen_accepts_legitimate_proofs():
    for good in (
        "by decide",
        "by intro n; omega",
        "by\n  intro n\n  induction n with\n  | zero => rfl\n"
        "  | succ k ih => simp only [poacF]; omega",
    ):
        assert screen_submission(good) is None


# --- kernel validation -------------------------------------------------------


@needs_lean
@pytest.mark.parametrize("difficulty", [0, 1, 2, 3])
def test_reference_proofs_pass_kernel(difficulty):
    gc = make_challenge("proof", SEED, difficulty)
    result = check_proof(
        LEAN, gc.payload.preamble, gc.payload.proposition, gc.answer
    )
    assert result.ok, result.reason


@needs_lean
def test_wrong_proof_rejected():
    gc = make_challenge("proof", SEED, 1)
    result = check_proof(
        LEAN, gc.payload.preamble, gc.payload.proposition, "by intro n; rfl"
    )
    assert not result.ok


@needs_lean
def test_blind_tactics_fail_induction_goals():
    """d2/d3 goals must not fall to definition-blind tactic spam."""
    from benchmarks.clients import BLIND_TACTIC_SPAM

    for difficulty in (2, 3):
        gc = make_challenge("proof", SEED, difficulty)
        result = check_proof(
            LEAN, gc.payload.preamble, gc.payload.proposition, BLIND_TACTIC_SPAM
        )
        assert not result.ok, f"blind spam passed d{difficulty}"


@needs_lean
def test_kernel_timeout_enforced():
    gc = make_challenge("proof", SEED, 0)
    result = check_proof(
        LEAN, gc.payload.preamble, gc.payload.proposition, "by decide",
        timeout_s=0.01,
    )
    assert not result.ok and "timed out" in result.reason


@needs_lean
def test_reference_solver_proofs_are_kernel_valid():
    for difficulty in (0, 1, 2, 3):
        gc = make_challenge("proof", SEED, difficulty)
        submission = solve(gc.payload)
        result = check_proof(
            LEAN, gc.payload.preamble, gc.payload.proposition, submission
        )
        assert result.ok, f"d{difficulty}: {result.reason}"


# --- C4 session orchestration ------------------------------------------------


@needs_lean
def test_full_c4_session_passes():
    orch = Orchestrator(ReceiptIssuer.generate(), lean_bin=LEAN)
    created = orch.create_session(CapabilityTier.C4, None)
    rnd = created.round
    while True:
        outcome = orch.submit(
            created.session_id, rnd.round_index, rnd.nonce, solve(rnd.challenge)
        )
        if getattr(outcome, "status", None) == "next":
            rnd = outcome.round
            continue
        break
    assert outcome.status == "passed"
    assert outcome.families == ["proof", "proof", "proof"]


@needs_lean
def test_c4_wrong_proof_fails_session():
    orch = Orchestrator(ReceiptIssuer.generate(), lean_bin=LEAN)
    created = orch.create_session(CapabilityTier.C4, None)
    rnd = created.round
    outcome = orch.submit(created.session_id, rnd.round_index, rnd.nonce, "by sorry")
    assert outcome.status == "failed"
    assert outcome.failure is FailureClass.wrong_answer


def test_c4_unavailable_without_lean():
    orch = Orchestrator(ReceiptIssuer.generate(), lean_bin=None)
    with pytest.raises(SessionError, match="no Lean toolchain"):
        orch.create_session(CapabilityTier.C4, None)


# --- discovery gating ---------------------------------------------------------


def test_manifest_hides_c4_without_lean():
    client = TestClient(create_app(lean_bin=None))
    tiers = {t["tier"] for t in client.get("/.well-known/agent-capability.json").json()["tiers"]}
    assert tiers == {"C0", "C1", "C2", "C3"}
    # and creating a C4 session is refused
    resp = client.post("/v1/sessions", json={"tier": "C4"})
    assert resp.status_code == 503


@needs_lean
def test_manifest_lists_c4_with_lean():
    client = TestClient(create_app(lean_bin=LEAN))
    tiers = {t["tier"] for t in client.get("/.well-known/agent-capability.json").json()["tiers"]}
    assert "C4" in tiers


@needs_lean
def test_full_c4_flow_over_http():
    client = TestClient(create_app(lean_bin=LEAN))
    resp = client.post("/v1/sessions", json={"tier": "C4"})
    assert resp.status_code == 201
    data = resp.json()
    rnd = data["round"]
    while True:
        from poac.protocol.models import ProofChallenge

        payload = ProofChallenge.model_validate(rnd["challenge"])
        resp = client.post(
            f"/v1/sessions/{data['session_id']}/rounds/{rnd['round_index']}",
            json={"nonce": rnd["nonce"], "answer": solve(payload)},
        )
        assert resp.status_code == 200, resp.text
        outcome = resp.json()
        if outcome["status"] == "next":
            rnd = outcome["round"]
            continue
        break
    assert outcome["status"] == "passed"
