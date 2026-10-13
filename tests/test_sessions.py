"""Orchestrator tests: happy paths, timing, replay, protocol violations."""

import pytest

from poac.credentials.issuer import ReceiptIssuer
from poac.protocol.models import (
    CapabilityTier,
    FailureClass,
    HolderJwk,
    IdentityTier,
    NextRoundResponse,
    SessionFailedResponse,
    SessionPassedResponse,
)
from poac.reference.solver import solve
from poac.sessions.config import TIERS
from poac.sessions.orchestrator import Orchestrator, SessionError


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


from poac.challenges.proof_check import find_lean

LEAN = find_lean()


@pytest.fixture
def orchestrator(clock):
    return Orchestrator(
        ReceiptIssuer.generate(), server_secret=b"s" * 32, clock=clock,
        lean_bin=LEAN,
    )


def _play(orchestrator, clock, tier, per_round_delay=1.0, holder_jwk=None):
    created = orchestrator.create_session(tier, holder_jwk)
    outcome = None
    rnd = created.round
    while True:
        clock.advance(per_round_delay)
        outcome = orchestrator.submit(
            created.session_id, rnd.round_index, rnd.nonce, solve(rnd.challenge)
        )
        if isinstance(outcome, NextRoundResponse):
            rnd = outcome.round
            continue
        return created, outcome


@pytest.mark.parametrize("tier", list(CapabilityTier))
def test_full_pass_all_tiers(orchestrator, clock, tier):
    created, outcome = _play(orchestrator, clock, tier)
    assert isinstance(outcome, SessionPassedResponse)
    assert outcome.capability_tier is tier
    assert len(outcome.latency_ms) == TIERS[tier].rounds
    assert outcome.receipt.count(".") == 2  # compact JWS


def test_identity_tier_reflects_key_commitment(orchestrator, clock):
    jwk = HolderJwk(kty="OKP", crv="Ed25519", x="A" * 43)
    created, outcome = _play(orchestrator, clock, CapabilityTier.C1, holder_jwk=jwk)
    assert outcome.identity_tier is IdentityTier.I1

    created2, outcome2 = _play(orchestrator, clock, CapabilityTier.C1)
    assert outcome2.identity_tier is IdentityTier.I0


def test_c2_mixes_at_least_three_families(orchestrator, clock):
    _, outcome = _play(orchestrator, clock, CapabilityTier.C2)
    assert len(set(outcome.families)) >= 3


def test_round_timeout_fails_session(orchestrator, clock):
    created = orchestrator.create_session(CapabilityTier.C1, None)
    rnd = created.round
    clock.advance(TIERS[CapabilityTier.C1].round_deadline_ms / 1000 + 0.5)
    outcome = orchestrator.submit(
        created.session_id, rnd.round_index, rnd.nonce, solve(rnd.challenge)
    )
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.timeout
    # session is dead afterwards
    with pytest.raises(SessionError):
        orchestrator.submit(created.session_id, 1, rnd.nonce, "x")


def test_timing_boundary_inside_budget_passes(orchestrator, clock):
    created = orchestrator.create_session(CapabilityTier.C1, None)
    rnd = created.round
    clock.advance(TIERS[CapabilityTier.C1].round_deadline_ms / 1000 - 0.05)
    outcome = orchestrator.submit(
        created.session_id, rnd.round_index, rnd.nonce, solve(rnd.challenge)
    )
    assert isinstance(outcome, NextRoundResponse)


def test_wrong_answer_fails_without_revealing_expected(orchestrator, clock):
    created = orchestrator.create_session(CapabilityTier.C1, None)
    rnd = created.round
    outcome = orchestrator.submit(
        created.session_id, rnd.round_index, rnd.nonce, "definitely wrong"
    )
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.wrong_answer
    # structural leakage check: the failure payload carries only these fields
    # (a plain substring check is flaky — short numeric answers collide with
    # JSON digits like round_index)
    assert set(outcome.model_dump()) == {
        "status", "session_id", "failure", "round_index"
    }
    assert outcome.session_id == created.session_id


def test_wrong_nonce_is_protocol_violation(orchestrator, clock):
    created = orchestrator.create_session(CapabilityTier.C1, None)
    rnd = created.round
    outcome = orchestrator.submit(
        created.session_id, rnd.round_index, "forged-nonce", solve(rnd.challenge)
    )
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.protocol_violation


def test_wrong_round_index_is_protocol_violation(orchestrator, clock):
    created = orchestrator.create_session(CapabilityTier.C1, None)
    rnd = created.round
    outcome = orchestrator.submit(
        created.session_id, rnd.round_index + 1, rnd.nonce, solve(rnd.challenge)
    )
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.protocol_violation


def test_replay_of_completed_round_rejected(orchestrator, clock):
    created = orchestrator.create_session(CapabilityTier.C1, None)
    rnd = created.round
    answer = solve(rnd.challenge)
    nxt = orchestrator.submit(created.session_id, rnd.round_index, rnd.nonce, answer)
    assert isinstance(nxt, NextRoundResponse)
    replay = orchestrator.submit(created.session_id, rnd.round_index, rnd.nonce, answer)
    assert isinstance(replay, SessionFailedResponse)
    assert replay.failure is FailureClass.protocol_violation


def test_session_expiry(orchestrator, clock):
    created = orchestrator.create_session(CapabilityTier.C1, None)
    rnd = created.round
    clock.advance(TIERS[CapabilityTier.C1].session_deadline_ms / 1000 + 1)
    outcome = orchestrator.submit(
        created.session_id, rnd.round_index, rnd.nonce, solve(rnd.challenge)
    )
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.expired


def test_unknown_session_raises(orchestrator):
    with pytest.raises(SessionError):
        orchestrator.submit("nope", 1, "n", "a")


def test_sessions_are_single_use_after_pass(orchestrator, clock):
    created, outcome = _play(orchestrator, clock, CapabilityTier.C0)
    assert isinstance(outcome, SessionPassedResponse)
    with pytest.raises(SessionError):
        orchestrator.submit(created.session_id, 1, "n", "a")


def test_challenges_differ_across_sessions_and_secrets(clock):
    issuer = ReceiptIssuer.generate()
    orch_a = Orchestrator(issuer, server_secret=b"a" * 32, clock=clock)
    orch_b = Orchestrator(issuer, server_secret=b"b" * 32, clock=clock)
    payloads = {
        orch.create_session(CapabilityTier.C1, None).round.challenge.model_dump_json()
        for orch in (orch_a, orch_b)
        for _ in range(3)
    }
    assert len(payloads) == 6, "sessions must not share challenge instances"


def test_capacity_limit(clock):
    orch = Orchestrator(
        ReceiptIssuer.generate(), server_secret=b"s" * 32, clock=clock, max_sessions=2
    )
    orch.create_session(CapabilityTier.C0, None)
    orch.create_session(CapabilityTier.C0, None)
    with pytest.raises(SessionError):
        orch.create_session(CapabilityTier.C0, None)
