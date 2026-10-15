"""poac.client — the one-call agent/relying-party library (phase 2, D1)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from poac.api.app import create_app
from poac.client import HolderKey, PoacClient, PoacError, Receipt, SessionFailed
from poac.protocol.models import FailureClass
from poac.reference.solver import solve


@pytest.fixture
def http():
    return TestClient(create_app(lean_bin=None, session_rate_per_minute=10_000, base_url="http://poac.test"))


def test_quickstart_earn_present_verify(http):
    agent = PoacClient("http://poac.test", http=http)
    receipt = agent.earn("C1", solver=solve)
    assert isinstance(receipt, Receipt)
    assert receipt.tier == "C1" and receipt.identity_tier == "I1"
    assert len(receipt.families) == 3 and not receipt.is_expired()
    assert receipt.claims["cnf"]["jkt"] == agent.key.thumbprint

    # relying party, with its own client instance and no key of its own
    rp = PoacClient("http://poac.test", http=http)
    nonce = rp.verify_nonce()
    kb = agent.present(receipt, audience="https://rp.example", nonce=nonce)
    result = rp.verify(receipt, kb, audience="https://rp.example", nonce=nonce)
    assert result["valid"] is True, result
    # one-shot nonce: a replay is refused by the verifier
    assert rp.verify(receipt, kb, audience="https://rp.example", nonce=nonce)["valid"] is False


def test_wrong_key_cannot_present_someone_elses_receipt(http):
    agent = PoacClient("http://poac.test", http=http)
    receipt = agent.earn("C0", solver=solve)
    thief = PoacClient("http://poac.test", http=http)  # different key
    nonce = thief.verify_nonce()
    kb = thief.present(receipt, audience="https://rp", nonce=nonce)
    res = thief.verify(receipt, kb, audience="https://rp", nonce=nonce)
    assert res["valid"] is False and "key" in res["reason"].lower()


def test_session_failed_is_typed(http):
    agent = PoacClient("http://poac.test", http=http)
    with pytest.raises(SessionFailed) as ei:
        agent.earn("C1", solver=lambda c: "definitely wrong")
    assert ei.value.failure is FailureClass.wrong_answer
    assert ei.value.round_index == 1 and ei.value.families[0] in {"nlu", "logic", "data"}


def test_unknown_tier_and_bad_transport_raise_poac_error(http):
    agent = PoacClient("http://poac.test", http=http)
    with pytest.raises(PoacError, match="422"):
        agent.start("C9")
    with pytest.raises(PoacError, match="503"):
        agent.start("C4")  # no Lean in this app


def test_on_round_hook_and_unbound_sessions(http):
    seen = []
    agent = PoacClient("http://poac.test", http=http)
    receipt = agent.earn("C1", solver=solve, bind_key=False,
                         on_round=lambda rnd, ans, dt: seen.append((rnd.round_index, dt >= 0)))
    assert seen == [(1, True), (2, True), (3, True)]
    assert receipt.identity_tier == "I0" and "cnf" not in receipt.claims


def test_holder_key_round_trips_through_disk(tmp_path):
    k = HolderKey.generate()
    k.save(tmp_path / "k.jwk")
    k2 = HolderKey.load(tmp_path / "k.jwk")
    assert k2.thumbprint == k.thumbprint and k2.jwk == k.jwk
    assert oct((tmp_path / "k.jwk").stat().st_mode)[-3:] == "600"


def test_manifest_and_tiers(http):
    agent = PoacClient("http://poac.test", http=http)
    assert agent.tiers() == ["C0", "C1", "C2", "C3"]
    assert "issuer" in agent.manifest()


def test_verify_pins_issuer(http):
    agent = PoacClient("http://poac.test", http=http)
    receipt = agent.earn("C1", solver=solve)
    rp = PoacClient("http://poac.test", http=http)
    nonce = rp.verify_nonce()
    kb = agent.present(receipt, audience="https://rp.example", nonce=nonce)
    res = rp.verify(receipt, kb, audience="https://rp.example", nonce=nonce,
                    expected_issuer="http://other.test")
    assert res["valid"] is False and "issuer mismatch" in res["reason"]
    # the nonce was consumed by the verifier, so a fresh one for the positive case
    nonce = rp.verify_nonce()
    kb = agent.present(receipt, audience="https://rp.example", nonce=nonce)
    assert rp.verify(receipt, kb, audience="https://rp.example", nonce=nonce,
                     expected_issuer="http://poac.test")["valid"] is True
