"""Client IP behind the proxy, and pseudonymous source tags in the trials log.

Behind Caddy every request arrives from the proxy's address, so rate limits
keyed on `request.client.host` would share one bucket. With proxy headers
trusted, the real client IP is used — and /play rows carry a keyed hash of
it (never the address itself) so spam can be clustered and purged.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from poac.api.app import create_app, with_proxy_headers
from poac.credentials.issuer import ReceiptIssuer
from poac.sessions.orchestrator import Orchestrator
from poac.trials.log import TrialLog, purge_source
from poac.trials.source import source_tags


@pytest.fixture
def env(tmp_path):
    orch = Orchestrator(ReceiptIssuer.generate(), server_secret=b"k" * 32, lean_bin=None)
    log = TrialLog(tmp_path / "t.jsonl")
    app = create_app(orchestrator=orch, lean_bin=None, session_rate_per_minute=2, trial_log=log)
    return TestClient(with_proxy_headers(app)), orch, log, tmp_path / "t.jsonl"


def _start(client, ip):
    return client.post("/play/api/start", json={"tier": "C1", "mode": "unaided"},
                       headers={"X-Forwarded-For": ip})


def test_rate_limit_is_per_forwarded_client(env):
    client, *_ = env
    assert _start(client, "203.0.113.5").status_code == 201
    assert _start(client, "203.0.113.5").status_code == 201
    assert _start(client, "203.0.113.5").status_code == 429
    assert _start(client, "203.0.113.6").status_code == 201  # another visitor, own bucket


def test_rows_carry_source_tags_not_ip(env):
    client, orch, log, path = env
    key = orch.derived_key("trials-source")
    created = _start(client, "203.0.113.5").json()
    rnd = created["round"]
    client.post("/play/api/submit", json={"session_id": created["session_id"],
                "round_index": rnd["round_index"], "nonce": rnd["nonce"], "answer": "x"},
                headers={"X-Forwarded-For": "203.0.113.5"})
    text = path.read_text()
    assert "203.0.113" not in text
    rows = [json.loads(l) for l in text.splitlines()]
    assert {r["event"] for r in rows} == {"round", "session"}
    src, net = source_tags(key, "203.0.113.5")
    for r in rows:
        assert r["src"] == src and r["net"] == net
    assert len(src) == 16 and len(net) == 16


def test_source_tags_cluster_by_network():
    key = b"k" * 32
    a, an = source_tags(key, "203.0.113.5")
    b, bn = source_tags(key, "203.0.113.77")
    c, cn = source_tags(key, "198.51.100.1")
    assert a != b and an == bn and an != cn
    v6a, v6n = source_tags(key, "2001:db8:1:2::1")
    v6b, v6m = source_tags(key, "2001:db8:1:2:ffff::9")
    assert v6a != v6b and v6n == v6m
    assert source_tags(b"other" * 7, "203.0.113.5")[0] != a  # keyed: no rainbow tables


def test_purge_source_drops_matching_rows_and_stats_follow(tmp_path):
    path = tmp_path / "t.jsonl"
    log = TrialLog(path)
    log.append({"event": "session", "src": "aaaa", "net": "n1", "tier": "C1", "mode": "unaided",
                "status": "failed", "failure": "wrong_answer", "rounds_correct": 0, "total_ms": 1})
    log.append({"event": "session", "src": "bbbb", "net": "n1", "tier": "C1", "mode": "unaided",
                "status": "failed", "failure": "wrong_answer", "rounds_correct": 0, "total_ms": 1})
    log.append({"event": "round", "src": "aaaa", "net": "n1", "tier": "C1", "mode": "unaided",
                "round_index": 1, "family": "nlu", "answer_ms": 5, "budget_ms": 20000,
                "outcome": "wrong_answer", "correct_if_untimed": False, "answer_chars": 1})
    removed = purge_source(path, src="aaaa")
    assert removed == 2
    rows = [json.loads(l) for l in path.read_text().splitlines()]
    assert [r["src"] for r in rows] == ["bbbb"]
    assert purge_source(path, net="n1") == 1
    assert path.read_text().strip() == ""


def test_without_proxy_wrapper_header_is_ignored(tmp_path):
    """Direct exposure (no Caddy) must not let clients spoof their address."""
    app = create_app(lean_bin=None, session_rate_per_minute=1, trial_log=TrialLog(tmp_path / "t.jsonl"))
    client = TestClient(app)
    assert _start(client, "203.0.113.5").status_code == 201
    assert _start(client, "203.0.113.6").status_code == 429  # same real client, header ignored
