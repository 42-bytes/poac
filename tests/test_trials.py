"""Human-trial game at /play (phase 2, C2): same orchestrator, same deadlines,
extra server-side telemetry (time-to-answer per family, even for wrong or
late answers) appended to a JSONL log."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from poac.api.app import create_app
from poac.client import _CHALLENGE
from poac.credentials.issuer import ReceiptIssuer
from poac.reference.solver import solve
from poac.sessions.orchestrator import Orchestrator
from poac.trials.log import TrialLog


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    clock = FakeClock()
    issuer = ReceiptIssuer.generate()
    orch = Orchestrator(issuer, clock=clock, lean_bin=None)
    log = TrialLog(tmp_path / "trials.jsonl")
    app = create_app(issuer=issuer, orchestrator=orch, lean_bin=None,
                     session_rate_per_minute=10_000, trial_log=log, trial_clock=clock)
    return TestClient(app), clock, log, tmp_path / "trials.jsonl"


def _start(client, tier="C1", mode="unaided", nick="t1"):
    r = client.post("/play/api/start", json={"tier": tier, "mode": mode, "nickname": nick})
    assert r.status_code == 201, r.text
    return r.json()


def test_page_is_served_and_linked_from_notice(env):
    client, *_ = env
    r = client.get("/play")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "/play/api/start" in r.text
    assert "/play" in client.get("/").text


def test_full_session_logs_server_timed_rounds(env):
    client, clock, log, path = env
    s = _start(client)
    sid, rnd = s["session_id"], s["round"]
    assert rnd["round_index"] == 1 and rnd["time_budget_ms"] > 0
    while True:
        clock.t += 3.5  # human takes 3.5 s per round
        answer = solve(_CHALLENGE.validate_python(rnd["challenge"]))
        out = client.post("/play/api/submit", json={
            "session_id": sid, "round_index": rnd["round_index"],
            "nonce": rnd["nonce"], "answer": answer}).json()
        if out["status"] == "next":
            rnd = out["round"]
            continue
        break
    assert out["status"] == "passed" and out["receipt"]
    rows = [json.loads(l) for l in path.read_text().splitlines()]
    rounds = [r for r in rows if r["event"] == "round"]
    assert len(rounds) == 3
    assert all(r["nickname"] == "t1" and r["mode"] == "unaided" and r["tier"] == "C1"
               for r in rounds)
    assert all(abs(r["answer_ms"] - 3500) < 5 for r in rounds)
    assert all(r["outcome"] == "correct" and r["correct_if_untimed"] is True for r in rounds)
    assert {r["family"] for r in rounds} <= {"nlu", "logic", "data"}
    assert any(r["event"] == "session" and r["status"] == "passed" for r in rows)


def test_late_answer_is_recorded_with_untimed_correctness(env):
    client, clock, log, path = env
    s = _start(client, mode="relay")
    rnd = s["round"]
    clock.t += (rnd["time_budget_ms"] / 1000) + 30  # way over the deadline
    answer = solve(_CHALLENGE.validate_python(rnd["challenge"]))
    out = client.post("/play/api/submit", json={
        "session_id": s["session_id"], "round_index": 1, "nonce": rnd["nonce"],
        "answer": answer}).json()
    assert out["status"] == "failed" and out["failure"] == "timeout"
    assert out["correct_if_untimed"] is True   # the page says "too slow — but right"
    row = [json.loads(l) for l in path.read_text().splitlines() if '"round"' in l][0]
    assert row["outcome"] == "timeout" and row["correct_if_untimed"] is True
    assert row["mode"] == "relay" and row["answer_ms"] > row["budget_ms"]


def test_wrong_answer_recorded(env):
    client, clock, log, path = env
    s = _start(client)
    clock.t += 2
    out = client.post("/play/api/submit", json={
        "session_id": s["session_id"], "round_index": 1,
        "nonce": s["round"]["nonce"], "answer": "nope"}).json()
    assert out["status"] == "failed" and out["failure"] == "wrong_answer"
    row = [json.loads(l) for l in path.read_text().splitlines() if '"round"' in l][0]
    assert row["outcome"] == "wrong_answer" and row["correct_if_untimed"] is False


def test_stats_aggregate_by_family_and_mode(env):
    client, clock, log, path = env
    for mode, dt in (("unaided", 4.0), ("relay", 9.0)):
        s = _start(client, mode=mode)
        clock.t += dt
        client.post("/play/api/submit", json={
            "session_id": s["session_id"], "round_index": 1,
            "nonce": s["round"]["nonce"], "answer": solve(_CHALLENGE.validate_python(s["round"]["challenge"]))})
    # a fast wrong answer: counts as a round (accuracy) but never as a time
    s = _start(client, mode="relay")
    clock.t += 0.5
    client.post("/play/api/submit", json={
        "session_id": s["session_id"], "round_index": 1, "nonce": s["round"]["nonce"], "answer": "nope"})
    st = client.get("/play/api/stats").json()
    assert st["sessions"] == 1 and st["rounds"] == 3   # only the failed session finished
    fam = st["by_family"]
    assert sum(v["n"] for v in fam.values()) == 3
    assert set(st["by_mode"]) == {"unaided", "relay"}
    relay = st["by_mode"]["relay"]
    assert relay["n"] == 2 and relay["n_timed"] == 1
    assert relay["answer_ms_p50"] == pytest.approx(9000, abs=5)   # not dragged down by the 500 ms wrong answer
    assert relay["correct_if_untimed_rate"] == 0.5
    # reference numbers for the comparison chart: per model, per tier
    agents = st["agents"]["solve_ms_p50"]
    # generated by benchmarks/summarize.py; check shape, not this week's numbers
    assert len(agents) >= 5
    for by_tier in agents.values():
        for tier, e in by_tier.items():
            assert tier in {"C1", "C2", "C3", "C4", "C5"}
            assert e["ms"] > 0 and 0.0 <= e["pass"] <= 1.0 and e["n"] > 0
    assert set(agents["Claude Opus 5.5"]) == {"C1", "C2", "C3", "C4", "C5"}
    # humans grouped by tier/mode so the chart can show one level at a time
    assert st["by_tier_and_mode"]["C1/relay"]["answer_ms_p50"] == pytest.approx(9000, abs=5)
    # anonymous per-session mean answer time per mode and tier, sorted, so the
    # page can say where a player stands ("faster than 60% of unaided C1 sessions")
    assert st["session_avg_ms"]["unaided"]["C1"] == [pytest.approx(4000, abs=5)]
    assert st["session_avg_ms"]["relay"]["C1"] == [pytest.approx(9000, abs=5)]   # all-wrong session has no time


def test_bad_input_is_4xx(env):
    client, *_ = env
    assert client.post("/play/api/start", json={"tier": "C9", "mode": "unaided"}).status_code == 422
    assert client.post("/play/api/start", json={"tier": "C1", "mode": "psychic"}).status_code == 422
    assert client.post("/play/api/submit", json={
        "session_id": "nope", "round_index": 1, "nonce": "n", "answer": "a"}).status_code == 404


def test_rate_limited_like_agents(tmp_path):
    client = TestClient(create_app(lean_bin=None, session_rate_per_minute=1,
                                   trial_log=TrialLog(tmp_path / "t.jsonl")))
    assert client.post("/play/api/start", json={"tier": "C1", "mode": "unaided"}).status_code == 201
    assert client.post("/play/api/start", json={"tier": "C1", "mode": "unaided"}).status_code == 429
