"""poac.mcp_server — MCP tool surface (phase 2, D2)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from poac.api.app import create_app
from poac.client import _CHALLENGE, PoacClient
from poac.mcp_server import PoacTools, build_server, load_or_create_key
from poac.reference.solver import solve

AUD = "https://forum.example"


@pytest.fixture
def verifier():
    return TestClient(create_app(lean_bin=None, session_rate_per_minute=10_000))


@pytest.fixture
def tools(verifier):
    return PoacTools(PoacClient("http://poac.test", http=verifier))


def _play(tools, tier="C1"):
    s = tools.poac_start(tier)
    assert s["ok"], s
    sid, rnd = s["session_id"], s["round"]
    while True:
        answer = solve(_CHALLENGE.validate_python(rnd["challenge"]))
        out = tools.poac_submit(sid, rnd["round_index"], rnd["nonce"], answer)
        assert out["ok"], out
        if out["status"] == "next":
            rnd = out["round"]
            continue
        return sid, out


def test_discover_lists_tiers(tools):
    d = tools.poac_discover()
    assert d["ok"] and d["verifier"] == "http://poac.test"
    assert {t["tier"] for t in d["manifest"]["tiers"]} >= {"C0", "C1", "C2", "C3"}
    assert d["holder_thumbprint"] == tools.client.key.thumbprint


def test_start_submit_present_verify_round_trip(tools):
    sid, out = _play(tools)
    assert out["status"] == "passed" and out["receipt"] and out["expires_at"] > 0
    assert out["identity_tier"] == "I1"  # bound to the on-disk/holder key

    nonce = tools.client.verify_nonce()
    p = tools.poac_present(audience=AUD, nonce=nonce, session_id=sid)
    assert p["ok"] and p["headers"]["Authorization"] == f"PoAC {out['receipt']}"

    v = tools.poac_verify(p["receipt"], p["kb_jwt"], audience=AUD)  # nonce read from kb_jwt
    assert v["ok"] and v["valid"] is True and v["capability_tier"] == "C1"
    assert v["holder_thumbprint"] == tools.client.key.thumbprint

    # the same presentation cannot be replayed
    v2 = tools.poac_verify(p["receipt"], p["kb_jwt"], audience=AUD)
    assert v2["ok"] and v2["valid"] is False


def test_errors_are_returned_not_raised(tools):
    assert tools.poac_start("C9")["ok"] is False
    assert tools.poac_submit("nope", 0, "x", "y")["ok"] is False
    assert tools.poac_present(AUD, "n", session_id="unknown")["ok"] is False
    assert tools.poac_verify("a.b.c", "not-a-jwt", AUD)["ok"] is False


def test_wrong_answer_fails_session_cleanly(tools):
    s = tools.poac_start("C1")
    rnd = s["round"]
    out = tools.poac_submit(s["session_id"], rnd["round_index"], rnd["nonce"], "definitely wrong")
    assert out["ok"] and out["status"] == "failed" and out["failure"]


def test_mcp_server_registers_all_tools(tools):
    server = build_server(tools.client)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == {"poac_discover", "poac_start", "poac_submit", "poac_present", "poac_verify"}
    for t in asyncio.run(server.list_tools()):
        assert t.description and t.input_schema  # agents read these


def test_key_persists_across_servers(tmp_path):
    p = tmp_path / "k" / "holder.jwk"
    a = load_or_create_key(p)
    b = load_or_create_key(p)
    assert a.thumbprint == b.thumbprint
    assert oct(p.stat().st_mode & 0o777) == "0o600"
