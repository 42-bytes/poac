"""MCP server exposing PoAC to any MCP-capable agent (Claude, Cursor, Codex, …).

Run:  poac-mcp [--verifier https://poac.42bytes.eu] [--key-file ~/.poac/holder.jwk]
Env:  POAC_VERIFIER_URL, POAC_KEY_FILE

Tools (all return JSON-serialisable dicts; the agent does the thinking):
  poac_discover  — manifest + tiers so the agent can choose a tier
  poac_start     — open a session; returns round 1 (challenge, deadline)
  poac_submit    — submit an answer; returns next round, or the receipt
  poac_present   — build a key-binding JWT for an audience + nonce
  poac_verify    — relying-party side: verify a receipt + KB-JWT

The holder key lives on disk (0600) so receipts earned across sessions
belong to the same agent identity. Receipts are returned in full; the
agent is responsible for sending them to the platform that asked.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from poac.client import HolderKey, PoacClient, PoacError, _unverified_claims, kb_nonce

DEFAULT_VERIFIER = "https://poac.42bytes.eu"
DEFAULT_KEY_FILE = Path.home() / ".poac" / "holder.jwk"


def load_or_create_key(path: Path) -> HolderKey:
    if path.exists():
        return HolderKey.load(path)
    key = HolderKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    key.save(path)
    return key


class PoacTools:
    """Plain callables, so they are testable without an MCP transport."""

    def __init__(self, client: PoacClient):
        self.client = client
        self._receipts: dict[str, str] = {}  # session_id -> receipt token, for poac_present

    @staticmethod
    def _err(exc: Exception) -> dict[str, Any]:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)}

    def poac_discover(self) -> dict[str, Any]:
        """Fetch the verifier's capability manifest: offered tiers, rounds per tier,
        per-round time budget (ms), challenge families, receipt TTL. Call first to pick a tier."""
        try:
            return {"ok": True, "verifier": self.client.base_url,
                    "holder_thumbprint": self.client.key.thumbprint,
                    "manifest": self.client.manifest()}
        except (PoacError, Exception) as exc:  # noqa: BLE001
            return self._err(exc)

    def poac_start(self, tier: str = "C1") -> dict[str, Any]:
        """Open a PoAC session at `tier` (C0..C5) bound to this agent's key. Returns
        session_id and round 1. The round deadline is enforced by the server clock:
        answer immediately with poac_submit, do not pause to ask the user."""
        try:
            s = self.client.start(tier, bind_key=True)
            return {"ok": True, **s.model_dump(mode="json")}
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)

    def poac_submit(self, session_id: str, round_index: int, nonce: str,
                    answer: str) -> dict[str, Any]:
        """Submit the answer for the current round. `answer` is the bare answer
        (entity name, integer as text, program output, path weight, or Lean proof
        text after ':='). Returns status 'next' with the next round, 'passed' with
        the receipt, or 'failed' with a reason (then start a new session)."""
        try:
            rnd = SimpleNamespace(round_index=round_index, nonce=nonce)
            out = self.client.submit(session_id, rnd, answer).model_dump(mode="json")
            if out.get("status") == "passed" and out.get("receipt"):
                self._receipts[session_id] = out["receipt"]
                out["expires_at"] = int(_unverified_claims(out["receipt"])["exp"])
            return {"ok": True, **out}
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)

    def poac_present(self, audience: str, nonce: str, receipt: str | None = None,
                     session_id: str | None = None) -> dict[str, Any]:
        """Build the key-binding JWT that proves you hold the key the receipt is
        bound to. `audience` is the relying platform's URL; `nonce` is the fresh value
        it gave you (it fetched it from the verifier). Pass the receipt token, or the
        session_id of a session this server passed. Send both strings to the platform:
        Authorization: PoAC <receipt>, PoAC-KB: <kb_jwt>."""
        try:
            if receipt is None:
                if session_id is None or session_id not in self._receipts:
                    raise PoacError("give `receipt` or a `session_id` that passed here")
                receipt = self._receipts[session_id]
            kb = self.client.present(receipt, audience=audience, nonce=nonce)
            return {"ok": True, "receipt": receipt, "kb_jwt": kb,
                    "headers": {"Authorization": f"PoAC {receipt}", "PoAC-KB": kb}}
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)

    def poac_verify(self, receipt: str, kb_jwt: str, audience: str,
                    nonce: str | None = None) -> dict[str, Any]:
        """Relying-party check: ask the verifier whether receipt + kb_jwt are valid
        for `audience`. If `nonce` is omitted it is read from the kb_jwt (the verifier
        still enforces that it was issued by it and unused)."""
        try:
            if nonce is None:
                nonce = kb_nonce(kb_jwt)
            if not nonce:
                raise PoacError("kb_jwt is malformed or lacks a nonce")
            return {"ok": True, **self.client.verify(receipt, kb_jwt, audience, nonce)}
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)

    def all(self):
        return [self.poac_discover, self.poac_start, self.poac_submit,
                self.poac_present, self.poac_verify]


def build_server(client: PoacClient):
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        name="poac",
        version="0.2.0",
        instructions=(
            "PoAC (Proof of Agent Capability) is a reverse CAPTCHA. When a site or API "
            "asks for PoAC: poac_discover → poac_start(tier) → poac_submit for each round "
            "(answer fast; rounds have server-side deadlines of a few seconds) → "
            "poac_present(audience, nonce) → send the two headers to the site. "
            "Use poac_verify only when you are the relying party."
        ),
    )
    tools = PoacTools(client)
    for fn in tools.all():
        server.tool(name=fn.__name__)(fn)
    return server


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verifier", default=os.environ.get("POAC_VERIFIER_URL", DEFAULT_VERIFIER))
    ap.add_argument("--key-file", type=Path,
                    default=Path(os.environ.get("POAC_KEY_FILE", DEFAULT_KEY_FILE)))
    ap.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    args = ap.parse_args(argv)
    client = PoacClient(args.verifier, key=load_or_create_key(args.key_file))
    build_server(client).run(transport=args.transport)


if __name__ == "__main__":
    main()
