"""Relying-party integration for FastAPI/Starlette apps.

    from fastapi import Depends, FastAPI
    from poac.rp import PoacGate

    gate = PoacGate(verifier_url="https://poac.42bytes.eu",
                    audience="https://forum.example", min_tier="C1")
    app = FastAPI()
    app.include_router(gate.router)        # GET /poac/nonce for agents

    @app.post("/posts")
    def create_post(agent = Depends(gate.require)):
        return {"posted_by": agent.holder_thumbprint, "tier": agent.tier}

Wire format (what an agent sends):

    Authorization: PoAC <receipt JWS>
    PoAC-KB: <key-binding JWT over {aud, nonce, iat, receipt_hash}>

The agent gets the nonce from ``GET /poac/nonce`` on *this* app, which
proxies the verifier's one-shot ``GET /v1/verify/nonce``. The gate is
stateless: the verifier enforces nonce freshness and single use, and the
``aud`` claim ties the presentation to this audience. A missing or bad
presentation yields 401 with a ``WWW-Authenticate`` challenge that tells
the agent where the verifier and the nonce endpoint are.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from poac.client import kb_nonce
from poac.protocol.models import CapabilityTier, IdentityTier

_TIER_ORDER = {t: i for i, t in enumerate(CapabilityTier)}


@dataclass(frozen=True)
class PoacAgent:
    """What a passing presentation proves about the caller."""

    tier: str
    identity_tier: str
    holder_thumbprint: str | None
    issued_at: int | None
    expires_at: int | None
    receipt: str

    def at_least(self, tier: str) -> bool:
        return _TIER_ORDER[CapabilityTier(self.tier)] >= _TIER_ORDER[CapabilityTier(tier)]


class PoacGate:
    def __init__(
        self,
        verifier_url: str,
        audience: str,
        min_tier: str = "C1",
        min_identity_tier: str = "I1",
        nonce_path: str = "/poac/nonce",
        http: httpx.Client | None = None,
        timeout: float = 10.0,
    ):
        CapabilityTier(min_tier)
        IdentityTier(min_identity_tier)
        self.verifier_url = verifier_url.rstrip("/")
        self.audience = audience
        self.min_tier = min_tier
        self.min_identity_tier = min_identity_tier
        self.nonce_path = nonce_path
        self._http = http or httpx.Client(base_url=self.verifier_url, timeout=timeout)
        self.router = APIRouter()
        self.router.add_api_route(nonce_path, self._nonce_endpoint, methods=["GET"],
                                  include_in_schema=False)

    # --- agent-facing nonce proxy ----------------------------------------------------

    def _nonce_endpoint(self, response: Response) -> dict:
        r = self._http.get("/v1/verify/nonce")
        if r.status_code != 200:
            raise HTTPException(503, "PoAC verifier unavailable")
        body = r.json()
        response.headers["Cache-Control"] = "no-store"
        return {"nonce": body["nonce"], "expires_in": body["expires_in"],
                "audience": self.audience, "verifier": self.verifier_url}

    # --- the dependency -----------------------------------------------------------------

    def _challenge(self, detail: str, status: int = 401) -> HTTPException:
        return HTTPException(
            status, detail,
            headers={"WWW-Authenticate": (
                f'PoAC realm="{self.audience}", verifier="{self.verifier_url}", '
                f'nonce="{self.nonce_path}", min_tier="{self.min_tier}"'
            )},
        )

    def require(self, request: Request) -> PoacAgent:
        auth = request.headers.get("Authorization", "")
        scheme, _, receipt = auth.partition(" ")
        kb_jwt = request.headers.get("PoAC-KB")
        if scheme.lower() != "poac" or not receipt or not kb_jwt:
            raise self._challenge("PoAC receipt and key-binding JWT required")
        nonce = kb_nonce(kb_jwt)
        if not nonce:
            raise self._challenge("key-binding JWT is malformed or lacks a nonce")
        r = self._http.post("/v1/verify", json={
            "receipt": receipt, "kb_jwt": kb_jwt, "audience": self.audience, "nonce": nonce,
        })
        if r.status_code != 200:
            raise HTTPException(503, "PoAC verifier unavailable")
        res = r.json()
        if not res.get("valid"):
            raise self._challenge(f"PoAC presentation rejected: {res.get('reason')}")
        agent = PoacAgent(
            tier=res["capability_tier"], identity_tier=res["identity_tier"],
            holder_thumbprint=res.get("holder_thumbprint"),
            issued_at=res.get("issued_at"), expires_at=res.get("expires_at"), receipt=receipt,
        )
        if not agent.at_least(self.min_tier):
            raise self._challenge(
                f"capability tier {agent.tier} below required {self.min_tier}", status=403)
        if list(IdentityTier).index(IdentityTier(agent.identity_tier)) < \
                list(IdentityTier).index(IdentityTier(self.min_identity_tier)):
            raise self._challenge(
                f"identity tier {agent.identity_tier} below required {self.min_identity_tier}",
                status=403)
        return agent
