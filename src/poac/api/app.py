"""FastAPI application factory for the PoAC prototype verifier."""

from __future__ import annotations

import threading
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from poac.challenges.proof_check import find_lean
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.presentation import verify_presentation

_AUTODETECT = object()  # sentinel: None must remain a valid "disabled" value
from poac.discovery.content import (
    CAPABILITY_MANIFEST_PATH,
    HUMAN_NOTICE_HTML,
    LLMS_TXT,
    build_manifest,
)
from poac.protocol.models import (
    PresentationRequest,
    PresentationResult,
    RoundOutcome,
    RoundSubmitRequest,
    SessionCreatedResponse,
    SessionCreateRequest,
)
from poac.sessions.orchestrator import Orchestrator, SessionError

MAX_BODY_BYTES = 64 * 1024
SESSION_RATE_PER_MINUTE = 30


class _RateLimiter:
    """Minimal fixed-window per-client limiter (prototype scope: L3)."""

    def __init__(self, limit_per_minute: int):
        self._limit = limit_per_minute
        self._window: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        minute = int(time.time() // 60)
        with self._lock:
            win, count = self._window.get(client, (minute, 0))
            if win != minute:
                win, count = minute, 0
            if count >= self._limit:
                self._window[client] = (win, count)
                return False
            self._window[client] = (win, count + 1)
            return True


def create_app(
    issuer: ReceiptIssuer | None = None,
    orchestrator: Orchestrator | None = None,
    base_url: str = "http://localhost:8000",
    session_rate_per_minute: int = SESSION_RATE_PER_MINUTE,
    lean_bin: str | None | object = _AUTODETECT,
) -> FastAPI:
    issuer = issuer or ReceiptIssuer.generate(issuer_url=base_url)
    if lean_bin is _AUTODETECT:
        lean_bin = find_lean()
    orchestrator = orchestrator or Orchestrator(issuer, lean_bin=lean_bin)
    kernel_tiers_enabled = orchestrator.lean_bin is not None
    limiter = _RateLimiter(session_rate_per_minute)
    seen_verify_nonces: set[str] = set()
    verify_lock = threading.Lock()

    app = FastAPI(
        title="PoAC — Proof of Agent Capability (prototype)",
        version="0.1.0",
        description=(
            "Reverse-CAPTCHA verifier: timed multi-round challenges that are "
            "easy for autonomous AI agents and infeasible for humans under "
            "the deadline. Passing proves timed capability of a key holder — "
            "never identity, intent, or absence of human origin."
        ),
    )
    app.state.issuer = issuer
    app.state.orchestrator = orchestrator

    @app.middleware("http")
    async def guard_and_link_headers(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and int(length) > MAX_BODY_BYTES:
            return PlainTextResponse("payload too large", status_code=413)
        response = await call_next(request)
        response.headers["Link"] = (
            f'</llms.txt>; rel="describedby", '
            f'<{CAPABILITY_MANIFEST_PATH}>; rel="describedby", '
            f'</openapi.json>; rel="service-desc"'
        )
        return response

    # --- challenge sessions -------------------------------------------------

    @app.post("/v1/sessions", response_model=SessionCreatedResponse, status_code=201)
    def create_session(body: SessionCreateRequest, request: Request):
        client = request.client.host if request.client else "unknown"
        if not limiter.allow(client):
            raise HTTPException(429, "rate limit exceeded")
        try:
            return orchestrator.create_session(body.tier, body.holder_jwk)
        except SessionError as exc:
            raise HTTPException(503, exc.message) from exc

    @app.post("/v1/sessions/{session_id}/rounds/{round_index}")
    def submit_round(
        session_id: str, round_index: int, body: RoundSubmitRequest
    ) -> RoundOutcome:
        try:
            return orchestrator.submit(session_id, round_index, body.nonce, body.answer)
        except SessionError as exc:
            raise HTTPException(404, exc.message) from exc

    # --- relying-platform verification --------------------------------------

    @app.post("/v1/verify", response_model=PresentationResult)
    def verify(body: PresentationRequest):
        with verify_lock:
            if body.nonce in seen_verify_nonces:
                return PresentationResult(valid=False, reason="nonce already used")
            seen_verify_nonces.add(body.nonce)
        return verify_presentation(
            receipt=body.receipt,
            kb_jwt=body.kb_jwt,
            audience=body.audience,
            nonce=body.nonce,
            issuer_jwks=issuer.jwks(),
        )

    # --- discovery -----------------------------------------------------------

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def human_notice():
        return HUMAN_NOTICE_HTML

    @app.get("/llms.txt", response_class=PlainTextResponse, include_in_schema=False)
    def llms_txt():
        return LLMS_TXT

    @app.get(CAPABILITY_MANIFEST_PATH, include_in_schema=False)
    def capability_manifest():
        return build_manifest(
            issuer.issuer_url, include_kernel_tiers=kernel_tiers_enabled
        ).model_dump()

    @app.get("/.well-known/jwks.json", include_in_schema=False)
    def jwks():
        return issuer.jwks()

    return app
