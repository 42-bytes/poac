"""FastAPI application factory for the PoAC prototype verifier."""

from __future__ import annotations

import threading
import time

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

from poac.api.nonces import InMemoryNonceStore, NonceState, NonceStore
from poac.challenges.proof_check import find_lean
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.presentation import verify_presentation

_AUTODETECT = object()  # sentinel: None must remain a valid "disabled" value
from poac.discovery.content import (
    AGENT_CARD_PATH,
    CAPABILITY_MANIFEST_PATH,
    HUMAN_NOTICE_HTML,
    LLMS_TXT,
    SKILL_MD,
    SKILL_PATH,
    build_agent_card,
    build_manifest,
)
from poac.protocol.models import (
    PresentationRequest,
    PresentationResult,
    RoundOutcome,
    RoundSubmitRequest,
    SessionCreatedResponse,
    SessionCreateRequest,
    VerifyNonceResponse,
)
from poac.sessions.orchestrator import Orchestrator, SessionError, VerifierError
from poac.trials.api import build_trials_router
from poac.trials.log import TrialLog

MAX_BODY_BYTES = 64 * 1024
SESSION_RATE_PER_MINUTE = 30


class _RateLimiter:
    """Minimal fixed-window per-client limiter (prototype scope: L3).

    Memory is bounded: whenever the wall-clock minute rolls over, every
    entry from a previous minute is dropped, so the table never holds more
    than one minute's worth of distinct clients.
    """

    def __init__(self, limit_per_minute: int, clock=time.time):
        self._limit = limit_per_minute
        self._clock = clock
        self._window: dict[str, tuple[int, int]] = {}
        self._current_minute: int | None = None
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        minute = int(self._clock() // 60)
        with self._lock:
            if minute != self._current_minute:
                self._window = {
                    c: wc for c, wc in self._window.items() if wc[0] == minute
                }
                self._current_minute = minute
            win, count = self._window.get(client, (minute, 0))
            if win != minute:
                win, count = minute, 0
            if count >= self._limit:
                self._window[client] = (win, count)
                return False
            self._window[client] = (win, count + 1)
            return True

    def __len__(self) -> int:  # for tests / metrics
        with self._lock:
            return len(self._window)


def with_proxy_headers(app: FastAPI):
    """Trust X-Forwarded-For from the reverse proxy so `request.client.host`
    is the visitor, not the proxy. Only for deployments where the verifier is
    reachable solely through the proxy (the compose stack: Caddy strips any
    client-supplied forwarding headers before adding its own)."""
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    return ProxyHeadersMiddleware(app, trusted_hosts="*")


def create_app(
    issuer: ReceiptIssuer | None = None,
    orchestrator: Orchestrator | None = None,
    base_url: str = "http://localhost:8000",
    session_rate_per_minute: int = SESSION_RATE_PER_MINUTE,
    lean_bin: str | None | object = _AUTODETECT,
    nonce_store: NonceStore | None = None,
    trial_log: TrialLog | None = None,
    trial_clock=None,
) -> FastAPI:
    issuer = issuer or ReceiptIssuer.generate(issuer_url=base_url)
    if lean_bin is _AUTODETECT:
        lean_bin = find_lean()
    orchestrator = orchestrator or Orchestrator(issuer, lean_bin=lean_bin)
    kernel_tiers_enabled = orchestrator.lean_bin is not None
    limiter = _RateLimiter(session_rate_per_minute)
    nonces: NonceStore = nonce_store or InMemoryNonceStore()

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
    app.state.nonce_store = nonces
    app.state.rate_limiter = limiter

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
            return orchestrator.create_session(body.tier, body.holder_jwk, body.receipt_format)
        except SessionError as exc:
            status = 400 if "receipt format" in exc.message else 503
            headers = {"Retry-After": "10"} if "retry later" in exc.message else None
            raise HTTPException(status, exc.message, headers=headers) from exc

    @app.post("/v1/sessions/{session_id}/rounds/{round_index}")
    def submit_round(
        session_id: str, round_index: int, body: RoundSubmitRequest
    ) -> RoundOutcome:
        try:
            return orchestrator.submit(session_id, round_index, body.nonce, body.answer)
        except VerifierError as exc:
            raise HTTPException(503, exc.message) from exc
        except SessionError as exc:
            raise HTTPException(404, exc.message) from exc

    @app.get("/v1/stats")
    def stats(response: Response) -> dict:
        """Lifetime counters: receipts issued (total, per tier) and sessions started."""
        response.headers["Cache-Control"] = "public, max-age=30"
        return orchestrator.counters()

    # --- relying-platform verification --------------------------------------

    @app.get("/v1/verify/nonce", response_model=VerifyNonceResponse)
    def verify_nonce():
        """Issue a one-shot nonce the presenter must bind into its KB-JWT."""
        try:
            nonce, ttl = nonces.issue()
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        return VerifyNonceResponse(nonce=nonce, expires_in=ttl)

    @app.post("/v1/verify", response_model=PresentationResult)
    def verify(body: PresentationRequest):
        # the nonce is consumed whether or not the presentation verifies,
        # so a failed attempt cannot be retried with the same nonce
        state = nonces.consume(body.nonce)
        if state is NonceState.used:
            return PresentationResult(valid=False, reason="nonce already used")
        if state is NonceState.unknown:
            return PresentationResult(
                valid=False,
                reason="nonce not issued by this verifier or expired; GET /v1/verify/nonce",
            )
        return verify_presentation(
            receipt=body.receipt,
            kb_jwt=body.kb_jwt,
            audience=body.audience,
            nonce=body.nonce,
            issuer_jwks=issuer.jwks(),
            expected_issuer=issuer.issuer_url,
            require_pq=body.require_pq,
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
            issuer.issuer_url, include_kernel_tiers=kernel_tiers_enabled,
            receipt_formats=issuer.receipt_formats,
        ).model_dump()

    @app.get("/.well-known/jwks.json", include_in_schema=False)
    def jwks():
        return issuer.jwks()

    @app.get(AGENT_CARD_PATH, include_in_schema=False)
    def agent_card():
        return build_agent_card(issuer.issuer_url, include_kernel_tiers=kernel_tiers_enabled)

    @app.get(SKILL_PATH, response_class=PlainTextResponse, include_in_schema=False)
    def skill_md():
        return SKILL_MD.replace("{verifier_url}", issuer.issuer_url)

    # --- human-trial game (/play) -------------------------------------------
    app.state.trial_log = trial_log or TrialLog(None)
    app.include_router(build_trials_router(
        orchestrator, app.state.trial_log, allow=limiter.allow, clock=trial_clock))

    return app
