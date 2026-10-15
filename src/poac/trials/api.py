"""`/play` routes: the game page, a thin proxy over the orchestrator that
timestamps every round server-side, and aggregate stats.

The proxy calls the *same* orchestrator methods as `/v1/sessions`, so
deadlines, chaining and corpus rotation are identical to what agents face.
The only differences: no holder key (I0), and every submission is logged
with its server-measured time-to-answer and whether it would have been
correct without the clock.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from importlib import resources
from typing import Any, Callable, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import Field

from poac.challenges.base import answers_match
from poac.protocol.models import (
    CapabilityTier,
    NextRoundResponse,
    SessionFailedResponse,
    SessionPassedResponse,
    StrictModel,
)
from poac.sessions.orchestrator import Orchestrator, SessionError, VerifierError
from poac.trials.log import TrialLog

Mode = Literal["unaided", "relay"]
MAX_PENDING = 10_000


class TrialStart(StrictModel):
    tier: CapabilityTier
    mode: Mode
    nickname: str = Field(default="anon", max_length=32)


class TrialSubmit(StrictModel):
    session_id: str
    round_index: int = Field(ge=1)
    nonce: str
    answer: str = Field(max_length=20_000)


@dataclass
class _Pending:
    nickname: str
    mode: str
    tier: str
    round_index: int
    family: str
    issued_at: float
    started_at: float
    rounds_done: int = 0


def build_trials_router(
    orchestrator: Orchestrator,
    log: TrialLog,
    allow: Callable[[str], bool],
    clock: Callable[[], float] | None = None,
) -> APIRouter:
    clock = clock or orchestrator.clock
    router = APIRouter()
    pending: "OrderedDict[str, _Pending]" = OrderedDict()
    lock = threading.Lock()
    page = resources.files("poac.trials").joinpath("play.html").read_text(encoding="utf-8")

    @router.get("/play", response_class=HTMLResponse, include_in_schema=False)
    def play_page():
        return page

    @router.post("/play/api/start", status_code=201, include_in_schema=False)
    def start(body: TrialStart, request: Request) -> dict[str, Any]:
        client = request.client.host if request.client else "unknown"
        if not allow(client):
            raise HTTPException(429, "rate limit exceeded")
        try:
            created = orchestrator.create_session(body.tier, None)
        except SessionError as exc:
            raise HTTPException(503, exc.message) from exc
        now = clock()
        with lock:
            pending[created.session_id] = _Pending(
                nickname=body.nickname.strip() or "anon", mode=body.mode,
                tier=body.tier.value, round_index=1,
                family=created.round.challenge.family, issued_at=now, started_at=now)
            while len(pending) > MAX_PENDING:
                pending.popitem(last=False)
        return created.model_dump(mode="json")

    @router.post("/play/api/submit", include_in_schema=False)
    def submit(body: TrialSubmit) -> dict[str, Any]:
        arrival = clock()
        with lock:
            p = pending.get(body.session_id)
        if p is None:
            raise HTTPException(404, "unknown or finished trial session")
        expected = orchestrator.peek_expected_answer(body.session_id)
        untimed = answers_match(body.answer, expected) if expected is not None else None
        try:
            out = orchestrator.submit(body.session_id, body.round_index, body.nonce, body.answer)
        except VerifierError as exc:
            raise HTTPException(503, exc.message) from exc
        except SessionError as exc:
            raise HTTPException(404, exc.message) from exc

        budget_ms = orchestrator_round_budget(orchestrator, p.tier)
        outcome = "correct" if not isinstance(out, SessionFailedResponse) else out.failure.value
        log.append({
            "event": "round", "session_id": body.session_id, "nickname": p.nickname,
            "mode": p.mode, "tier": p.tier, "round_index": p.round_index, "family": p.family,
            "answer_ms": round((arrival - p.issued_at) * 1000, 1), "budget_ms": budget_ms,
            "outcome": outcome, "correct_if_untimed": untimed,
            "answer_chars": len(body.answer),
        })
        with lock:
            if isinstance(out, NextRoundResponse):
                p.rounds_done += 1
                p.round_index = out.round.round_index
                p.family = out.round.challenge.family
                p.issued_at = clock()
            else:
                pending.pop(body.session_id, None)
                log.append({
                    "event": "session", "session_id": body.session_id, "nickname": p.nickname,
                    "mode": p.mode, "tier": p.tier,
                    "status": "passed" if isinstance(out, SessionPassedResponse) else "failed",
                    "failure": None if isinstance(out, SessionPassedResponse) else out.failure.value,
                    "rounds_correct": p.rounds_done + (1 if outcome == "correct" else 0),
                    "total_ms": round((arrival - p.started_at) * 1000, 1),
                })
        return out.model_dump(mode="json")

    @router.get("/play/api/stats", include_in_schema=False)
    def stats() -> dict[str, Any]:
        return log.stats()

    return router


def orchestrator_round_budget(orchestrator: Orchestrator, tier: str) -> int:
    from poac.sessions.config import TIERS

    return TIERS[CapabilityTier(tier)].round_deadline_ms
