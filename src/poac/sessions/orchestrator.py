"""Round orchestration: one-time sessions, HMAC-chained rounds, server timing.

Security properties enforced here (see docs/threat-model.md):

- round *n+1*'s family and instance derive from an HMAC over the server
  secret, session id, round index, and the hash of the *verified* previous
  answer — rounds cannot be precomputed or solved in parallel;
- deadlines use the server clock only (monotonic by default; wall-clock
  when replicas share a persistent store);
- any protocol violation (wrong round, wrong nonce, resubmission, expiry)
  permanently fails the session;
- failures reveal a failure class, never the expected answer.

State lives behind a ``SessionStore``; every public operation runs inside
one store transaction, which is the process lock for the in-memory store and
a database-level lock for shared stores.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Callable

from poac.challenges.base import answers_match
from poac.challenges.proof_check import check_proof
from poac.challenges.source import ChallengeSource, TemplateSource
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.signer import SignerError
from poac.protocol.models import (
    MAX_ANSWER_CHARS,
    CapabilityTier,
    FailureClass,
    HolderJwk,
    NextRoundResponse,
    ProofChallenge,
    RoundChallenge,
    SessionCreatedResponse,
    SessionFailedResponse,
    SessionPassedResponse,
)
from poac.sessions.config import TIERS, tier_requires_kernel
from poac.sessions.state import RoundState, Session
from poac.sessions.store import InMemorySessionStore, SessionStore


class SessionError(Exception):
    """Protocol violation surfaced as HTTP 4xx by the API layer."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class VerifierError(SessionError):
    """The verifier itself failed (e.g. the Lean toolchain crashed).

    Surfaced as HTTP 503. The affected session is voided — the prover did
    nothing wrong, but the round can no longer be judged, and leaving it
    half-validated would wedge the session until the sweeper reaps it.
    """


class Orchestrator:
    def __init__(
        self,
        issuer: ReceiptIssuer,
        server_secret: bytes | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_sessions: int = 10_000,
        lean_bin: str | None = None,
        store: SessionStore | None = None,
        source: ChallengeSource | None = None,
    ):
        self._issuer = issuer
        self._secret = server_secret or secrets.token_bytes(32)
        self._clock = clock
        self._store: SessionStore = store or InMemorySessionStore()
        self._source: ChallengeSource = source or TemplateSource()
        self._max_sessions = max_sessions
        self._lean_bin = lean_bin

    @property
    def lean_bin(self) -> str | None:
        return self._lean_bin

    @property
    def store(self) -> SessionStore:
        return self._store

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    def peek_expected_answer(self, session_id: str) -> str | None:
        """Research hook for the human-trial game: the current round's
        expected answer, so a late or wrong submission can still be scored
        "would have been right". Never exposed over the API; None for
        kernel-validated rounds and unknown sessions."""
        session = self._store.get(session_id)
        state = session.round_state if session else None
        if state is None or isinstance(state.payload, ProofChallenge):
            return None
        return state.expected_answer

    # --- internals ---------------------------------------------------------

    def _round_seed(self, session: Session, round_index: int) -> bytes:
        msg = b"|".join(
            [
                session.session_id.encode(),
                str(round_index).encode(),
                session.prev_answer_hash,
            ]
        )
        return hmac.new(self._secret, msg, hashlib.sha256).digest()

    def _pick_family(self, session: Session, seed: bytes) -> str:
        allowed = list(session.config.families)
        # prefer families not used yet so C2+ always mixes families
        unused = [f for f in allowed if f not in session.families]
        pool = unused or allowed
        return pool[seed[0] % len(pool)]

    def _issue_round(self, session: Session) -> RoundChallenge:
        round_index = session.current_round + 1
        seed = self._round_seed(session, round_index)
        family = self._pick_family(session, seed)
        generated = self._source.draw(family, seed, session.config.difficulty)

        session.current_round = round_index
        session.families.append(family)
        session.round_state = RoundState(
            family=family,
            expected_answer=generated.answer,
            nonce=secrets.token_urlsafe(24),
            issued_at=self._clock(),
            chain_material=generated.chain_material or generated.answer,
            payload=generated.payload,
        )
        return RoundChallenge(
            session_id=session.session_id,
            round_index=round_index,
            rounds_total=session.config.rounds,
            challenge=generated.payload,
            nonce=session.round_state.nonce,
            time_budget_ms=session.config.round_deadline_ms,
            answer_format=generated.answer_format,
        )

    def _fail(self, session: Session, failure: FailureClass) -> SessionFailedResponse:
        session.status = "failed"
        session.round_state = None
        self._store.put(session)
        return SessionFailedResponse(
            status="failed",
            session_id=session.session_id,
            failure=failure,
            round_index=session.current_round,
        )

    # --- public API --------------------------------------------------------

    def create_session(
        self,
        tier: CapabilityTier,
        holder_jwk: HolderJwk | None,
        receipt_format: str = "compact",
    ) -> SessionCreatedResponse:
        if receipt_format not in self._issuer.receipt_formats:
            raise SessionError(
                f"receipt format {receipt_format!r} unavailable here; offered: "
                + ", ".join(self._issuer.receipt_formats)
            )
        if tier_requires_kernel(TIERS[tier]) and self._lean_bin is None:
            raise SessionError(
                f"tier {tier.value} unavailable: this verifier has no Lean toolchain"
            )
        with self._store.transaction():
            self._store.sweep(self._clock())
            if self._store.count() >= self._max_sessions:
                raise SessionError("session capacity exceeded, retry later")
            session = Session(
                session_id=secrets.token_urlsafe(18),
                tier=tier,
                config=TIERS[tier],
                holder_jwk=holder_jwk,
                created_at=self._clock(),
                receipt_format=receipt_format,
            )
            first_round = self._issue_round(session)
            self._store.put(session)
        return SessionCreatedResponse(
            session_id=session.session_id,
            tier=tier,
            identity_tier=session.identity_tier,
            suite_version="2026.09-proto",
            round=first_round,
        )

    def submit(
        self, session_id: str, round_index: int, nonce: str, answer: str
    ) -> NextRoundResponse | SessionPassedResponse | SessionFailedResponse:
        """Validate a round submission.

        Protocol and timing checks run inside the store transaction; the
        (potentially slow) Lean kernel check for proof rounds runs *outside*
        it so concurrent sessions are not serialized behind subprocess calls.
        The round is marked `validating` in between, so a concurrent
        resubmission cannot race the check.
        """
        with self._store.transaction():
            session = self._store.get(session_id)
            if session is None:
                raise SessionError("unknown session")
            if session.status != "active" or session.round_state is None:
                raise SessionError("session is no longer active")
            state = session.round_state
            if state.validating:
                raise SessionError("a submission for this round is being validated")

            now = self._clock()
            # session-level expiry
            if now - session.created_at > session.config.session_deadline_ms / 1000:
                return self._fail(session, FailureClass.expired)
            # protocol violations: wrong round, wrong nonce
            if round_index != session.current_round or not hmac.compare_digest(
                nonce, state.nonce
            ):
                return self._fail(session, FailureClass.protocol_violation)
            # per-round deadline (server clock, stamped at arrival —
            # server-side validation time never counts against the prover)
            elapsed_ms = (now - state.issued_at) * 1000
            if elapsed_ms > session.config.round_deadline_ms:
                return self._fail(session, FailureClass.timeout)

            kernel_round = isinstance(state.payload, ProofChallenge)
            if kernel_round:
                state.validating = True
                self._store.put(session)
            else:
                # short-answer families keep the tighter length bound
                correct = len(answer) <= MAX_ANSWER_CHARS and answers_match(
                    answer, state.expected_answer
                )
                return self._finalize(session, state, elapsed_ms, correct)

        # --- kernel validation, outside the transaction ---
        try:
            result = check_proof(
                self._lean_bin,
                preamble=state.payload.preamble,
                proposition=state.payload.proposition,
                submission=answer,
            )
        except Exception as exc:  # toolchain missing/crashed, OS error, ...
            with self._store.transaction():
                session = self._store.get(session_id)
                if session is not None and session.round_state is not None:
                    session.status = "failed"
                    session.round_state = None
                    self._store.put(session)
            raise VerifierError(
                f"kernel check unavailable ({exc.__class__.__name__}); session voided"
            ) from exc

        with self._store.transaction():
            session = self._store.get(session_id)
            if session is None:
                raise SessionError("session expired during validation")
            state = session.round_state
            if session.status != "active" or state is None or not state.validating:
                raise SessionError("session is no longer active")
            state.validating = False
            return self._finalize(session, state, elapsed_ms, result.ok)

    def _finalize(
        self,
        session: Session,
        state: RoundState,
        elapsed_ms: float,
        correct: bool,
    ) -> NextRoundResponse | SessionPassedResponse | SessionFailedResponse:
        """Runs inside a store transaction."""
        if not correct:
            return self._fail(session, FailureClass.wrong_answer)

        session.latencies_ms.append(int(elapsed_ms))
        session.prev_answer_hash = hashlib.sha256(
            state.chain_material.encode()
        ).digest()
        session.round_state = None

        if session.current_round < session.config.rounds:
            nxt = self._issue_round(session)
            self._store.put(session)
            return NextRoundResponse(status="next", round=nxt)

        session.status = "passed"
        self._store.put(session)
        try:
            receipt = self._issuer.issue(
                session_id=session.session_id,
                capability_tier=session.tier,
                identity_tier=session.identity_tier,
                families=session.families,
                latencies_ms=session.latencies_ms,
                rounds_total=session.config.rounds,
                receipt_ttl_s=session.config.receipt_ttl_s,
                holder_jwk=session.holder_jwk,
                receipt_format=session.receipt_format,  # type: ignore[arg-type]
            )
        except SignerError as exc:
            # The prover passed; the signing backend (e.g. KMS) is down. No
            # receipt can be issued, and the session cannot be replayed to
            # get one later — surface 503 rather than inventing a token.
            raise VerifierError(f"receipt signing unavailable ({exc}); session passed but unissued") from exc
        return SessionPassedResponse(
            status="passed",
            session_id=session.session_id,
            capability_tier=session.tier,
            identity_tier=session.identity_tier,
            families=list(session.families),
            latency_ms=list(session.latencies_ms),
            receipt=receipt,
        )
