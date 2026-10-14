"""Agent-side client: earn a receipt, present it, verify one.

    from poac.client import PoacClient

    client = PoacClient("https://poac.42bytes.eu")          # fresh Ed25519 key
    receipt = client.earn("C1", solver=my_solver)           # solver(challenge) -> str
    kb_jwt = client.present(receipt, audience="https://rp.example", nonce=rp_nonce)

``solver`` receives a typed challenge (``poac.protocol.models.Challenge``:
NluChallenge, CodeChallenge, ... ProofChallenge) and returns the answer
string. The client handles key generation, the round loop, nonces and
deadlines; it never retries a round (one submission per round is the
protocol).

Relying parties use the same class the other way round::

    rp = PoacClient("https://poac.42bytes.eu")
    nonce = rp.verify_nonce()                 # hand to the agent
    result = rp.verify(receipt, kb_jwt, audience="https://rp.example", nonce=nonce)

Depends only on httpx, joserfc and pydantic (all already required by the
verifier package).
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx
from joserfc.jwk import OKPKey
from pydantic import TypeAdapter

from poac.credentials.presentation import create_kb_jwt
from poac.protocol.models import (
    Challenge,
    FailureClass,
    HolderJwk,
    NextRoundResponse,
    RoundChallenge,
    SessionCreatedResponse,
    SessionFailedResponse,
    SessionPassedResponse,
)

Solver = Callable[[Challenge], str]

_CHALLENGE = TypeAdapter(Challenge)
_OUTCOME = TypeAdapter(NextRoundResponse | SessionPassedResponse | SessionFailedResponse)


class PoacError(Exception):
    """Transport or protocol error (non-2xx, malformed response)."""


class SessionFailed(PoacError):
    def __init__(self, failure: FailureClass, round_index: int, families: list[str]):
        super().__init__(f"session failed at round {round_index}: {failure.value}")
        self.failure = failure
        self.round_index = round_index
        self.families = families


class HolderKey:
    """Ed25519 holder key. Receipts are bound to its thumbprint (``cnf.jkt``)."""

    def __init__(self, key: OKPKey):
        self._key = key

    @classmethod
    def generate(cls) -> HolderKey:
        return cls(OKPKey.generate_key("Ed25519"))

    @classmethod
    def load(cls, path: str | Path) -> HolderKey:
        return cls(OKPKey.import_key(json.loads(Path(path).read_text())))

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.write_text(json.dumps(self._key.as_dict(private=True)))
        p.chmod(0o600)

    @property
    def jwk(self) -> HolderJwk:
        d = self._key.as_dict(private=False)
        return HolderJwk(kty="OKP", crv="Ed25519", x=d["x"])

    @property
    def thumbprint(self) -> str:
        return self._key.thumbprint()

    @property
    def joserfc_key(self) -> OKPKey:
        return self._key


@dataclass(frozen=True)
class Receipt:
    token: str  # compact JWS, pass this around
    tier: str
    identity_tier: str
    families: list[str]
    latency_ms: list[int]
    session_id: str
    claims: dict[str, Any] = field(repr=False)  # decoded, NOT verified — informational

    @property
    def expires_at(self) -> int:
        return int(self.claims["exp"])

    @property
    def issuer(self) -> str:
        return str(self.claims["iss"])

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at


def _unverified_claims(jws: str) -> dict[str, Any]:
    payload = jws.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def kb_nonce(kb_jwt: str) -> str | None:
    """Nonce claim of a key-binding JWT, read without verification (the
    verifier re-checks it). None if the token is malformed."""
    try:
        return _unverified_claims(kb_jwt).get("nonce")
    except Exception:  # noqa: BLE001 - malformed token is the caller's 401, not a 500
        return None


def kb_nonce(kb_jwt: str) -> str | None:
    """Nonce claim of a key-binding JWT, read without verification (the
    verifier re-checks it). None if the token is malformed."""
    try:
        return _unverified_claims(kb_jwt).get("nonce")
    except Exception:  # noqa: BLE001 - malformed token is the caller's 401, not a 500
        return None


class PoacClient:
    def __init__(
        self,
        base_url: str,
        key: HolderKey | None = None,
        http: httpx.Client | None = None,
        timeout: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.key = key or HolderKey.generate()
        self._http = http or httpx.Client(base_url=self.base_url, timeout=timeout)
        self._owns_http = http is None

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> PoacClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- discovery ---------------------------------------------------------------

    def manifest(self) -> dict[str, Any]:
        return self._get("/.well-known/agent-capability.json")

    def tiers(self) -> list[str]:
        return [t["tier"] for t in self.manifest()["tiers"]]

    # --- earning -------------------------------------------------------------------

    def start(self, tier: str, bind_key: bool = True) -> SessionCreatedResponse:
        body: dict[str, Any] = {"tier": tier}
        if bind_key:
            body["holder_jwk"] = self.key.jwk.model_dump(exclude_none=True)
        r = self._http.post("/v1/sessions", json=body)
        if r.status_code != 201:
            raise PoacError(f"POST /v1/sessions -> {r.status_code}: {r.text[:300]}")
        return SessionCreatedResponse.model_validate(r.json())

    def submit(self, session_id: str, rnd: RoundChallenge, answer: str):
        r = self._http.post(
            f"/v1/sessions/{session_id}/rounds/{rnd.round_index}",
            json={"nonce": rnd.nonce, "answer": answer},
        )
        if r.status_code != 200:
            raise PoacError(f"submit round {rnd.round_index} -> {r.status_code}: {r.text[:300]}")
        return _OUTCOME.validate_python(r.json())

    def earn(
        self,
        tier: str,
        solver: Solver,
        bind_key: bool = True,
        on_round: Callable[[RoundChallenge, str, float], None] | None = None,
    ) -> Receipt:
        """Play a full session. ``on_round(round, answer, solve_seconds)`` is
        called after each submission (for logging/benchmarks)."""
        created = self.start(tier, bind_key=bind_key)
        rnd = created.round
        families: list[str] = []
        while True:
            families.append(rnd.challenge.family)
            t0 = time.perf_counter()
            answer = solver(rnd.challenge)
            dt = time.perf_counter() - t0
            outcome = self.submit(created.session_id, rnd, answer)
            if on_round:
                on_round(rnd, answer, dt)
            if isinstance(outcome, NextRoundResponse):
                rnd = outcome.round
                continue
            if isinstance(outcome, SessionFailedResponse):
                raise SessionFailed(outcome.failure, outcome.round_index, families)
            return Receipt(
                token=outcome.receipt,
                tier=outcome.capability_tier.value,
                identity_tier=outcome.identity_tier.value,
                families=[f for f in outcome.families],
                latency_ms=list(outcome.latency_ms),
                session_id=outcome.session_id,
                claims=_unverified_claims(outcome.receipt),
            )

    # --- presenting ----------------------------------------------------------------

    def present(self, receipt: Receipt | str, audience: str, nonce: str) -> str:
        """Key-binding JWT proving possession of the receipt's holder key.
        ``nonce`` must come from the relying party (which got it from the
        verifier's ``GET /v1/verify/nonce``)."""
        token = receipt.token if isinstance(receipt, Receipt) else receipt
        return create_kb_jwt(self.key.joserfc_key, token, audience, nonce)

    # --- verifying (relying-party side) ------------------------------------------

    def verify_nonce(self) -> str:
        return str(self._get("/v1/verify/nonce")["nonce"])

    def verify(self, receipt: Receipt | str, kb_jwt: str, audience: str, nonce: str) -> dict[str, Any]:
        token = receipt.token if isinstance(receipt, Receipt) else receipt
        r = self._http.post(
            "/v1/verify",
            json={"receipt": token, "kb_jwt": kb_jwt, "audience": audience, "nonce": nonce},
        )
        if r.status_code != 200:
            raise PoacError(f"POST /v1/verify -> {r.status_code}: {r.text[:300]}")
        return r.json()

    # --- internals -------------------------------------------------------------------

    def _get(self, path: str) -> dict[str, Any]:
        r = self._http.get(path)
        if r.status_code != 200:
            raise PoacError(f"GET {path} -> {r.status_code}: {r.text[:300]}")
        return r.json()
