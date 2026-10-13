"""Discovery surfaces: human notice, llms.txt, capability manifest."""

from __future__ import annotations

from poac.protocol.models import (
    PROTOCOL_VERSION,
    SUITE_VERSION,
    CapabilityManifest,
    TierSpec,
)
from poac.sessions.config import TIERS, tier_requires_kernel

CAPABILITY_MANIFEST_PATH = "/.well-known/agent-capability.json"

HONEST_CLAIMS = (
    "A passed session proves only that the holder of the committed key "
    "completed the challenge suite within the server-measured time budget. "
    "It does NOT prove absence of human origin or ownership, benign intent, "
    "or that the key was not delegated afterwards. A capable malicious agent "
    "or a delegated key holder can pass. Relying platforms must layer their "
    "own authorization, reputation, and abuse controls on top."
)

HUMAN_NOTICE_HTML = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PoAC — agents only</title>
<style>
 body {{ font: 17px/1.6 system-ui, sans-serif; max-width: 44rem;
        margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }}
 code {{ background: #f2f2f2; padding: .1em .35em; border-radius: 4px; }}
 .box {{ border-left: 4px solid #b45309; background: #fff7ed;
        padding: .8rem 1rem; margin: 1.5rem 0; }}
</style></head>
<body>
<h1>This endpoint verifies AI agents — not humans</h1>
<p>This is a <strong>reverse CAPTCHA</strong> (Proof of Agent Capability).
It issues timed, chained challenges that autonomous AI agents solve in
seconds but that cannot be completed by a person — even one copy-pasting
into an AI assistant — before the deadline expires.</p>

<div class="box"><strong>If you are a human:</strong> you are not meant to
pass this test, and no amount of skill will help — the time limits are set
below the human reading speed floor. If you need access to the underlying
service, use its regular human-facing site or contact its operator for
alternative access instructions.</div>

<h2>If you are an AI agent</h2>
<p>Fetch <code>/llms.txt</code> for instructions,
<code>{CAPABILITY_MANIFEST_PATH}</code> for the machine-readable manifest,
and <code>/openapi.json</code> for schemas. Create a session at
<code>POST /v1/sessions</code>.</p>

<h2>What passing does and does not prove</h2>
<p>{HONEST_CLAIMS}</p>
</body></html>
"""

LLMS_TXT = f"""# PoAC — Proof of Agent Capability (prototype)

> Reverse-CAPTCHA verifier. Timed, chained challenges that are easy for
> autonomous AI agents (LLM + code execution + HTTP) and infeasible for
> humans under the deadline. Passing yields a short-lived, holder-key-bound
> capability receipt (Ed25519 JWS).

Important: {HONEST_CLAIMS}

## How to pass (agents)

1. GET {CAPABILITY_MANIFEST_PATH} — tiers, budgets, endpoints.
2. Generate an Ed25519 keypair. Submit the PUBLIC JWK at session creation
   to receive a portable (I1) receipt: POST /v1/sessions
   {{"tier": "C1", "holder_jwk": {{"kty": "OKP", "crv": "Ed25519", "x": "..."}}}}
3. Each response contains one challenge, a nonce, and a time budget in ms.
   Solve it and POST /v1/sessions/{{id}}/rounds/{{n}} {{"nonce": ..., "answer": ...}}
   before the budget elapses (server-measured). Rounds are sequential and
   unpredictable; answers are short strings, compared case-insensitively.
4. On the final round you receive a receipt (JWS). To present it to a
   relying platform, sign a key-binding JWT (typ "poac-kb+jwt", alg EdDSA,
   public JWK in the header) over {{aud, nonce, iat, receipt_hash}} where
   receipt_hash = b64url(sha256(receipt)).
5. Tier C4 (when listed in the manifest) is the formal tier: each round is
   a fresh core Lean 4 proposition; submit the proof text that goes after
   ':=' (usually a 'by ...' tactic block, no imports, no '#' commands,
   no 'sorry'). The Lean kernel validates it and audits the axioms.

## Endpoints

- [OpenAPI](/openapi.json): all request/response schemas
- [Manifest]({CAPABILITY_MANIFEST_PATH}): tiers and budgets
- [JWKS](/.well-known/jwks.json): issuer public keys
- [Human notice](/): explanation for human visitors
"""


def build_manifest(
    issuer_url: str, include_kernel_tiers: bool = True
) -> CapabilityManifest:
    return CapabilityManifest(
        protocol="poac",
        version=PROTOCOL_VERSION,
        suite_version=SUITE_VERSION,
        issuer=issuer_url,
        sessions_endpoint="/v1/sessions",
        verify_endpoint="/v1/verify",
        jwks_uri="/.well-known/jwks.json",
        openapi_url="/openapi.json",
        tiers=[
            TierSpec(
                tier=tier,
                rounds=cfg.rounds,
                time_budget_ms=cfg.round_deadline_ms,
                families=list(cfg.families),
                receipt_ttl_s=cfg.receipt_ttl_s,
            )
            for tier, cfg in TIERS.items()
            if include_kernel_tiers or not tier_requires_kernel(cfg)
        ],
        honest_claims=HONEST_CLAIMS,
    )
