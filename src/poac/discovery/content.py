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
 .tally {{ color: #555; font-size: .95em; margin-top: -.5rem; }}
 .tally strong {{ color: #1a1a1a; font-variant-numeric: tabular-nums; }}
</style></head>
<body>
<h1>This endpoint verifies AI agents — not humans</h1>
<p class="tally" id="tally" hidden>
  <strong id="tallyN">0</strong> receipts issued to agents so far
  (<span id="tallyS">0</span> sessions attempted).</p>
<p>This is a <strong>reverse CAPTCHA</strong> (Proof of Agent Capability).
It issues timed, chained challenges that autonomous AI agents solve in
seconds but that cannot be completed by a person — even one copy-pasting
into an AI assistant — before the deadline expires.</p>

<div class="box"><strong>If you are a human:</strong> you are not meant to
pass this test, and no amount of skill will help — the time limits are set
below the human reading speed floor. If you need access to the underlying
service, use its regular human-facing site or contact its operator for
alternative access instructions.</div>

<p><strong>Curious how you'd do?</strong> <a href="/play">Play the trial game</a>
— same puzzles, same clock. Your times help us measure the human floor
(anonymous; late answers welcome).</p>

<h2>If you are an AI agent</h2>
<p>Fetch <code>/llms.txt</code> for instructions,
<code>{CAPABILITY_MANIFEST_PATH}</code> for the machine-readable manifest,
and <code>/openapi.json</code> for schemas. Create a session at
<code>POST /v1/sessions</code>.</p>

<h2>What passing does and does not prove</h2>
<p>{HONEST_CLAIMS}</p>
<script>
fetch('/v1/stats').then(r => r.json()).then(s => {{
  document.getElementById('tallyN').textContent = s.receipts_issued.toLocaleString();
  document.getElementById('tallyS').textContent = s.sessions_started.toLocaleString();
  document.getElementById('tally').hidden = false;
}}).catch(() => {{}});
</script>
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
   relying platform, first GET /v1/verify/nonce (one-shot, expires in ~120 s),
   then sign a key-binding JWT (typ "poac-kb+jwt", alg Ed25519, public JWK in
   the header) over {{aud, nonce, iat, receipt_hash}} where
   receipt_hash = b64url(sha256(receipt)), and POST /v1/verify
   {{receipt, kb_jwt, audience, nonce}}. Presenter-chosen nonces are rejected.
5. Tier C4 (when listed in the manifest) is the formal tier: each round is
   a fresh core Lean 4 proposition; submit the proof text that goes after
   ':=' (usually a 'by ...' tactic block, no imports, no '#' commands,
   no 'sorry'). The Lean kernel validates it and audits the axioms.
   Tier C5 (when listed) is the full-spectrum tier: six rounds, one per
   family including one Lean proof, 30 s each at C3 difficulty.

## Endpoints

- [OpenAPI](/openapi.json): all request/response schemas
- [Manifest]({CAPABILITY_MANIFEST_PATH}): tiers and budgets
- [Agent Card](/.well-known/agent-card.json): A2A-style discovery record
- [Skill](/skill.md): loadable SKILL.md with the exact steps and per-family answering tips
- [JWKS](/.well-known/jwks.json): issuer public keys
- [Stats](/v1/stats): lifetime counters — receipts issued (total, per tier), sessions started
- [Human notice](/): explanation for human visitors
"""


AGENT_CARD_PATH = "/.well-known/agent-card.json"
SKILL_PATH = "/skill.md"


def build_agent_card(issuer_url: str, include_kernel_tiers: bool = True) -> dict:
    """A2A-style Agent Card so A2A-aware agents discover PoAC the way they
    discover any other agent. PoAC is not an A2A agent (it speaks plain
    HTTP+JSON), so `preferredTransport` says so and `url` is the OpenAPI
    root; the skills list mirrors the tiers."""
    tiers = [
        t for t, cfg in TIERS.items() if include_kernel_tiers or not tier_requires_kernel(cfg)
    ]
    return {
        "name": "PoAC — Proof of Agent Capability",
        "description": (
            "Reverse-CAPTCHA verifier: timed, chained challenges that capable "
            "autonomous agents pass and humans cannot. Issues short-lived, "
            "holder-key-bound Ed25519 receipts (JWS) that relying platforms "
            "verify with one call."
        ),
        "url": issuer_url,
        "preferredTransport": "HTTP+JSON",
        "version": PROTOCOL_VERSION,
        "protocolVersion": "0.3",
        "documentationUrl": f"{issuer_url}/llms.txt",
        "provider": {"organization": "PoAC project", "url": issuer_url},
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "securitySchemes": {
            "poacReceipt": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "PoAC receipt (JWS) + key-binding JWT; see /llms.txt §4",
            }
        },
        "skills": [
            {
                "id": f"poac-{t.value.lower()}",
                "name": f"Earn a {t.value} capability receipt",
                "description": (
                    f"{TIERS[t].rounds} round(s), {TIERS[t].round_deadline_ms // 1000} s each, "
                    f"families: {', '.join(TIERS[t].families)}"
                ),
                "tags": ["capability", "verification", t.value.lower()],
                "examples": [f'POST {issuer_url}/v1/sessions {{"tier": "{t.value}"}}'],
            }
            for t in tiers
        ],
        "x-poac": {
            "manifest": f"{issuer_url}{CAPABILITY_MANIFEST_PATH}",
            "skill_md": f"{issuer_url}{SKILL_PATH}",
            "jwks": f"{issuer_url}/.well-known/jwks.json",
        },
    }


SKILL_MD = f"""---
name: pass-poac
description: Earn and present a PoAC (Proof of Agent Capability) receipt. Use when a site or API says it requires PoAC, returns 401/403 mentioning PoAC, or links to /.well-known/agent-capability.json.
---

# Pass a PoAC capability check

PoAC is a reverse CAPTCHA: solve a few timed challenges, get a signed
receipt bound to your key, present it to the platform that asked. Nothing
here needs a browser. Deadlines are measured by the server; do not stall
between rounds — read the challenge, answer, submit, repeat.

## Fastest path (Python)

```python
pip install poac            # or: pip install git+<repo>
from poac.client import PoacClient
agent = PoacClient("{{verifier_url}}")          # keep agent.key; save with agent.key.save(path)
receipt = agent.earn("C1", solver=answer)       # answer(challenge) -> str, see below
kb_jwt = agent.present(receipt, audience=platform_url, nonce=platform_nonce)
```

Send `receipt.token` and `kb_jwt` to the platform the way it asks (header
`Authorization: PoAC <receipt>` + `PoAC-KB: <kb_jwt>`, or its own form).
If the platform demands a post-quantum signature, earn with
`receipt_format="json-dual"` (offered when the manifest's `receipt_formats`
lists it): the receipt is then signed with Ed25519 and ML-DSA-65.

## Raw HTTP (any language)

1. `GET {{verifier_url}}{CAPABILITY_MANIFEST_PATH}` — tiers, budgets, endpoints.
2. `POST /v1/sessions` `{{"tier": "C1", "holder_jwk": {{"kty":"OKP","crv":"Ed25519","x":"..."}}}}`
   → `session_id`, round 1 (`challenge`, `nonce`, `time_budget_ms`).
3. For each round: `POST /v1/sessions/{{session_id}}/rounds/{{round_index}}`
   `{{"nonce": ..., "answer": ...}}` within the budget. `status: next` → go
   on; `status: passed` → `receipt`; `status: failed` → start a new session.
4. To present: ask the platform for its nonce (it fetched
   `GET /v1/verify/nonce`), sign a JWT with your Ed25519 key, header
   `{{"alg":"Ed25519","typ":"poac-kb+jwt","jwk":<public jwk>}}`, claims
   `{{"aud": platform_url, "nonce": nonce, "iat": now, "receipt_hash": b64url(sha256(receipt))}}`.

## Answering challenges

Each challenge has `family` and an `answer_format` hint. Return only the
answer, no explanation.

- `nlu`: read the whole narrative; the question names exact conditions; answer with the single entity name.
- `logic`: parse every constraint, solve the ordering, answer with the name only.
- `data`: filter `rows` by ALL stated conditions (ignore the stated distractors), compute the metric, answer with the integer.
- `code`: predict the program's printed output exactly.
- `diagram`: the SVG is a weighted graph; compute the cheapest path weight between the named nodes.
- `proof` (C4/C5): return only the Lean 4 text after `:=`, usually a `by` block. Core Lean only, no imports, no `#` commands, no `sorry`. `omega` closes linear arithmetic; recurrences need `induction n with | zero => rfl | succ k ih => simp only [defs]; omega`.

## Expectations

- One submission per round; a wrong answer or a late answer ends the session. Starting over is fine.
- Receipts expire (`exp`); earn a new one rather than caching for long.
- A receipt proves capability of the key holder under a deadline, nothing about intent. Platforms may add their own rules.
"""


def build_manifest(
    issuer_url: str,
    include_kernel_tiers: bool = True,
    receipt_formats: list[str] | None = None,
) -> CapabilityManifest:
    return CapabilityManifest(
        receipt_formats=receipt_formats or ["compact"],
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
