"""`poac-verifier` console entry point.

Single replica (default): in-memory state, fresh issuer key and server
secret per process.

Multiple replicas: pass ``--state-db`` (shared SQLite file for sessions and
verify nonces), ``--issuer-key-file`` (shared Ed25519 JWK; created on first
run) and ``POAC_SERVER_SECRET`` (hex, >= 32 bytes). With a shared store the
orchestrator uses wall-clock time so timestamps compare across hosts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def _load_or_create_issuer_key(path: Path):
    from joserfc.jwk import OKPKey

    if path.exists():
        return OKPKey.import_key(json.loads(path.read_text()))
    key = OKPKey.generate_key("Ed25519", {"alg": "Ed25519", "use": "sig"})
    path.write_text(json.dumps(key.as_dict(private=True)))
    path.chmod(0o600)
    print(f"generated issuer key -> {path}", file=sys.stderr)
    return key


def build_app(args: argparse.Namespace):
    from poac.api.app import create_app
    from poac.credentials.issuer import ReceiptIssuer
    from poac.sessions.orchestrator import Orchestrator

    issuer = None
    if args.issuer_key_file:
        issuer = ReceiptIssuer(
            _load_or_create_issuer_key(Path(args.issuer_key_file)),
            issuer_url=args.base_url,
        )

    secret_hex = os.environ.get("POAC_SERVER_SECRET")
    secret = bytes.fromhex(secret_hex) if secret_hex else None
    if secret is not None and len(secret) < 32:
        sys.exit("POAC_SERVER_SECRET must be at least 32 bytes (64 hex chars)")

    source = None
    if args.corpus_db:
        from poac.corpus.source import CorpusSource
        from poac.corpus.store import CorpusStore

        source = CorpusSource(CorpusStore(args.corpus_db))

    if not args.state_db:
        orchestrator = None
        nonce_store = None
        if issuer or secret or source:
            from poac.challenges.proof_check import find_lean

            orchestrator = Orchestrator(
                issuer or ReceiptIssuer.generate(issuer_url=args.base_url),
                server_secret=secret,
                lean_bin=find_lean(),
                source=source,
            )
            issuer = orchestrator._issuer
    else:
        if secret is None:
            sys.exit("--state-db requires POAC_SERVER_SECRET so replicas agree on the HMAC chain")
        if issuer is None:
            sys.exit("--state-db requires --issuer-key-file so replicas agree on receipts")
        from poac.api.nonces import SqliteNonceStore
        from poac.challenges.proof_check import find_lean
        from poac.sessions.store import SqliteSessionStore

        orchestrator = Orchestrator(
            issuer,
            server_secret=secret,
            clock=time.time,
            lean_bin=find_lean(),
            store=SqliteSessionStore(args.state_db),
            source=source,
        )
        nonce_store = SqliteNonceStore(args.state_db)

    return create_app(
        issuer=issuer,
        orchestrator=orchestrator,
        base_url=args.base_url,
        nonce_store=nonce_store,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="poac-verifier",
        description="Run the PoAC reverse-CAPTCHA verifier.",
    )
    parser.add_argument("--host", default=os.environ.get("POAC_HOST", "0.0.0.0"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("POAC_PORT", "8000"))
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("POAC_BASE_URL", "http://localhost:8000"),
        help="public URL used as the receipt issuer identifier",
    )
    parser.add_argument(
        "--state-db",
        default=os.environ.get("POAC_STATE_DB"),
        help="SQLite file shared by replicas for sessions + verify nonces",
    )
    parser.add_argument(
        "--issuer-key-file",
        default=os.environ.get("POAC_ISSUER_KEY_FILE"),
        help="Ed25519 private JWK (JSON); created if missing",
    )
    parser.add_argument(
        "--corpus-db",
        default=os.environ.get("POAC_CORPUS_DB"),
        help="private challenge corpus (SQLite); templates are the fallback",
    )
    args = parser.parse_args(argv)

    import uvicorn

    uvicorn.run(build_app(args), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
