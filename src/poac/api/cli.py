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
    from poac.trials.log import TrialLog

    from poac.credentials.keyring import load_previous_keys

    issuer = None
    kms_key = args.kms_key
    # public keys retired by `poac-keys`, published until their retire_at
    previous = load_previous_keys(args.previous_keys_file) if args.previous_keys_file else []
    if kms_key:
        # Private key lives in AWS KMS. If a local key file also exists, its
        # public half stays in the JWKS so receipts issued before the switch
        # keep verifying until they expire (5 min); the private part is no
        # longer used for anything.
        from poac.credentials.signer import KmsMlDsaSigner, KmsSigner

        region = os.environ.get("POAC_KMS_REGION")
        if args.issuer_key_file and Path(args.issuer_key_file).exists():
            previous.append(_load_or_create_issuer_key(Path(args.issuer_key_file)).as_dict(private=False))
        signer = KmsSigner(kms_key, region=region)
        pq = KmsMlDsaSigner(args.kms_pq_key, region=region) if args.kms_pq_key else None
        issuer = ReceiptIssuer(signer, issuer_url=args.base_url, previous_keys=previous, pq_signer=pq)
        print(f"issuer key: AWS KMS {kms_key} (kid {signer.kid})"
              + (f"; PQ key: AWS KMS {args.kms_pq_key} (kid {pq.kid}); json-dual receipts offered" if pq else "")
              + (f"; publishing {len(previous)} previous key(s)" if previous else ""), file=sys.stderr)
    elif args.issuer_key_file:
        if args.kms_pq_key:
            sys.exit("--kms-pq-key requires --kms-key (the Ed25519 key must be in KMS too)")
        issuer = ReceiptIssuer(
            _load_or_create_issuer_key(Path(args.issuer_key_file)),
            issuer_url=args.base_url,
            previous_keys=previous,
        )
        if previous:
            print(f"publishing {len(previous)} previous key(s) from {args.previous_keys_file}", file=sys.stderr)

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
                kernel_slots=args.kernel_slots,
                max_kernel_sessions=args.max_kernel_sessions,
            )
            issuer = orchestrator._issuer
    else:
        if secret is None:
            sys.exit("--state-db requires POAC_SERVER_SECRET so replicas agree on the HMAC chain")
        if issuer is None:
            sys.exit("--state-db requires --issuer-key-file or --kms-key so replicas agree on receipts")
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
            kernel_slots=args.kernel_slots,
            max_kernel_sessions=args.max_kernel_sessions,
        )
        nonce_store = SqliteNonceStore(args.state_db)

    return create_app(
        issuer=issuer,
        orchestrator=orchestrator,
        base_url=args.base_url,
        nonce_store=nonce_store,
        trial_log=TrialLog(args.trials_log),
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
    parser.add_argument(
        "--kms-key",
        default=os.environ.get("POAC_KMS_ED25519_KEY"),
        help="AWS KMS Ed25519 key ARN/alias to sign receipts with (needs poac[kms] and "
             "AWS credentials; POAC_KMS_REGION). The local key file, if any, becomes a "
             "previous key in the JWKS.",
    )
    parser.add_argument(
        "--kernel-slots", type=int, default=int(os.environ.get("POAC_KERNEL_SLOTS", "2")),
        help="max concurrent Lean kernel checks (each a process of up to POAC_LEAN_MAX_MEMORY_MB); "
             "use 1 on 1 GB nodes",
    )
    parser.add_argument(
        "--max-kernel-sessions", type=int, default=int(os.environ.get("POAC_MAX_KERNEL_SESSIONS", "8")),
        help="max simultaneously active C4/C5 sessions; beyond it session creation answers 503",
    )
    parser.add_argument(
        "--previous-keys-file",
        default=os.environ.get("POAC_PREVIOUS_KEYS_FILE"),
        help="JSON written by `poac-keys` (rotate-local / retire-kms): public keys to keep "
             "publishing in the JWKS until their retire_at. Missing file = none.",
    )
    parser.add_argument(
        "--kms-pq-key",
        default=os.environ.get("POAC_KMS_MLDSA65_KEY"),
        help="AWS KMS ML-DSA-65 key ARN/alias; enables dual-signed (Ed25519 + ML-DSA-65) "
             "receipts on request (receipt_format=json-dual). Requires --kms-key.",
    )
    parser.add_argument(
        "--trials-log",
        default=os.environ.get("POAC_TRIALS_LOG"),
        help="JSONL file for /play human-trial telemetry (default: memory only)",
    )
    parser.add_argument(
        "--trust-proxy-headers", action="store_true",
        default=os.environ.get("POAC_TRUST_PROXY_HEADERS", "0") == "1",
        help="use X-Forwarded-For as the client address (only when the verifier is reachable "
             "solely through the reverse proxy; otherwise clients could spoof it)",
    )
    args = parser.parse_args(argv)

    import uvicorn

    app = build_app(args)
    if args.trust_proxy_headers:
        from poac.api.app import with_proxy_headers

        app = with_proxy_headers(app)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
