"""``poac-keys`` — issuer key rotation.

    poac-keys rotate-local --issuer-key-file /data/issuer.jwk \
                           --previous-keys-file /data/previous-keys.json [--retire-after 24h]
        Generate a new Ed25519 issuer key into the key file; move the old
        public key into the previous-keys file with a retire_at. Restart the
        verifier afterwards.

    poac-keys retire-kms --key <old KMS key ARN/alias> \
                         --previous-keys-file /data/previous-keys.json [--retire-after 24h]
        Snapshot a KMS key's public half into the previous-keys file. Run
        this BEFORE pointing POAC_KMS_ED25519_KEY (or POAC_KMS_MLDSA65_KEY)
        at the new key and restarting. Works for Ed25519 and ML-DSA-65 keys.

    poac-keys show --previous-keys-file /data/previous-keys.json
        List previous keys with their retire_at and status.

Both writers prune entries whose retire_at has already passed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from poac.credentials.keyring import load_previous_keys, save_previous_keys

_DUR = re.compile(r"^(\d+)([smhd])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86_400}


def parse_duration(text: str) -> int:
    m = _DUR.match(text.strip())
    if not m:
        raise ValueError(f"duration must look like 30m, 24h or 2d, got {text!r}")
    return int(m.group(1)) * _UNIT[m.group(2)]


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _merge(existing: list[dict[str, Any]], new: dict[str, Any], now: int) -> list[dict[str, Any]]:
    kept = [k for k in existing if k["retire_at"] > now and k["kid"] != new["kid"]]
    return [*kept, new]


def cmd_rotate_local(args: argparse.Namespace, now: int) -> int:
    from joserfc.jwk import OKPKey

    key_path, prev_path = Path(args.issuer_key_file), Path(args.previous_keys_file)
    if not key_path.exists():
        print(f"no key file at {key_path}; nothing to rotate (the verifier creates one on first start)",
              file=sys.stderr)
        return 1
    old = OKPKey.import_key(json.loads(key_path.read_text()))
    old_pub = old.as_dict(private=False)
    old_pub["kid"] = old.thumbprint()
    old_pub["retire_at"] = now + parse_duration(args.retire_after)

    new = OKPKey.generate_key("Ed25519", {"alg": "Ed25519", "use": "sig"})
    tmp = key_path.with_suffix(key_path.suffix + ".new")
    tmp.write_text(json.dumps(new.as_dict(private=True)))
    tmp.chmod(0o600)
    save_previous_keys(prev_path, _merge(load_previous_keys(prev_path), old_pub, now))
    os.replace(tmp, key_path)  # previous-keys written first, so a crash never loses the old kid
    print(f"rotated {key_path}: new kid {new.thumbprint()}\n"
          f"previous kid {old_pub['kid']} published until retire_at {_iso(old_pub['retire_at'])} "
          f"in {prev_path}\nrestart the verifier to pick up the new key.", file=sys.stderr)
    return 0


def cmd_retire_kms(args: argparse.Namespace, now: int, kms_client: Any | None) -> int:
    from poac.credentials.signer import KmsMlDsaSigner, KmsSigner, SignerError

    region = args.region or os.environ.get("POAC_KMS_REGION")
    if kms_client is None:
        try:
            import boto3
        except ImportError:
            print("boto3 required: pip install 'poac[kms]'", file=sys.stderr)
            return 1
        kms_client = boto3.client("kms", region_name=region)
    spec = kms_client.get_public_key(KeyId=args.key).get("KeySpec")
    cls = {"ECC_NIST_EDWARDS25519": KmsSigner, "ML_DSA_65": KmsMlDsaSigner}.get(spec)
    if cls is None:
        print(f"{args.key} is {spec}; only ECC_NIST_EDWARDS25519 / ML_DSA_65 issuer keys are supported",
              file=sys.stderr)
        return 1
    try:
        signer = cls(args.key, client=kms_client, region=region)
    except SignerError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    entry = signer.public_jwk()
    entry["retire_at"] = now + parse_duration(args.retire_after)
    prev_path = Path(args.previous_keys_file)
    save_previous_keys(prev_path, _merge(load_previous_keys(prev_path), entry, now))
    print(f"snapshotted {args.key} ({signer.alg}, kid {signer.kid}) into {prev_path}, "
          f"retire_at {_iso(entry['retire_at'])}.\n"
          f"now point the verifier at the NEW key (.env) and restart; this key keeps verifying "
          f"old receipts until retire_at.", file=sys.stderr)
    return 0


def cmd_show(args: argparse.Namespace, now: int) -> int:
    keys = load_previous_keys(args.previous_keys_file)
    if not keys:
        print("no previous keys")
        return 0
    for k in keys:
        status = "published" if k["retire_at"] > now else "RETIRED (dropped from JWKS)"
        print(f"{k['kid']}  {k['kty']}/{k.get('alg', '?')}  retire_at {_iso(k['retire_at'])}  {status}")
    return 0


def main(argv: list[str] | None = None, kms_client: Any | None = None) -> int:
    ap = argparse.ArgumentParser(prog="poac-keys", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--now", type=int, default=None, help=argparse.SUPPRESS)  # tests
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("rotate-local", parents=[common],
                       help="new local Ed25519 key; old public key -> previous-keys")
    r.add_argument("--issuer-key-file", required=True)
    r.add_argument("--previous-keys-file", required=True)
    r.add_argument("--retire-after", default="24h")

    k = sub.add_parser("retire-kms", parents=[common], help="snapshot a KMS key's public half into previous-keys")
    k.add_argument("--key", required=True, help="KMS key ARN or alias being retired")
    k.add_argument("--previous-keys-file", required=True)
    k.add_argument("--retire-after", default="24h")
    k.add_argument("--region", default=None)

    s = sub.add_parser("show", parents=[common], help="list previous keys")
    s.add_argument("--previous-keys-file", required=True)

    args = ap.parse_args(argv)
    now = args.now if args.now is not None else int(time.time())
    if args.cmd == "rotate-local":
        return cmd_rotate_local(args, now)
    if args.cmd == "retire-kms":
        return cmd_retire_kms(args, now, kms_client)
    return cmd_show(args, now)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
