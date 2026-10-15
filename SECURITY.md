# Security

## Reporting

Please report vulnerabilities privately through GitHub's "Report a
vulnerability" (Security → Advisories) on this repository. You should hear
back within 72 hours. Do not open public issues for security reports.

## What a report about receipt integrity needs to show

PoAC's trust boundary is small and explicit:

- Receipts are JWS signed by the verifier's issuer key. In the public
  instance the private key lives in AWS KMS (`ECC_NIST_EDWARDS25519`,
  optionally co-signed with `ML_DSA_65`) and is not exportable. Anyone can
  run this code; nobody but the operator of a verifier can mint receipts
  that validate against that verifier's `/.well-known/jwks.json`.
- Relying parties pin the verifier: `iss` must equal the pinned URL and
  the `kid` must appear in that verifier's JWKS, in addition to the
  verifier's own `/v1/verify` answer.
- Presentations are holder-bound (`cnf.jkt` + KB-JWT over a verifier-issued
  one-shot nonce); a stolen receipt is useless without the holder key.

Issues in scope: forged or replayed receipts/presentations, algorithm or
serialisation confusion, nonce reuse, sandbox escape from Lean kernel
checks, challenge-corpus exfiltration, timing side channels that let a
non-agent pass.

## Supply chain

Releases are built in GitHub Actions and published to PyPI via Trusted
Publishing (OIDC) with Sigstore attestations; there is no long-lived PyPI
token. Verify a wheel with `pip download poac && python -m pip install
pypi-attestations && pypi-attestations verify pypi …`. The full git
history is scanned with gitleaks on every push.
