"""Lean kernel validation for the proof family.

Security model (see docs/threat-model.md): the submission is untrusted text
that Lean will *elaborate*, and elaboration is programmable. Defense layers:

1. token screen — reject any submission containing tokens that reach the
   axiom system, metaprogramming, or the compiler/FFI;
2. subprocess isolation with a hard timeout and a minimal environment;
3. axiom audit — even if a proof "checks", it is accepted only when
   ``#print axioms poac_target`` reports a subset of Lean's three standard
   axioms. This catches ``sorry`` (which exits 0 with just a warning!) and
   any obfuscated route to ``sorryAx``.

Container isolation is additionally required for production deployment;
this module alone is prototype-grade.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from poac.protocol.models import MAX_PROOF_ANSWER_CHARS

LEAN_VERSION = "4.33.1"
CHECK_TIMEOUT_S = 20

ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}

# Substring screen over the raw submission. Broad on purpose: false
# positives merely fail one round; false negatives are a security hole.
FORBIDDEN_TOKENS = (
    "sorry",          # includes sorryAx
    "admit",
    "axiom",
    "unsafe",
    "extern",
    "implemented_by",
    "native_decide",
    "ofReduceBool",
    "ofReduceNat",
    "macro",
    "elab",
    "syntax",
    "notation",
    "import",
    # bare "open" (no trailing space): `open\nNat in ...` must not slip past
    "open",
    "set_option",
    "partial",
    "opaque",
    "initialize",
    "builtin",
    "run_cmd",
    "run_elab",
    "#",              # bans all commands: #eval, #check, #print, ...
    "@[",             # attributes
    "attribute",
    "IO.",
    "Lean.",
    "System.",
)


@dataclass(frozen=True)
class ProofCheckResult:
    ok: bool
    reason: str


def find_lean() -> str | None:
    """Locate a Lean binary: env override, elan toolchain, then PATH."""
    env_bin = os.environ.get("POAC_LEAN_BIN")
    if env_bin and Path(env_bin).is_file():
        return env_bin
    toolchain = (
        Path.home()
        / ".elan"
        / "toolchains"
        / f"leanprover--lean4---v{LEAN_VERSION}"
        / "bin"
        / "lean"
    )
    if toolchain.is_file():
        return str(toolchain)
    return shutil.which("lean")


def screen_submission(submission: str) -> str | None:
    """Return a rejection reason, or None if the text passes the screen."""
    if len(submission) > MAX_PROOF_ANSWER_CHARS:
        return "submission too long"
    if not submission.strip():
        return "submission is empty"
    # non-ASCII is allowed (∀, →, ≤ ...), but control chars are not
    if any(ord(c) < 32 and c not in "\n\t" for c in submission):
        return "submission contains control characters"
    for token in FORBIDDEN_TOKENS:
        if token in submission:
            return f"forbidden token: {token.strip()!r}"
    return None


def assemble_file(preamble: str, proposition: str, submission: str) -> str:
    parts = []
    if preamble.strip():
        parts.append(preamble.strip())
    parts.append(f"theorem poac_target : {proposition} := {submission.strip()}")
    parts.append("#print axioms poac_target")
    return "\n\n".join(parts) + "\n"


_AXIOM_LINE = re.compile(r"'poac_target' depends on axioms: \[([^\]]*)\]")


def check_proof(
    lean_bin: str,
    preamble: str,
    proposition: str,
    submission: str,
    timeout_s: float = CHECK_TIMEOUT_S,
) -> ProofCheckResult:
    reason = screen_submission(submission)
    if reason is not None:
        return ProofCheckResult(False, reason)

    source = assemble_file(preamble, proposition, submission)
    with tempfile.TemporaryDirectory(prefix="poac-lean-") as tmp:
        path = Path(tmp) / "Submission.lean"
        path.write_text(source, encoding="utf-8")
        try:
            proc = subprocess.run(
                [lean_bin, str(path)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                cwd=tmp,
                env={"HOME": tmp, "PATH": str(Path(lean_bin).parent)},
            )
        except subprocess.TimeoutExpired:
            return ProofCheckResult(False, "kernel check timed out")

    output = proc.stdout + proc.stderr
    if proc.returncode != 0:
        return ProofCheckResult(False, "lean rejected the proof")
    if "warning: declaration uses 'sorry'" in output or "uses `sorry`" in output:
        return ProofCheckResult(False, "proof uses sorry")

    m = _AXIOM_LINE.search(output)
    if m is None:
        # `#print axioms` prints "'poac_target' does not depend on any axioms"
        # when the proof is axiom-free; anything else is suspicious.
        if "'poac_target' does not depend on any axioms" in output:
            return ProofCheckResult(True, "ok")
        return ProofCheckResult(False, "axiom audit output missing")
    axioms = {a.strip() for a in m.group(1).split(",") if a.strip()}
    if not axioms <= ALLOWED_AXIOMS:
        return ProofCheckResult(
            False, f"disallowed axioms: {sorted(axioms - ALLOWED_AXIOMS)}"
        )
    return ProofCheckResult(True, "ok")
