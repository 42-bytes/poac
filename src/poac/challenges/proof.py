"""Formal-proof family: fresh core-Lean-4 propositions, kernel-validated.

Unlike the other five families there is no precomputed short answer — the
Lean kernel is the validator (see ``proof_check``). Every generated
proposition ships with a generator-authored reference proof, which (a)
guarantees provability by construction and (b) serves as the oracle in
tests and benchmarks.

Difficulty grammar (all arithmetic kept linear so `omega` can close goals
once the inductive structure is handled — core Lean has no `ring`):

- d0: closed arithmetic identity            → decidable by `decide`
- d1: universally quantified linear identity → `intro` + `omega`
- d2: closed form of a seeded linear recurrence → induction + omega
- d3: joint closed form of two seeded recurrences → induction + omega
"""

from __future__ import annotations

import random

from poac.challenges.base import GeneratedChallenge
from poac.challenges.proof_check import LEAN_VERSION
from poac.protocol.models import ProofChallenge

INSTRUCTIONS = (
    f"Submit only the Lean proof text that goes after ':=' (typically a "
    f"'by ...' tactic block) for the theorem 'poac_target' stated in "
    f"'proposition', in the context of 'preamble'. Core Lean {LEAN_VERSION} "
    "only: no imports, no metaprogramming, no '#' commands, no 'sorry'. "
    "The verifier compiles preamble + theorem + your text and audits the "
    "axioms of the result."
)


def _d0(rng: random.Random) -> tuple[str, str, str]:
    a, b, c = rng.randint(11, 99), rng.randint(11, 99), rng.randint(100, 999)
    prop = f"{a} * {b} + {c} = {a * b + c}"
    return "", prop, "by decide"


def _d1(rng: random.Random) -> tuple[str, str, str]:
    a, b, c = rng.randint(2, 12), rng.randint(2, 12), rng.randint(1, 50)
    kind = rng.choice(["distrib", "ineq"])
    if kind == "distrib":
        prop = f"∀ n : Nat, {a} * n + {b} * n + {c} = {a + b} * n + {c}"
    else:
        d = rng.randint(1, 9)
        prop = f"∀ n : Nat, {a} * n + {c} ≤ {a + d} * n + {c + b}"
    return "", prop, "by intro n; omega"


_INDUCTION_PROOF = """by
  intro n
  induction n with
  | zero => rfl
  | succ k ih => simp only [{defs}]; omega"""


def _d2(rng: random.Random) -> tuple[str, str, str]:
    a, c = rng.randint(2, 15), rng.randint(0, 30)
    preamble = f"def poacF : Nat → Nat\n  | 0 => {c}\n  | n + 1 => poacF n + {a}"
    prop = f"∀ n : Nat, poacF n = {a} * n + {c}"
    return preamble, prop, _INDUCTION_PROOF.format(defs="poacF")


def _d3(rng: random.Random) -> tuple[str, str, str]:
    a1, c1 = rng.randint(2, 15), rng.randint(0, 30)
    a2, c2 = rng.randint(2, 15), rng.randint(0, 30)
    preamble = (
        f"def poacF : Nat → Nat\n  | 0 => {c1}\n  | n + 1 => poacF n + {a1}\n\n"
        f"def poacG : Nat → Nat\n  | 0 => {c2}\n  | n + 1 => poacG n + {a2}"
    )
    prop = f"∀ n : Nat, poacF n + poacG n = {a1 + a2} * n + {c1 + c2}"
    return preamble, prop, _INDUCTION_PROOF.format(defs="poacF, poacG")


_LEVELS = {0: _d0, 1: _d1, 2: _d2, 3: _d3}


def generate(rng: random.Random, difficulty: int) -> GeneratedChallenge:
    preamble, prop, reference_proof = _LEVELS[max(0, min(difficulty, 3))](rng)
    payload = ProofChallenge(
        family="proof",
        language="lean4",
        lean_version=LEAN_VERSION,
        preamble=preamble,
        proposition=prop,
        instructions=INSTRUCTIONS,
    )
    return GeneratedChallenge(
        payload=payload,
        answer=reference_proof,
        answer_format="lean4 proof (text after ':=')",
        # rounds are chained on the proposition, not the (non-canonical) proof
        chain_material=prop,
    )
