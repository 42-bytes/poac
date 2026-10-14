"""`poac-corpus` — author, inspect and rotate the private corpus.

    poac-corpus build  --db corpus.sqlite --author llm --model openai:gpt-5.2 \
                       --family nlu --difficulty 2 --count 50 --batch 2026-10
    poac-corpus stats  --db corpus.sqlite
    poac-corpus retire --db corpus.sqlite --batch 2026-09
"""

from __future__ import annotations

import argparse
import sys

from poac.corpus.specs import CORPUS_FAMILIES


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="poac-corpus")
    p.add_argument("--db", required=True, help="corpus SQLite file")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="author new instances")
    b.add_argument("--author", choices=["stub", "llm"], default="llm")
    b.add_argument("--model", help="render model, e.g. openai:gpt-5.2 (llm author)")
    b.add_argument("--readback-model", help="defaults to --model; use another vendor")
    b.add_argument("--family", choices=CORPUS_FAMILIES, action="append",
                   help="repeatable; default all")
    b.add_argument("--difficulty", type=int, action="append", help="repeatable; default 0-3")
    b.add_argument("--count", type=int, default=20, help="per (family, difficulty)")
    b.add_argument("--batch", default="default")
    b.add_argument("--seed", type=int)
    b.add_argument("--max-exposures", type=int, default=5)

    sub.add_parser("stats", help="active/retired counts and exposures")

    r = sub.add_parser("retire", help="retire a whole batch (rotation)")
    r.add_argument("--batch", required=True)

    a = p.parse_args(argv)

    from poac.corpus.store import CorpusStore

    store = CorpusStore(a.db, max_exposures=getattr(a, "max_exposures", 5))

    if a.cmd == "stats":
        s = store.stats()
        print(f"active={s.active} retired={s.retired} exposures={s.exposures}")
        for (fam, d), n in sorted(s.by_family.items()):
            print(f"  {fam}/d{d}: {n}")
        return 0

    if a.cmd == "retire":
        print(f"retired {store.retire_batch(a.batch)} instances from batch {a.batch!r}")
        return 0

    from poac.corpus.build import build

    if a.author == "stub":
        from poac.corpus.author import StubAuthor

        author = StubAuthor()
    else:
        if not a.model:
            sys.exit("--model is required for --author llm")
        from poac.corpus.author import PydanticAIAuthor

        author = PydanticAIAuthor(a.model, a.readback_model)

    total_ok = total_req = 0
    for fam in a.family or CORPUS_FAMILIES:
        for d in a.difficulty or (0, 1, 2, 3):
            rep = build(store, author, fam, d, a.count, batch=a.batch, seed=a.seed)
            print(rep.summary())
            for reason in rep.rejected[:5]:
                print(f"    - {reason[:200]}")
            if len(rep.rejected) > 5:
                print(f"    - ... {len(rep.rejected) - 5} more")
            total_ok += rep.accepted
            total_req += rep.requested
    print(f"total accepted {total_ok}/{total_req} (author={author.name}, batch={a.batch})")
    return 0 if total_ok == total_req else 1


if __name__ == "__main__":
    sys.exit(main())
