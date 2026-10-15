"""`poac-trials`: operator tools for the /play human-trials log.

    poac-trials sources [--log FILE]        rows and sessions per source tag
    poac-trials purge --src TAG | --net TAG  drop a source's rows (spam)
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path

from poac.trials.log import purge_source


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="poac-trials", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default=os.environ.get("POAC_TRIALS_LOG", "/data/human-trials.jsonl"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sources", help="rows, sessions and passes per source tag, busiest first")
    pg = sub.add_parser("purge", help="remove every row from a source (src) or network (net)")
    pg.add_argument("--src")
    pg.add_argument("--net")
    args = ap.parse_args(argv)
    path = Path(args.log)

    if args.cmd == "sources":
        rows = _rows(path)
        per: dict[str, Counter] = {}
        for r in rows:
            c = per.setdefault(r.get("src", "-"), Counter(net=r.get("net", "-")))
            c["rows"] += 1
            if r.get("event") == "session":
                c["sessions"] += 1
                c["passed"] += r.get("status") == "passed"
            if r.get("event") == "round" and r.get("correct_if_untimed"):
                c["fast_ms"] = min(c.get("fast_ms", 10**9), r.get("answer_ms", 10**9))
        print(f"{'src':16} {'net':16} {'rows':>5} {'sess':>5} {'pass':>5} {'fastest_ok_ms':>14}")
        for src, c in sorted(per.items(), key=lambda kv: -kv[1]["rows"]):
            fast = c.get("fast_ms"); fast = "-" if fast is None else f"{fast:.0f}"
            print(f"{src:16} {c['net']:16} {c['rows']:5} {c['sessions']:5} {c['passed']:5} {fast:>14}")
        return

    if not (args.src or args.net):
        ap.error("purge needs --src or --net")
    n = purge_source(path, src=args.src, net=args.net)
    print(f"removed {n} rows from {path}")
