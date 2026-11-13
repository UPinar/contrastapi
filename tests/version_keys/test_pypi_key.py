"""Check public.fn_osv_version_sortable('PyPI', v) against packaging.version.Version.

Usage: python3 test_pypi_key.py DATABASE   (a database that holds schema.sql)

Checks, each printed with its mismatch count (exit 1 on any mismatch):
  parse   - the key is NULL exactly when packaging refuses the version (InvalidVersion)
  order   - over the corpus, the rank of the key under COLLATE "C" equals the rank of Version
            (so equal keys <=> equal versions, and key order == version order)
  scalibr - each "a <op> b" line of the scalibr fixtures holds for the keys
            (lines with a version packaging refuses are counted as skipped, not checked)
"""

import os
import re
import subprocess
import sys
import tempfile

from packaging.version import InvalidVersion, Version

if len(sys.argv) < 2:
    print(f"usage: {os.path.basename(sys.argv[0])} DATABASE", file=sys.stderr)
    sys.exit(2)
DB = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")


def psql(sql, stdin_text=None):
    """Run sql in DB, answer the rows as lists of tab-separated fields."""
    out = subprocess.run(["psql", "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", DB, "-c", sql],
                         input=stdin_text, capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


def parse(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None


def sql_ranks(versions):
    """Answer {version: (is_null, dense rank of its key)} computed in the database."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(v.replace("\\", "\\\\") for v in versions) + "\n")
        path = f.name
    try:
        script = (
            "CREATE TEMP TABLE corpus (v text);\n"
            f"\\copy corpus FROM '{path}'\n"
            "SELECT v, k IS NULL, CASE WHEN k IS NOT NULL THEN dense_rank() OVER (PARTITION BY k IS NULL ORDER BY k COLLATE \"C\") END\n"
            "  FROM (SELECT v, public.fn_osv_version_sortable('PyPI', v) AS k FROM corpus) s;\n"
        )
        out = subprocess.run(["psql", "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", DB],
                             input=script, capture_output=True, text=True, check=True).stdout
    finally:
        os.unlink(path)
    res = {}
    for line in out.splitlines():
        v, is_null, rank = line.split("\t")
        res[v] = (is_null == "t", int(rank) if rank else None)
    return res


def check_corpus(versions):
    ranks = sql_ranks(versions)
    parse_bad, order_bad = [], []
    valid = []
    for v in versions:
        pv = parse(v)
        is_null, rank = ranks[v]
        if (pv is None) != is_null:
            parse_bad.append((v, "packaging=" + ("invalid" if pv is None else "valid"), "key=" + ("NULL" if is_null else "set")))
        if pv is not None and not is_null:
            valid.append((pv, rank, v))
    valid.sort(key=lambda t: t[0])
    expected, prev = 0, None
    for pv, rank, v in valid:
        if prev is None or pv != prev:
            expected += 1
            prev = pv
        if rank != expected:
            order_bad.append((v, f"key rank {rank}", f"Version rank {expected}"))
    return parse_bad, order_bad, len(valid)


def check_scalibr():
    lines = []
    for name in ("scalibr_pypi-versions.txt", "scalibr_pypi-versions-generated.txt"):
        for raw in open(os.path.join(FIX, name), encoding="utf-8"):
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("//"):
                continue
            m = re.match(r"^(\S+)\s+([<>=])\s+(\S+)$", s)
            if m:
                lines.append(m.groups())
    versions = sorted({v for a, _, b in lines for v in (a, b)})
    ranks = sql_ranks(versions)
    bad, skipped = [], 0
    for a, op, b in lines:
        if parse(a) is None or parse(b) is None:
            skipped += 1
            continue
        (na, ra), (nb, rb) = ranks[a], ranks[b]
        if na or nb:
            bad.append((a, op, b, "key NULL"))
            continue
        got = "<" if ra < rb else ">" if ra > rb else "="
        if got != op:
            bad.append((a, op, b, "key says " + got))
    return bad, skipped, len(lines)


def main():
    corpus = [l.rstrip("\n") for l in open(os.path.join(FIX, "pypi_corpus.txt"), encoding="utf-8") if l.strip()]
    parse_bad, order_bad, n_valid = check_corpus(corpus)
    scal_bad, scal_skip, scal_n = check_scalibr()
    print(f"corpus: {len(corpus)} versions, {n_valid} valid with a key")
    print(f"parse   mismatches: {len(parse_bad)}")
    print(f"order   mismatches: {len(order_bad)}")
    print(f"scalibr mismatches: {len(scal_bad)} of {scal_n} lines ({scal_skip} skipped: packaging refuses a side)")
    for title, rows in (("parse", parse_bad), ("order", order_bad), ("scalibr", scal_bad)):
        for r in rows[:8]:
            print(f"  {title}: {r}")
    sys.exit(1 if parse_bad or order_bad or scal_bad else 0)


if __name__ == "__main__":
    main()
