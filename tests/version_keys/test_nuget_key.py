"""NuGet sortable key test: public.fn_osv_nuget_sortable(v) against nuget_ref (the Python port
of osv-scalibr's comparator).

Usage: python3 test_nuget_key.py KEY_DATABASE [DATA_DATABASE]
  KEY_DATABASE:  a database that holds schema.sql. public.fn_osv_nuget_sortable runs there.
  DATA_DATABASE: the database whose NuGet advisories are read, read-only (default: KEY_DATABASE).

1. scalibr fixtures: each "a op b" line whose two keys are not NULL has the key order op.
2. corpus (fixtures/nuget_corpus.txt): NULL keys are listed; sorted by key, each adjacent pair
   is ordered the same by scalibr, and two keys are equal iff scalibr calls the versions equal.
   The NuGet order is total, so this covers every pair; 300,000 random pairs are checked too.
3. real verdicts, against a database with OSV advisory data. Each NuGet package row whose
   ranges all give intervals is read. Each event and listed version of its package is checked: is it
   listed, or inside an interval? The intervals are built from the range events, the way the
   service builds its stored intervals. Each version is checked once with the keys and once
   with scalibr's comparator. The verdicts must agree. With no NuGet rows, this part checks nothing.
Exit 1 on any mismatch.
"""

import collections
import functools
import json
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuget_ref

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
if len(sys.argv) < 2:
    print(f"usage: {os.path.basename(sys.argv[0])} KEY_DATABASE [DATA_DATABASE]", file=sys.stderr)
    sys.exit(2)
KEY_DB = sys.argv[1]
DATA_DB = sys.argv[2] if len(sys.argv) > 2 else KEY_DB


def psql(db, script):
    return subprocess.run(["psql", "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", db],
                          input=script, check=True, capture_output=True, text=True).stdout


def refuse_control_characters(versions):
    """Exit when a version holds a control character.

    psql reads the COPY data from the script itself. A line break inside a version could end
    the data early, and psql would then run the lines after it as its own commands. So a
    version with a control character is refused, not keyed.
    """
    for version in versions:
        if any(ord(c) < 0x20 for c in version):
            sys.exit(f"a version holds a control character: {version!r}")


def keys(versions):
    versions = sorted(set(versions))
    refuse_control_characters(versions)
    script = ("CREATE TEMP TABLE vk (version text);\n"
              "COPY vk FROM STDIN WITH (FORMAT csv, DELIMITER E'\\x01', QUOTE E'\\x02');\n"
              + "\n".join(versions) + "\n\\.\n"
              "SELECT version, coalesce(array_to_string(public.fn_osv_nuget_sortable(version), ' '), '\\N') FROM vk;\n")
    out = {}
    for line in psql(KEY_DB, script).splitlines():
        v, k = line.split("\t")
        out[v] = None if k == "\\N" else k.split(" ")
    assert set(versions) <= set(out), "a version got no key row"
    return out


def sign(a, b):
    return (a > b) - (a < b)


def inside(q, lo, close, cmp):
    if lo != "0" and cmp(q, lo) < 0:
        return False
    if close is None:
        return True
    kind, v = close
    return cmp(q, v) < 0 if kind == "fixed" else cmp(q, v) <= 0


def main():
    bad = 0
    fixtures = []
    for line in open(os.path.join(FIX, "scalibr_nuget-versions.txt")):
        line = line.strip()
        if line and not line.startswith(("//", "#")):
            a, op, b = line.split(" ")
            fixtures.append((a, b, {"<": -1, "=": 0, ">": 1}[op]))
    corpus = [l.rstrip("\n") for l in open(os.path.join(FIX, "nuget_corpus.txt"))]
    rows = [line.split("\t") for line in psql(DATA_DB, "SELECT package_name_normalized, version_ranges, to_jsonb(listed_versions) "
                                                       "FROM osv_affected WHERE ecosystem = 'NuGet' AND advisory_id NOT LIKE 'MAL-%'").splitlines()]
    rows = [(p, json.loads(r), json.loads(v)) for p, r, v in rows]
    events, listed = collections.defaultdict(set), collections.defaultdict(set)
    for pkg, ranges, versions in rows:
        listed[pkg] |= set(versions)
        events[pkg] |= {v for r in ranges for e in r.get("events", []) for kind, v in e.items() if kind != "limit" and v != "0"}
    k = keys([v for a, b, _ in fixtures for v in (a, b)] + corpus + [v for s in events.values() for v in s]
             + [v for s in listed.values() for v in s])

    mism = skipped = 0
    for a, b, want in fixtures:
        assert nuget_ref.compare(a, b) == want, f"nuget_ref disagrees with the fixture: {a} {b}"
        if k[a] is None or k[b] is None:
            skipped += 1
        elif sign(k[a], k[b]) != want:
            mism += 1
            print(f"  fixture mismatch: {a} vs {b}: key {sign(k[a], k[b])}, scalibr {want}")
    print(f"fixtures: {len(fixtures)} lines, {mism} mismatches, {skipped} skipped (a NULL key)")
    bad += mism

    nulls = [v for v in corpus if k[v] is None]
    print(f"corpus: {len(corpus)} versions, {len(nulls)} NULL keys {nulls[:10]}")
    ordered = sorted((v for v in corpus if k[v] is not None), key=lambda v: k[v])
    mism = 0
    for a, b in zip(ordered, ordered[1:]):
        if nuget_ref.compare(a, b) != sign(k[a], k[b]):
            mism += 1
            if mism <= 10:
                print(f"  adjacent mismatch: {a} vs {b}: key {sign(k[a], k[b])}, scalibr {nuget_ref.compare(a, b)}")
    rnd = random.Random(20261028)
    for _ in range(300000):
        a, b = rnd.choice(ordered), rnd.choice(ordered)
        if nuget_ref.compare(a, b) != sign(k[a], k[b]):
            mism += 1
            if mism <= 10:
                print(f"  random mismatch: {a} vs {b}")
    print(f"  {len(ordered) - 1} adjacent + 300000 random pairs, {mism} mismatches")
    bad += mism

    ref_cmp = functools.lru_cache(maxsize=None)(nuget_ref.compare)
    checked = flipped = 0
    for pkg, ranges, versions in rows:
        intervals = []
        for r in ranges:
            evs = [(kind, v) for e in r.get("events", []) for kind, v in e.items()]
            if r.get("type") not in ("ECOSYSTEM", "SEMVER") or any(kind == "limit" for kind, _ in evs) \
                    or any(v != "0" and k[v] is None for _, v in evs):
                intervals = None
                break
            closes = [(kind, v) for kind, v in evs if kind in ("fixed", "last_affected")]
            for kind, v in evs:
                if kind == "introduced":
                    later = [c for c in closes if v == "0" or k[c[1]] > k[v] or (c[0] == "last_affected" and k[c[1]] == k[v])]
                    intervals.append((v, min(later, key=lambda c: k[c[1]]) if later else None))
        if not intervals:
            continue
        listed_keys = {tuple(k[l]) for l in versions if k[l] is not None}
        for q in events[pkg] | listed[pkg]:
            if k[q] is None:
                continue
            ours = tuple(k[q]) in listed_keys or any(inside(q, lo, hi, lambda a, b: sign(k[a], k[b])) for lo, hi in intervals)
            ref = any(ref_cmp(q, l) == 0 for l in versions) or any(inside(q, lo, hi, ref_cmp) for lo, hi in intervals)
            checked += 1
            if ours != ref:
                flipped += 1
                if flipped <= 10:
                    print(f"  verdict differs: {pkg} {q} {intervals}: keys {ours}, scalibr {ref}")
    print(f"real verdicts: {checked} (package row x event/listed version), {flipped} differ")
    bad += flipped
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
