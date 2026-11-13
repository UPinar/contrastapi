"""Packagist sortable key test: public.fn_osv_packagist_sortable(v) against packagist_ref
(osv.dev's order, the oracle, and Composer's order, what a user installs).

Usage: python3 test_packagist_key.py KEY_DATABASE [DATA_DATABASE]
  KEY_DATABASE:  a database that holds schema.sql. public.fn_osv_packagist_sortable runs there.
  DATA_DATABASE: the database whose Packagist advisories are read, read-only (default: KEY_DATABASE).

1. scalibr fixtures: each "a op b" line whose two keys are not NULL has the key order op.
2. corpus (fixtures/packagist_corpus.txt): a version has a key iff packagist_ref.KEYED accepts
   it; sorted by key, each adjacent pair and 300,000 random pairs are ordered the same by
   osv.dev and by Composer. The same for 20,000 synthetic versions of the hard parts (v, the
   words and their short forms, a number after a word or not, leading zeros, -dev).
3. real verdicts, against a database with OSV advisory data. Each Packagist package row whose
   ranges all give intervals is read. Each event and listed version of its package is checked: is it
   listed, or inside an interval? The intervals are built from the range events, the way the
   service builds its stored intervals. Each version is checked once with the keys and once
   with osv.dev's order. The verdicts must agree. With no Packagist rows, this part checks nothing.
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
import packagist_ref

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
              "SELECT version, coalesce(array_to_string(public.fn_osv_packagist_sortable(version), ' '), '\\N') FROM vk;\n")
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


def synthetic(count):
    rnd = random.Random(20261030)
    words = ["alpha", "beta", "a", "b", "RC", "rc", "pl", "p"]
    out = set()
    while len(out) < count:
        v = ("v" if rnd.random() < 0.3 else "") + ".".join(rnd.choice(["0", "1", "2", "10", "01", "007"]) for _ in range(3))
        x = rnd.random()
        if x < 0.1:
            v += "-dev"
        elif x < 0.7:
            v += rnd.choice(["", "-", ".", "_"]) + rnd.choice(words) + rnd.choice(["", "0", "1", "2", "10", ".1", "-2", "01"])
        out.add(v)
    return sorted(out)


def check_pairs(label, versions, k, rnd):
    ordered = sorted(versions, key=lambda v: k[v])
    pairs = list(zip(ordered, ordered[1:])) + [(rnd.choice(ordered), rnd.choice(ordered)) for _ in range(300000)]
    mism = 0
    for a, b in pairs:
        ours = sign(k[a], k[b])
        if ours != packagist_ref.osv_compare(a, b) or ours != packagist_ref.composer_compare(a, b):
            mism += 1
            if mism <= 10:
                print(f"  {label} pair mismatch: {a} vs {b}: key {ours}, osv.dev {packagist_ref.osv_compare(a, b)}, "
                      f"Composer {packagist_ref.composer_compare(a, b)}")
    print(f"  {label}: {len(ordered) - 1} adjacent + 300000 random pairs, {mism} mismatches")
    return mism


def main():
    bad = 0
    fixtures = []
    for line in open(os.path.join(FIX, "scalibr_packagist-versions.txt")):
        line = line.strip()
        if line and not line.startswith(("//", "#")):
            a, op, b = line.split(" ")
            fixtures.append((a, b, {"<": -1, "=": 0, ">": 1}[op]))
    corpus = [l.rstrip("\n") for l in open(os.path.join(FIX, "packagist_corpus.txt"))]
    synth = synthetic(20000)
    rows = [line.split("\t") for line in psql(DATA_DB, "SELECT package_name_normalized, version_ranges, to_jsonb(listed_versions) "
                                                       "FROM osv_affected WHERE ecosystem = 'Packagist' AND advisory_id NOT LIKE 'MAL-%'").splitlines()]
    rows = [(p, json.loads(r), json.loads(v)) for p, r, v in rows]
    events, listed = collections.defaultdict(set), collections.defaultdict(set)
    for pkg, ranges, versions in rows:
        listed[pkg] |= set(versions)
        events[pkg] |= {v for r in ranges for e in r.get("events", []) for kind, v in e.items() if kind != "limit" and v != "0"}
    k = keys([v for a, b, _ in fixtures for v in (a, b)] + corpus + synth + [v for s in events.values() for v in s]
             + [v for s in listed.values() for v in s])

    mism = skipped = 0
    for a, b, want in fixtures:
        if k[a] is None or k[b] is None:
            skipped += 1
        elif sign(k[a], k[b]) != want:
            mism += 1
            print(f"  fixture mismatch: {a} vs {b}: key {sign(k[a], k[b])}, scalibr {want}")
    print(f"fixtures: {len(fixtures)} lines, {mism} mismatches, {skipped} skipped (a NULL key)")
    bad += mism

    rnd = random.Random(20261028)
    for label, versions in (("corpus", corpus), ("synthetic", synth)):
        wrong = [v for v in versions if (k[v] is None) == bool(packagist_ref.KEYED.match(v))]
        print(f"{label}: {len(versions)} versions, {sum(k[v] is None for v in versions)} NULL keys, "
              f"{len(wrong)} where the key and KEYED disagree {wrong[:10]}")
        bad += len(wrong)
        bad += check_pairs(label, [v for v in versions if k[v] is not None], k, rnd)

    ref_cmp = functools.lru_cache(maxsize=None)(packagist_ref.osv_compare)
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
                    print(f"  verdict differs: {pkg} {q} {intervals}: keys {ours}, osv.dev {ref}")
    print(f"real verdicts: {checked} (package row x event/listed version), {flipped} differ")
    bad += flipped
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
