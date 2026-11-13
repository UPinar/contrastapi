"""RubyGems sortable key test: public.fn_osv_rubygems_sortable(v) against Ruby's own Gem::Version
(rubygems_ref.rb, next to this file).

Usage: python3 test_rubygems_key.py KEY_DATABASE [DATA_DATABASE]
  KEY_DATABASE:  a database that holds schema.sql. public.fn_osv_rubygems_sortable runs there.
  DATA_DATABASE: the database whose RubyGems advisories are read, read-only (default: KEY_DATABASE).

1. fixtures (fixtures/scalibr_rubygems-versions.txt): each "a op b" line whose two versions Ruby
   accepts has the Ruby order, and the key has it too.
2. corpus (fixtures/rubygems_corpus.txt): a version has a key only when Ruby accepts it, and a NULL
   key only when Ruby refuses it, or it has a -, white space or a number of more than 99 digits; sorted by key, each adjacent pair is
   ordered the same by Ruby, and so are 300,000 random pairs.
   The same for 20,000 synthetic versions built from the hard parts (0 and 00 before letters and
   before numbers, upper and lower case, -, letters and digits in one part), since few real
   versions hold a -, a 00 part or an upper-case letter. Each synthetic version with a - must have a NULL key, each other one
   a key.
3. real verdicts, against a database with OSV advisory data. Each RubyGems package row whose
   ranges all give intervals is read. Each event and listed version of its package is checked: is it
   listed, or inside an interval? The intervals are built from the range events, the way the
   service builds its stored intervals. Each version is checked once with the keys and once
   with Ruby. The verdicts must agree. With no RubyGems rows, this part checks nothing.
Each call to Ruby starts one ruby process and sends it one line per comparison. Exit 1 on any mismatch.
"""

import collections
import json
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
REF = os.path.join(HERE, "rubygems_ref.rb")
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
              "SELECT version, coalesce(array_to_string(public.fn_osv_rubygems_sortable(version), ' '), '\\N') FROM vk;\n")
    out = {}
    for line in psql(KEY_DB, script).splitlines():
        v, k = line.split("\t")
        out[v] = None if k == "\\N" else k.split(" ")
    assert set(versions) <= set(out), "a version got no key row"
    return out


def ruby(args, lines):
    out = subprocess.run(["ruby", REF, *args], input="".join(l + "\n" for l in lines),
                         check=True, capture_output=True, text=True).stdout.split("\n")[:-1]
    assert len(out) == len(lines), "ruby answered a different number of lines"
    return out


def ruby_cmp(pairs):
    """Answer {(a, b): -1/0/1 or None (Ruby refuses one)} for the pairs."""
    pairs = sorted(set(pairs))
    return {p: None if o == "ERR" else int(o) for p, o in zip(pairs, ruby([], [f"{a}\t{b}" for a, b in pairs]))}


def synthetic(count):
    """Answer count distinct versions Gem::Version accepts, built from the hard parts."""
    rnd = random.Random(20261029)
    parts = ["0", "00", "1", "2", "10", "007", "a", "A", "b", "rc", "pre", "Z", "0a", "a0", "1b2"]
    out = set()
    while len(out) < count:
        v = rnd.choice(["0", "1", "2", "10"]) + "".join("." + rnd.choice(parts) for _ in range(rnd.randint(0, 5)))
        if rnd.random() < 0.3:
            v += "-" + ".".join(rnd.choice(parts + ["x-y"]) for _ in range(rnd.randint(1, 3)))
        out.add(v)
    return sorted(out)


def check_pairs(label, versions, k, rnd):
    ordered = sorted(versions, key=lambda v: k[v])
    pairs = list(zip(ordered, ordered[1:])) + [(rnd.choice(ordered), rnd.choice(ordered)) for _ in range(300000)]
    ref = ruby_cmp(pairs)
    mism = 0
    for a, b in pairs:
        if ref[(a, b)] != sign(k[a], k[b]):
            mism += 1
            if mism <= 10:
                print(f"  {label} pair mismatch: {a} vs {b}: key {sign(k[a], k[b])}, Ruby {ref[(a, b)]}")
    print(f"  {label}: {len(ordered) - 1} adjacent + 300000 random pairs, {mism} mismatches")
    return mism


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
    for line in open(os.path.join(FIX, "scalibr_rubygems-versions.txt")):
        line = line.strip()
        if line and not line.startswith(("//", "#")):
            a, op, b = line.split(" ")
            fixtures.append((a, b, {"<": -1, "=": 0, ">": 1}[op]))
    corpus = [l.rstrip("\n") for l in open(os.path.join(FIX, "rubygems_corpus.txt"))]
    rows = [line.split("\t") for line in psql(DATA_DB, "SELECT package_name_normalized, version_ranges, to_jsonb(listed_versions) "
                                                       "FROM osv_affected WHERE ecosystem = 'RubyGems' AND advisory_id NOT LIKE 'MAL-%'").splitlines()]
    rows = [(p, json.loads(r), json.loads(v)) for p, r, v in rows]
    events, listed = collections.defaultdict(set), collections.defaultdict(set)
    for pkg, ranges, versions in rows:
        listed[pkg] |= set(versions)
        events[pkg] |= {v for r in ranges for e in r.get("events", []) for kind, v in e.items() if kind != "limit" and v != "0"}
    synth = synthetic(20000)
    k = keys([v for a, b, _ in fixtures for v in (a, b)] + corpus + synth + [v for s in events.values() for v in s]
             + [v for s in listed.values() for v in s])

    ref = ruby_cmp([(a, b) for a, b, _ in fixtures])
    mism = refused = 0
    for a, b, want in fixtures:
        if ref[(a, b)] is None:
            refused += 1
            if k[a] is not None and k[b] is not None:
                mism += 1
                print(f"  fixture: Ruby refuses {a} or {b}, both have a key")
            continue
        if ref[(a, b)] != want:
            print(f"  note: Ruby and scalibr part on {a} {b}: Ruby {ref[(a, b)]}, scalibr {want}")
        if k[a] is None or k[b] is None or sign(k[a], k[b]) != ref[(a, b)]:
            mism += 1
            print(f"  fixture mismatch: {a} vs {b}: key {k[a]} {k[b]}, Ruby {ref[(a, b)]}")
    print(f"fixtures: {len(fixtures)} lines, {refused} with a version Ruby refuses, {mism} mismatches")
    bad += mism

    valid = dict(zip(corpus, ruby(["valid"], corpus)))
    nulls = [v for v in corpus if k[v] is None]
    wrong_null = [v for v in nulls if valid[v] == "1" and "-" not in v and not re.search(r"\s", v)
                  and not re.search(r"[1-9][0-9]{99}", v) and v != ""]
    wrong_key = [v for v in corpus if k[v] is not None and valid[v] != "1"]
    print(f"corpus: {len(corpus)} versions, {len(nulls)} NULL keys {nulls[:10]}")
    print(f"  NULL though Ruby accepts it: {len(wrong_null)} {wrong_null[:10]}; a key though Ruby refuses it: {len(wrong_key)} {wrong_key[:10]}")
    bad += len(wrong_null) + len(wrong_key)
    rnd = random.Random(20261028)
    bad += check_pairs("corpus", [v for v in corpus if k[v] is not None], k, rnd)
    synth_null = [v for v in synth if k[v] is None and "-" not in v]
    synth_dash = [v for v in synth if k[v] is not None and "-" in v]
    print(f"synthetic: {len(synth)} versions, {sum('-' in v for v in synth)} with a -; "
          f"a NULL key without a -: {len(synth_null)} {synth_null[:5]}; a key with a -: {len(synth_dash)} {synth_dash[:5]}")
    bad += len(synth_null) + len(synth_dash)
    bad += check_pairs("synthetic", [v for v in synth if k[v] is not None], k, rnd)

    cases = []
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
        for q in events[pkg] | listed[pkg]:
            if k[q] is not None:
                cases.append((pkg, q, intervals, versions))
    needed = set()
    for _, q, intervals, versions in cases:
        needed |= {(q, l) for l in versions} | {(q, lo) for lo, _ in intervals if lo != "0"} | {(q, hi[1]) for _, hi in intervals if hi}
    ref = ruby_cmp(needed)
    flipped = 0
    for pkg, q, intervals, versions in cases:
        listed_keys = {tuple(k[l]) for l in versions if k[l] is not None}
        ours = tuple(k[q]) in listed_keys or any(inside(q, lo, hi, lambda a, b: sign(k[a], k[b])) for lo, hi in intervals)
        theirs = any(ref[(q, l)] == 0 for l in versions) or any(inside(q, lo, hi, lambda a, b: ref[(a, b)]) for lo, hi in intervals)
        if ours != theirs:
            flipped += 1
            if flipped <= 10:
                print(f"  verdict differs: {pkg} {q} {intervals}: keys {ours}, Ruby {theirs}")
    print(f"real verdicts: {len(cases)} (package row x event/listed version), {len(needed)} Ruby comparisons, {flipped} differ")
    bad += flipped
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
