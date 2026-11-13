"""Maven sortable key test: public.fn_osv_version_sortable('Maven', v) against maven_ref (the
Python port of osv-scalibr's comparator).

Usage: python3 test_maven_key.py DATABASE   (a database that holds schema.sql)

The blocking property: wherever the key order differs from scalibr's,
public.fn_osv_maven_order_is_uncertain says so. uncertain() below mirrors that function. The
test checks the SQL answers against the mirror.
1. scalibr fixtures: each "a op b" line whose two keys are not NULL has the key order op, or
   the pair is uncertain.
2. corpus (fixtures/maven_corpus.txt): NULL keys are counted by reason; two versions share a
   key iff scalibr parses them to the same tokens.
3. pairs: real (each event version of a package against each event and listed version of it),
   300,000 random corpus pairs, and query spellings outside the lists (each event with -dev,
   -ea, -redhat-1, .v1, -jre, -SNAPSHOT or .Final-redhat-1, with a leading v, and without a .Final,
   .RELEASE or .final ending): key order = scalibr's, or uncertain.
4. verdicts, against a database with OSV advisory data. They cover the real versions and
   those spellings. Each package row whose ranges all give intervals is checked the way
   api.fn_package_check_advisory checks it. Its intervals are built the way the service builds
   its stored intervals. A range whose events are uncertain among themselves
   gives no interval. An interval whose bound is uncertain against the version answers "may
   affect". Each row is checked once with the keys and once with scalibr's comparator. The key
   verdict must be scalibr's, or NULL.
The real pairs, the spellings and the verdicts read the Maven rows of osv_affected. With no
Maven rows, they check nothing.
Exit 1 on any failure.
"""

import collections
import json
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import maven_ref

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
if len(sys.argv) < 2:
    print(f"usage: {os.path.basename(sys.argv[0])} DATABASE", file=sys.stderr)
    sys.exit(2)
DB = sys.argv[1]


def psql(script, stdin=None):
    return subprocess.run(["psql", "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", DB],
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
    """Answer {version: key list or None}, one psql call."""
    versions = sorted(set(versions))
    refuse_control_characters(versions)
    data = "\n".join(versions)
    script = ("CREATE TEMP TABLE vk (version text);\n"
              "COPY vk FROM STDIN WITH (FORMAT csv, DELIMITER E'\\x01', QUOTE E'\\x02');\n"
              f"{data}\n\\.\n"
              "SELECT version, coalesce(array_to_string(public.fn_osv_version_sortable('Maven', version), ' '), '\\N') FROM vk;\n")
    out = {}
    for line in psql(script).splitlines():
        v, k = line.split("\t")
        out[v] = None if k == "\\N" else k.split(" ")
    missing = set(versions) - set(out)
    assert not missing, f"no key row for {sorted(missing)[:5]}"
    return out


def sign(a, b):
    return (a > b) - (a < b)


def fixture_lines():
    for name in ("scalibr_maven-versions.txt", "scalibr_maven-versions-generated.txt"):
        for line in open(os.path.join(FIX, name)):
            line = line.strip()
            if line and not line.startswith(("//", "#")):
                a, op, b = line.split(" ")
                yield a, b, {"<": -1, "=": 0, ">": 1}[op]


def uncertain(a, b):
    """uncertain mirrors public.fn_osv_maven_order_is_uncertain on two key lists."""
    if a is None or b is None:
        return False
    zero = ("3", "8000")
    for i, (x, y) in enumerate(zip(a, b)):
        if x == y or (x in zero and y in zero):
            continue
        if i == 0 or "4" in (x, y):
            return False
        return (x == "3" and y[0] in "567") or (y == "3" and x[0] in "567") or (x[0] == "2" and y[0] == "5") \
            or (y[0] == "2" and x[0] == "5")
    return False


VARIANT_SUFFIXES = ["-dev", "-ea", "-redhat-1", ".v1", "-jre", "-SNAPSHOT", ".Final-redhat-1"]


def variants(v):
    out = {v + s for s in VARIANT_SUFFIXES} | {"v" + v}
    for suffix in (".Final", ".RELEASE", ".final"):
        if v.endswith(suffix):
            out.add(v[: -len(suffix)])
    return out


def sql_uncertain(pairs):
    """Answer fn_osv_maven_order_is_uncertain for version pairs, as {(a, b): bool}."""
    refuse_control_characters([v for pair in pairs for v in pair])
    data = "\n".join(f"{a}\x01{b}" for a, b in pairs)
    script = ("CREATE TEMP TABLE up (a text, b text);\n"
              "COPY up FROM STDIN WITH (FORMAT csv, DELIMITER E'\\x01', QUOTE E'\\x02');\n"
              f"{data}\n\\.\n"
              "SELECT a, b, public.fn_osv_maven_order_is_uncertain(public.fn_osv_version_sortable('Maven', a), "
              "public.fn_osv_version_sortable('Maven', b)) FROM up;\n")
    return {(a, b): u == "t" for a, b, u in (line.split("\t") for line in psql(script).splitlines())}


def inside(q, lo, close, cmp):
    """q is in the interval from introduced lo to the closing event close, as cmp orders versions."""
    if lo != "0" and cmp(q, lo) < 0:
        return False
    if close is None:
        return True
    kind, v = close
    return cmp(q, v) < 0 if kind == "fixed" else cmp(q, v) <= 0


def scalibr(a, b):
    return maven_ref.compare_tokens(PARSED.setdefault(a, maven_ref.parse(a)), PARSED.setdefault(b, maven_ref.parse(b)))


PARSED = {}


def package_rows():
    out = psql("SELECT package_name_normalized, version_ranges, to_jsonb(listed_versions) FROM osv_affected "
               "WHERE ecosystem = 'Maven' AND advisory_id NOT LIKE 'MAL-%'")
    for line in out.splitlines():
        pkg, ranges, versions = line.split("\t")
        yield pkg, json.loads(ranges), json.loads(versions)


def null_reason(v):
    if not v[:1].isdigit():
        return "does not start with a digit"
    if not v.isascii() or any(not (c.isalnum() or c in "._+-") for c in v) or len(v) > 256:
        return "character"
    tokens = maven_ref.parse(v)
    if any(p == "-" and t == "" for p, t in tokens[1:]):
        return "empty - qualifier in the middle"
    if any(p == "." and t.startswith("+") for p, t in tokens[1:]):
        return ". qualifier starting with +"
    if any(t.isdigit() and len(t) > 99 for _, t in tokens):
        return "number over 99 digits"
    return "UNEXPECTED"


def intervals_of(ranges, k, cmp, uncertain_pair):
    """The intervals of a package row, built the way the service builds its stored intervals.

    The answer is None when a range gives no interval.
    """
    intervals = []
    for r in ranges:
        evs = [(kind, v) for e in r.get("events", []) for kind, v in e.items()]
        if r.get("type") not in ("ECOSYSTEM", "SEMVER") or any(kind == "limit" for kind, _ in evs) \
                or any(v != "0" and k[v] is None for _, v in evs):
            return None
        real = [v for _, v in evs if v != "0"]
        if any(uncertain_pair(a, b) for a in real for b in real if a < b):
            return None
        closes = [(kind, v) for kind, v in evs if kind in ("fixed", "last_affected")]
        for kind, v in evs:
            if kind == "introduced":
                later = [c for c in closes if v == "0" or cmp(c[1], v) > 0 or (c[0] == "last_affected" and cmp(c[1], v) == 0)]
                intervals.append((v, min(later, key=lambda c: k[c[1]]) if later else None))
    return intervals or None


def key_verdict(q, intervals, listed_keys, k):
    """key_verdict answers as api.fn_package_check_advisory does on one package row: True, False or None."""
    if tuple(k[q]) in listed_keys:
        return True
    unknown = False
    for lo, close in intervals:
        bounds = ([lo] if lo != "0" else []) + ([close[1]] if close else [])
        if any(uncertain(k[q], k[b]) for b in bounds):
            unknown = True
        elif inside(q, lo, close, lambda a, b: sign(k[a], k[b])):
            return True
    return None if unknown else False


def main():
    bad = 0
    fixtures = list(fixture_lines())
    corpus = [l.rstrip("\n") for l in open(os.path.join(FIX, "maven_corpus.txt"))]
    rows = list(package_rows())
    events, listed = collections.defaultdict(set), collections.defaultdict(set)
    for pkg, ranges, versions in rows:
        listed[pkg] |= set(versions)
        events[pkg] |= {v for r in ranges for e in r.get("events", []) for kind, v in e.items() if kind != "limit" and v != "0"}
    spelled = {pkg: set().union(*(variants(e) for e in evs)) - events[pkg] - listed[pkg] for pkg, evs in events.items()}
    k = keys([v for a, b, _ in fixtures for v in (a, b)] + corpus + [v for s in events.values() for v in s]
             + [v for s in listed.values() for v in s] + [v for s in spelled.values() for v in s])
    flagged = []

    skipped = mism = covered = 0
    for a, b, want in fixtures:
        assert maven_ref.compare(a, b) == want, f"maven_ref disagrees with the fixture: {a} {b}"
        if k[a] is None or k[b] is None:
            skipped += 1
            continue
        if uncertain(k[a], k[b]):
            flagged.append((a, b))
        if sign(k[a], k[b]) != want:
            if uncertain(k[a], k[b]):
                covered += 1
            else:
                mism += 1
                print(f"  fixture mismatch: {a} vs {b}: key {sign(k[a], k[b])}, scalibr {want}")
    print(f"fixtures: {len(fixtures)} lines, {mism} mismatches not flagged uncertain, {covered} flagged, {skipped} skipped (a NULL key)")
    bad += mism

    reasons = collections.Counter(null_reason(v) for v in corpus if k[v] is None)
    print(f"corpus: {len(corpus)} versions, {sum(reasons.values())} NULL keys {dict(reasons)}")
    bad += reasons["UNEXPECTED"]
    by_key, by_tokens = collections.defaultdict(set), collections.defaultdict(set)
    for v in corpus:
        if k[v] is not None:
            by_key[tuple(k[v])].add(tuple(maven_ref.parse(v)))
            by_tokens[tuple(maven_ref.parse(v))].add(tuple(k[v]))
    shared = sum(1 for t in by_key.values() if len(t) > 1)
    split = sum(1 for t in by_tokens.values() if len(t) > 1)
    print(f"  keys shared by different tokens: {shared}; tokens with more than one key: {split}")
    bad += shared + split

    rnd = random.Random(20261028)
    usable = [v for v in corpus if k[v] is not None]
    groups = {
        "real": ((e, o) for pkg, evs in events.items() for e in evs for o in evs | listed[pkg] if o != e),
        "random": ((rnd.choice(usable), rnd.choice(usable)) for _ in range(300000)),
        "spellings": ((e, o) for pkg, evs in events.items() for e in evs for o in spelled[pkg]),
    }
    for name, pairs in groups.items():
        n = mism = covered = agree_flagged = 0
        for a, b in pairs:
            if k[a] is None or k[b] is None:
                continue
            n += 1
            u = uncertain(k[a], k[b])
            if u:
                flagged.append((a, b))
            if sign(k[a], k[b]) != scalibr(a, b):
                if u:
                    covered += 1
                else:
                    mism += 1
                    if mism <= 10:
                        print(f"  {name} mismatch not flagged: {a} vs {b}")
            elif u:
                agree_flagged += 1
        print(f"{name} pairs: {n}, {mism} mismatches not flagged uncertain, {covered} flagged mismatches, "
              f"{agree_flagged} agreeing pairs flagged")
        bad += mism

    sample = flagged[:20000] + [(rnd.choice(usable), rnd.choice(usable)) for _ in range(20000)]
    got = sql_uncertain(sample)
    differ = sum(1 for a, b in sample if got[(a, b)] != uncertain(k[a], k[b]))
    print(f"fn_osv_maven_order_is_uncertain vs mirror: {len(sample)} pairs, {differ} differ")
    bad += differ

    for name, queries in (("real", lambda pkg: events[pkg] | listed[pkg]), ("spellings", lambda pkg: spelled[pkg])):
        checked = wrong = nulls = 0
        for pkg, ranges, versions in rows:
            ours_iv = intervals_of(ranges, k, lambda a, b: sign(k[a], k[b]), lambda a, b: uncertain(k[a], k[b]))
            ref_iv = intervals_of(ranges, k, scalibr, lambda a, b: False)
            if not ours_iv or not ref_iv:
                continue
            listed_keys = {tuple(k[l]) for l in versions if k[l] is not None}
            listed_tokens = {tuple(PARSED.setdefault(l, maven_ref.parse(l))) for l in versions}
            for q in queries(pkg):
                if k[q] is None:
                    continue
                ours = key_verdict(q, ours_iv, listed_keys, k)
                ref = tuple(PARSED.setdefault(q, maven_ref.parse(q))) in listed_tokens \
                    or any(inside(q, lo, hi, scalibr) for lo, hi in ref_iv)
                checked += 1
                if ours is None:
                    nulls += 1
                elif ours != ref:
                    wrong += 1
                    if wrong <= 10:
                        print(f"  {name} verdict wrong: {pkg} {q} {ours_iv}: keys {ours}, scalibr {ref}")
        print(f"{name} verdicts: {checked}, {wrong} wrong, {nulls} NULL (uncertain)")
        bad += wrong
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
