"""Packagist key against PHP itself: fn_osv_packagist_sortable against PHP's version_compare and
Composer's VersionParser (packagist_php_ref.php), where test_packagist_key.py checks it
against Python ports.

Usage: python3 test_packagist_php.py KEY_DATABASE [DATA_DATABASE]
  The arguments are those of test_packagist_key.py. KEY_DATABASE holds schema.sql.
  DATA_DATABASE defaults to KEY_DATABASE.
Needs php-cli and php-composer-semver.

Pairs: the keyed corpus and 20,000 synthetic versions, each sorted by key (adjacent pairs) plus
300,000 random pairs of each; and for each Packagist package, each pair of its keyed event and
listed versions. The package pairs need a database with OSV advisory data.
For a pair of two keyed versions the key order must equal PHP's raw order and
Composer's order (blocking). For 300,000 random pairs of the corpus, keyed or not, packagist_ref's
osv_compare is compared with PHP's raw order: that measures the Python port, and is reported,
not blocking (osv.dev runs the port, not PHP).
Exit 1 on a blocking mismatch.
"""

import collections
import json
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import packagist_ref
import test_packagist_key as tk

HERE = os.path.dirname(os.path.abspath(__file__))


def php(pairs):
    out = subprocess.run(["php", os.path.join(HERE, "packagist_php_ref.php")], input="".join(f"{a}\t{b}\n" for a, b in pairs),
                         check=True, capture_output=True, text=True).stdout.splitlines()
    assert len(out) == len(pairs), "php answered a different number of lines"
    return [tuple(None if x == "ERR" else int(x) for x in line.split("\t")) for line in out]


def main():
    corpus = [line.rstrip("\n") for line in open(os.path.join(tk.FIX, "packagist_corpus.txt"))]
    synth = tk.synthetic(20000)
    rows = [line.split("\t") for line in tk.psql(tk.DATA_DB, "SELECT package_name_normalized, version_ranges, to_jsonb(listed_versions) "
                                                            "FROM osv_affected WHERE ecosystem = 'Packagist' AND advisory_id NOT LIKE 'MAL-%'").splitlines()]
    per_package = collections.defaultdict(set)
    for pkg, ranges, versions in rows:
        per_package[pkg] |= set(json.loads(versions))
        per_package[pkg] |= {v for r in json.loads(ranges) for e in r.get("events", []) for kind, v in e.items() if kind != "limit" and v != "0"}
    k = tk.keys(corpus + synth + [v for s in per_package.values() for v in s])

    rnd = random.Random(20261029)
    keyed_pairs = []
    for versions in (corpus, synth):
        ordered = sorted((v for v in versions if k[v] is not None), key=lambda v: k[v])
        keyed_pairs += list(zip(ordered, ordered[1:])) + [(rnd.choice(ordered), rnd.choice(ordered)) for _ in range(300000)]
    for versions in per_package.values():
        keyed = sorted(v for v in versions if k[v] is not None)
        keyed_pairs += [(a, b) for i, a in enumerate(keyed) for b in keyed[i + 1:]]

    bad = refused = 0
    for (a, b), (raw, composer) in zip(keyed_pairs, php(keyed_pairs)):
        ours = tk.sign(k[a], k[b])
        if composer is None:
            refused += 1
        if ours != raw or (composer is not None and ours != composer):
            bad += 1
            if bad <= 10:
                print(f"  mismatch: {a} vs {b}: key {ours}, PHP raw {raw}, Composer {composer}")
    print(f"keyed pairs: {len(keyed_pairs)}, {bad} mismatches, {refused} pairs Composer refuses")

    port_pairs = [(rnd.choice(corpus), rnd.choice(corpus)) for _ in range(300000)]
    port_bad = collections.Counter()
    for (a, b), (raw, _) in zip(port_pairs, php(port_pairs)):
        if packagist_ref.osv_compare(a, b) != raw:
            port_bad[(a, b)] += 1
    print(f"port check (not blocking): {len(port_pairs)} random corpus pairs, keyed or not, "
          f"{len(port_bad)} where osv_compare and PHP's raw order differ {list(port_bad)[:5]}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
