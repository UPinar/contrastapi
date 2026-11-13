# SPDX-License-Identifier: Apache-2.0
# Source: osv/ecosystems/packagist.py of google/osv.dev (https://github.com/google/osv.dev),
#   ported 2026-10-28.
# The upstream file is under the Apache License 2.0.
# Upstream copyright notice: Copyright 2025 Google LLC.
# Changed: osv_compare and its helpers port the upstream comparison to plain functions.
# KEYED, composer_normalize and composer_compare are written for these tests.
"""Reference Packagist comparators for the tests.

osv_compare(a, b): osv.dev's order (the oracle), the PackagistVersion comparison of
google/osv.dev osv/ecosystems/packagist.py (Apache-2.0), ported to plain functions: PHP's
version_compare on the raw string, with special words matched exactly.

composer_compare(a, b): Composer's order (what a user installs) for the versions KEYED accepts:
VersionParser::normalize (numbers padded to four, a/b/rc/p/pl expanded, case folded) and then
PHP's version_compare, where a word matches a special form by its prefix (patch → p).

KEYED is the set fn_osv_packagist_sortable gives a key: v?N.N.N and an optional suffix. On it
the two orders agree; the tests check that pair by pair.
"""

import re

KEYED = re.compile(r"v?([0-9]{1,5})\.([0-9]+)\.([0-9]+)(?:[-._]?(alpha|beta|a|b|RC|rc|pl|p)(?:[.-]?([0-9]+))?|-dev)?\Z")

_SPECIAL = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "RC": 3, "rc": 3, "#": 4, "pl": 5, "p": 5, None: 0}


def _special(a, b):
    fa, fb = _SPECIAL.get(a, -1), _SPECIAL.get(b, -1)
    return (fa > fb) - (fa < fb)


def _slices(a_split, b_split):
    for a, b in zip(a_split, b_split):
        if a.isdecimal() and b.isdecimal():
            c = int(a) - int(b)
        elif not a.isdecimal() and not b.isdecimal():
            c = _special(a, b)
        elif a.isdecimal():
            c = _special("#", b)
        else:
            c = _special(a, "#")
        if c != 0:
            return 1 if c > 0 else -1
    if len(a_split) > len(b_split):
        if a_split[len(b_split)].isdecimal():
            return 1
        return _slices(a_split[len(b_split):], ["#"])
    if len(a_split) < len(b_split):
        if b_split[len(a_split)].isdecimal():
            return -1
        return _slices(["#"], b_split[len(a_split):])
    return 0


def _canonical(version):
    if version.startswith("v"):
        version = version[1:]
    replaced = re.sub("[-_+.]+", ".", version)
    replaced = re.sub(r"([^\d.])(\d)", r"\1.\2", replaced)
    return re.sub(r"(\d)([^\d.])", r"\1.\2", replaced)


def osv_compare(a, b):
    return _slices(_canonical(a).split("."), _canonical(b).split("."))


def composer_normalize(version):
    """VersionParser::normalize for a version of KEYED; the patch word is written p, the form
    PHP's prefix match gives it."""
    m = KEYED.match(version)
    assert m, version
    out = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.0"
    word = m.group(4)
    if word:
        out += "-" + {"a": "alpha", "b": "beta", "rc": "RC", "RC": "RC", "pl": "p", "p": "p"}.get(word, word) + (m.group(5) or "")
    elif version.endswith("-dev"):
        out += "-dev"
    return out


def composer_compare(a, b):
    return osv_compare(composer_normalize(a), composer_normalize(b))
