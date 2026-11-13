# SPDX-License-Identifier: Apache-2.0
# Source: semantic/version-maven.go of google/osv-scalibr
#   (https://github.com/google/osv-scalibr), ported 2026-10-28.
# The upstream file is under the Apache License 2.0.
# Upstream copyright notice: Copyright 2026 Google LLC.
# Changed: this file is a Python port of that Go file.
"""Reference Maven comparator for the tests: a Python port of osv-scalibr
semantic/version-maven.go (Apache-2.0).

parse(s) gives the token list, compare(a, b) gives -1 / 0 / 1 as scalibr's Compare does.
Only ASCII input is meaningful here, because Go's regexp \\d is [0-9]. The SQL key refuses
other input. The tests compare only versions with a key. They parse a listed version without
one only to look for it in the list.
"""

import re

KEYWORDS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_TRANSITION = re.compile(r"(?<=[0-9])(?=[^0-9])|(?<=[^0-9])(?=[0-9])")


def _numeric(value):
    return value != "" and value.isascii() and value.isdigit()


def parse(s):
    tokens = []
    raw = re.split(r"([-.])", s)
    for i in range(0, len(raw), 2):
        prefix = "" if i == 0 else raw[i - 1]
        part = raw[i]
        cuts = [m.start() for m in _TRANSITION.finditer(part)] + [len(part)]
        prev = 0
        for j, cut in enumerate(cuts):
            if j > 0:
                prefix = "-"
            current = part[prev:cut].lower()
            if current == "":
                current = "0"
            if current == "cr":
                current = "rc"
            if current in ("ga", "final", "release"):
                current = ""
            if cut != len(part):
                current = {"a": "alpha", "b": "beta", "m": "milestone"}.get(current, current)
            if _numeric(current):
                current = str(int(current))
            tokens.append((prefix, current))
            prev = cut
    i = len(tokens) - 1
    while i > 0:
        if tokens[i][1] in ("0", "", "final", "ga"):
            del tokens[i]
            i -= 1
            continue
        while i >= 0 and tokens[i][0] != "-":
            i -= 1
        i -= 1
    return tokens


def _null(token):
    if token[0] == ".":
        return (".", "" if token[1] == "sp" else "0", True)
    return ("-", "", True)


def _order(token):
    if _numeric(token[1]):
        return 2 if token[0] == "-" else 3
    return 1 if token[0] == "-" else 0


def _keyword(value):
    return KEYWORDS.index(value) if value in KEYWORDS else len(KEYWORDS)


def _less(v, w):
    if v[0] == w[0]:
        vn, wn = _numeric(v[1]), _numeric(w[1])
        if vn and wn:
            return int(v[1]) < int(w[1])
        if vn and not v[2]:
            return False
        if wn and not w[2]:
            return True
        li, ri = _keyword(v[1]), _keyword(w[1])
        if li == len(KEYWORDS) and ri == len(KEYWORDS):
            return v[1] < w[1]
        return li < ri
    return _order(v) < _order(w)


def _less_version(a, b):
    for i in range(max(len(a), len(b))):
        left = (*a[i], False) if i < len(a) else _null(b[i])
        right = (*b[i], False) if i < len(b) else _null(a[i])
        if left[:2] == right[:2]:
            continue
        return _less(left, right)
    return False


def compare_tokens(a, b):
    if a == b:
        return 0
    return -1 if _less_version(a, b) else 1


def compare(a, b):
    return compare_tokens(parse(a), parse(b))
