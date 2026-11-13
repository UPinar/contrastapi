# SPDX-License-Identifier: Apache-2.0
# Source: semantic/version-nuget.go, semantic/version-semver-like.go and the build compare of
#   semantic/version-semver.go of google/osv-scalibr (https://github.com/google/osv-scalibr),
#   ported 2026-10-28.
# The upstream files are under the Apache License 2.0.
# Upstream copyright notice: Copyright 2026 Google LLC.
# Changed: this file is a Python port of those Go files.
"""Reference NuGet comparator for the tests: a Python port of osv-scalibr
semantic/version-nuget.go, version-semver-like.go and the build compare of version-semver.go
(Apache-2.0).

compare(a, b) gives -1 / 0 / 1 as scalibr's NuGetVersion.CompareStr does.
"""

MAX_COMPONENTS = 4


def _big(s):
    """_big reads s as Go's big.Int SetString(s, 10) does: an optional sign, then digits."""
    body = s[1:] if s[:1] in ("+", "-") else s
    if body == "" or not (body.isascii() and body.isdigit()):
        return None
    return int(s)


def parse(line):
    comps, current, found_build = [], "", False
    if line.startswith("v"):
        line = line[1:]
    for c in line:
        if found_build:
            current += c
            continue
        if "0" <= c <= "9":
            current += c
            continue
        if current != "":
            comps.append(int(current))
            current = ""
        if c == ".":
            continue
        found_build = True
        current = c
    if not found_build and current != "":
        comps.append(int(current))
        current = ""
    build = current
    if len(comps) > MAX_COMPONENTS:
        build += "".join(f".{c}" for c in comps[MAX_COMPONENTS:])
        comps = comps[:MAX_COMPONENTS]
    return comps, build


def _cmp_components(a, b):
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x != y:
            return -1 if x < y else 1
    return 0


def _cmp_identifiers(a, b):
    for x, y in zip(a, b):
        xi, yi = _big(x), _big(y)
        if xi is not None and yi is not None:
            c = (xi > yi) - (xi < yi)
        elif xi is None and yi is None:
            c = (x > y) - (x < y)
        elif xi is not None:
            c = -1
        else:
            c = 1
        if c:
            return c
    return (len(a) > len(b)) - (len(a) < len(b))


def _cmp_build(a, b):
    a = a.split("+")[0]
    b = b.split("+")[0]
    a = a[1:] if a.startswith("-") else a
    b = b[1:] if b.startswith("-") else b
    if a == "" and b != "":
        return 1
    if a != "" and b == "":
        return -1
    return _cmp_identifiers(a.split("."), b.split("."))


def compare(a, b):
    (ca, ba), (cb, bb) = parse(a), parse(b)
    return _cmp_components(ca, cb) or _cmp_build(ba.lower(), bb.lower())
