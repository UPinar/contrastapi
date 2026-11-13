"""Write src/etld_table.c from the ICANN section of the Public Suffix List.

Usage:
  python3 -I tests/psl/gen_etld_table.py <list> <table.c>
  python3 -I tests/psl/gen_etld_table.py --rules <list>

tests/psl/public_suffix_list.dat holds a copy of the list. `make etld-table` runs the
first form on that copy. CI runs it again and fails when src/etld_table.c differs from
what it writes. The monthly psl workflow runs the second form on the copy and on a
fresh download, and compares the two rule lists.

The list has two sections. The ICANN section holds the suffixes that registries sell
names under. The PRIVATE section holds suffixes that companies such as GitHub give out,
like github.io. The table takes only the ICANN section, so user.github.io reduces to
github.io.

A rule is the first word of a line that is not a comment. A rule may start with "*." or
"!". A label outside ASCII is written in its xn-- form: "xn--" and the RFC 3492 punycode
of the label. The list writes each label in lower case and in Unicode normal form C,
which the conversion needs.

The second form prints the rules, one per line, in the order of the table.

The table quotes the VERSION and COMMIT lines of the list. Each must have the form
HEADER_VALUES gives.

Exit status: 0 when the table or the rule list was written. 1 on a wrong command line, a
list that cannot be read, a list without the ICANN markers, a rule that breaks the rules
above, or a VERSION or COMMIT line that is missing or has another form.
"""

import re
import sys

ICANN_BEGIN = "// ===BEGIN ICANN DOMAINS==="
ICANN_END = "// ===END ICANN DOMAINS==="

LDH_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

HEADER = """\
/*
 * etld_table.c — the ICANN rules of the Public Suffix List, for etld.c.
 *
 * tests/psl/gen_etld_table.py writes this file from tests/psl/public_suffix_list.dat.
 * Do not edit it. Run `make etld-table` after the list changes.
 *
 * List version: {version}
 * List commit:  {commit}
 *
 * The Public Suffix List is published by https://publicsuffix.org. It is subject to the
 * terms of the Mozilla Public License, v. 2.0. A copy of the license is at
 * https://mozilla.org/MPL/2.0/.
 *
 * etld_ruleText holds each rule, ended by a NUL byte. A label outside ASCII is written in
 * its xn-- form. etld_ruleOffsets holds the offset of each rule in etld_ruleText, in the
 * order strcmp sorts the rules.
 */

#include <stdint.h>  /* uint32_t */

#include "etld.h"
"""


HEADER_VALUES = {
    "VERSION": r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC",
    "COMMIT": r"[0-9a-f]{40}",
}


def read_header_value(text, name):
    """Return the value of the "// NAME: value" line of the list.

    The value must have the form HEADER_VALUES gives, or ValueError is raised.
    """
    match = re.search(r"^// " + name + r": (" + HEADER_VALUES[name] + r")$", text, re.MULTILINE)
    if match is None:
        raise ValueError("the list has no " + name + " line of the expected form")
    return match.group(1)


def ace_label(label):
    """Return the label in the form a DNS name carries."""
    if label == "*" or label.isascii():
        return label
    if label != label.lower():
        raise ValueError("label is not in lower case: " + label)
    return "xn--" + label.encode("punycode").decode("ascii")


def read_rules(text):
    """Return the sorted rules of the ICANN section of the list."""
    begin = text.index(ICANN_BEGIN)
    end = text.index(ICANN_END)
    rules = set()
    for line in text[begin:end].splitlines():
        line = line.strip()
        if line == "" or line.startswith("//"):
            continue
        word = line.split()[0]
        prefix = "!" if word.startswith("!") else ""
        labels = [ace_label(label) for label in word[len(prefix):].split(".")]
        for i, label in enumerate(labels):
            if label == "*" and i == 0 and prefix == "" and len(labels) > 1:
                continue
            if not LDH_LABEL.match(label):
                raise ValueError("rule has a label that is not LDH: " + word)
        rules.add(prefix + ".".join(labels))
    return sorted(rules, key=lambda rule: rule.encode("ascii"))


def write_table(rules, version, commit):
    """Return the text of src/etld_table.c."""
    lines = [HEADER.format(version=version, commit=commit)]
    lines.append("const char etld_ruleText[] =")
    for rule in rules:
        lines.append('  "' + rule + '\\0"')
    lines.append("  ;")
    lines.append("")
    lines.append("const uint32_t etld_ruleOffsets[] = {")
    offsets = []
    offset = 0
    for rule in rules:
        offsets.append(offset)
        offset += len(rule) + 1
    for start in range(0, len(offsets), 12):
        lines.append("  " + " ".join(str(value) + "," for value in offsets[start:start + 12]))
    lines.append("};")
    lines.append("")
    lines.append("const int etld_ruleCount = " + str(len(rules)) + ";")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) == 3 and argv[1] == "--rules":
        with open(argv[2], encoding="utf-8") as list_file:
            for rule in read_rules(list_file.read()):
                print(rule)
        return 0
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 1
    with open(argv[1], encoding="utf-8") as list_file:
        text = list_file.read()
    table = write_table(read_rules(text), read_header_value(text, "VERSION"), read_header_value(text, "COMMIT"))
    with open(argv[2], "w", encoding="utf-8", newline="\n") as table_file:
        table_file.write(table)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except ValueError as error:
        print("gen_etld_table: " + str(error), file=sys.stderr)
        sys.exit(1)
