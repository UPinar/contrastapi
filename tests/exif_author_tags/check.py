"""Compare the tag names of exiftool's Author group with AUTHOR_GROUP_TAGS.

Usage:
  exiftool -config "" -listx | python3 -I tests/exif_author_tags/check.py - tests/test_exifclient.c
  python3 -I tests/exif_author_tags/check.py <listx file> tests/test_exifclient.c

exiftool -listx prints every tag exiftool knows, as XML. Each table names its family 2
group, and a tag can name another one. The check reads the names whose group is Author.
AUTHOR_GROUP_TAGS in tests/test_exifclient.c holds one row for each of those names, with
the identifier kinds the name must mark. test_exifclient checks the kinds.
  - a name exiftool has and the table lacks needs a row, so the check fails;
  - a name the table has and exiftool lacks is a row to remove, so the check fails;
  - no Author name at all means the listing could not be read, so the check fails.

Exit status: 0 when the two sets of names are equal, 1 when they are not.
"""

import re
import sys

TABLE_RE = re.compile(r"<table name='([^']*)'[^>]*? g2='([^']*)'")
TAG_RE = re.compile(r"\s*<tag id='[^']*' name='([^']*)'([^>]*)>")
GROUP_RE = re.compile(r" g2='([^']*)'")
ROW_RE = re.compile(r'^\s*\{ "([^"]+)",')


def listx_author_names(lines):
    """Read the names of the tags whose family 2 group is Author."""
    names = set()
    table_group = None
    for line in lines:
        table = TABLE_RE.match(line)
        if table:
            table_group = table.group(2)
            continue
        tag = TAG_RE.match(line)
        if tag:
            group = GROUP_RE.search(tag.group(2))
            if (group.group(1) if group else table_group) == "Author":
                names.add(tag.group(1))
    return names


def table_names(test_path):
    """Read the names of AUTHOR_GROUP_TAGS, one row per line."""
    with open(test_path, encoding="utf-8") as test_file:
        text = test_file.read()
    start = text.index("AUTHOR_GROUP_TAGS[] = {\n")
    end = text.index("\n};\n", start)
    names = set()
    for line in text[start:end].split("\n")[1:]:
        row = ROW_RE.match(line)
        if row:
            names.add(row.group(1))
    return names


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    if sys.argv[1] == "-":
        exiftool_names = listx_author_names(sys.stdin)
    else:
        with open(sys.argv[1], encoding="utf-8") as listx:
            exiftool_names = listx_author_names(listx)
    pinned_names = table_names(sys.argv[2])

    if not exiftool_names:
        print("FAIL: the listing names no tag of the Author group")
        return 1
    added = sorted(exiftool_names - pinned_names)
    removed = sorted(pinned_names - exiftool_names)
    for name in added:
        print(f"FAIL: exiftool puts {name} in the Author group, and AUTHOR_GROUP_TAGS has no row for it")
    for name in removed:
        print(f"FAIL: AUTHOR_GROUP_TAGS has a row for {name}, and exiftool's Author group does not")
    if added or removed:
        return 1
    print(f"PASS: AUTHOR_GROUP_TAGS names the {len(exiftool_names)} tags of exiftool's Author group")
    return 0


if __name__ == "__main__":
    sys.exit(main())
