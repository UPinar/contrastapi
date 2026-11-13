"""Compare the role lists of sql/grants.sql with the functions the code calls.

Usage:
  python3 -I tests/grants/check.py <src dir> <sql dir> [<store.go path>]

sql/grants.sql gives each login role EXECUTE on the functions of one text[] array and on no
table. A function the code calls and the array lacks fails at run time with a permission
error. A function the array lists and no code calls is a grant nobody needs. This check reads
both sides as text, so it needs no database, and refuses a tree where they differ:
  - The api.fn_ names inside the string literals of <src>/**/*.c equal api_role_functions.
    Comments are taken out first, so a name in a comment does not count. Adjacent literals
    are joined, as the compiler joins them.
  - Only when a store.go path is given: the api. names inside the Go string literals equal
    the api. names of web_role_functions. The web. names the Go code calls are not compared:
    the Go repository registers them in role_function_grant, and grants.sql checks them at
    apply.
  - Each name of api_role_functions and web_role_functions has a CREATE FUNCTION in
    <sql>/*.sql or in schema.sql, the file beside <sql>.
A CREATE FUNCTION name is read as PostgreSQL reads it. An unquoted part folds to lower case.
A quoted part keeps its case. A name without a schema is a name of public, the schema of the
default search_path. A CREATE inside a -- or a /* */ comment does not count.

Each array is read from grants.sql by its variable name. The value may be given where the
variable is declared or in a later assignment. A declaration with the value '{}' and no
ARRAY[...] assignment reads as an empty array. A missing array, an empty one, an entry that
is not a schema-qualified fn_ name and a name listed twice all fail.

Exit status: 0 when every list matches, 1 when one differs, 2 on a wrong argument count.
Each failure names the array or the file, and where it can the function and the side that
differs. The PASS line counts the names of each array.
"""

import glob
import os
import re
import sys

USAGE = "usage: python3 -I tests/grants/check.py <src dir> <sql dir> [<store.go path>]"
ARRAY_NAMES = ("api_role_functions", "web_role_functions")
ENTRY_RE = re.compile(r"^(api|web)\.fn_[a-z0-9_]+$")
C_NAME_RE = re.compile(r"\bapi\.fn_[a-z0-9_]+")
IDENTIFIER_PATTERN = r'"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*'
CREATE_RE = re.compile(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(" + IDENTIFIER_PATTERN + r")(?:\s*\.\s*(" + IDENTIFIER_PATTERN + r"))?\s*\(",
                       re.IGNORECASE)
DOLLAR_TAG_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
IDENTIFIER_CHAR_RE = re.compile(r"[A-Za-z0-9_$]")


def read_text(path):
    with open(path, encoding="utf-8") as text_file:
        return text_file.read()


def string_literals(text, quotes):
    """The string literals of C or Go text, with comments skipped.

    quotes holds the characters that open a literal with backslash escapes. A backtick opens
    a Go raw literal, which ends at the next backtick. Literals separated only by white space
    come back joined, as C joins them. A literal that does not end stops the scan."""
    literals = []
    last_end = -1
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = length if end < 0 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = length if end < 0 else end + 2
            continue
        if ch == "`" and "`" in quotes:
            end = text.find("`", i + 1)
            if end < 0:
                break
            body = text[i + 1:end]
        elif ch in quotes or ch == "'":
            j = i + 1
            while j < length and text[j] != ch and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            if j >= length or text[j] != ch:
                break
            end = j
            if ch == "'":
                i = end + 1
                continue
            body = text[i + 1:end]
        else:
            i += 1
            continue
        if literals and last_end >= 0 and text[last_end:i].strip() == "":
            literals[-1] += body
        else:
            literals.append(body)
        last_end = end + 1
        i = end + 1
    return literals


def strip_sql_comments(text):
    """text without its -- comments and its /* */ comments.

    A /* */ comment may nest, as in PostgreSQL. Each line break of a comment stays, so a
    line number keeps its meaning. A quoted literal, an E'' literal and a quoted identifier
    stay whole, so a -- or a /* inside one is text. A dollar-quoted body is read on its own:
    a quote or a /* that it leaves open ends at its closing tag, as PostgreSQL reads it."""
    kept = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("--", i):
            end = text.find("\n", i)
            i = length if end < 0 else end
            continue
        if text.startswith("/*", i):
            depth = 0
            j = i
            while j < length:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            kept.append(" " + "\n" * text.count("\n", i, j))
            i = j
            continue
        follows_name = i > 0 and IDENTIFIER_CHAR_RE.match(text[i - 1])
        tag = None if follows_name else DOLLAR_TAG_RE.match(text, i)
        if tag:
            close = text.find(tag.group(0), tag.end())
            body_end = length if close < 0 else close
            kept.append(tag.group(0) + strip_sql_comments(text[tag.end():body_end]))
            if close >= 0:
                kept.append(tag.group(0))
            i = body_end + (len(tag.group(0)) if close >= 0 else 0)
            continue
        if text[i] in "Ee" and text.startswith("'", i + 1) and not follows_name:
            end = i + 2
            while end < length and (text[end] != "'" or text.startswith("''", end)):
                end += 2 if text[end] == "\\" or text.startswith("''", end) else 1
            kept.append(text[i:end + 1])
            i = end + 1
            continue
        if text[i] in "'\"":
            quote = text[i]
            end = i + 1
            while end < length and not (text[end] == quote and not text.startswith(quote * 2, end)):
                end += 2 if text.startswith(quote * 2, end) else 1
            kept.append(text[i:end + 1])
            i = end + 1
            continue
        kept.append(text[i])
        i += 1
    return "".join(kept)


def identifier(part):
    """The name PostgreSQL gives an identifier: a quoted one keeps its case, others fold."""
    if part.startswith('"'):
        return part[1:-1].replace('""', '"')
    return part.lower()


def created_names(text):
    """The schema-qualified name of each CREATE FUNCTION of SQL text, comments taken out."""
    names = []
    for first, second in CREATE_RE.findall(strip_sql_comments(text)):
        if second:
            names.append(identifier(first) + "." + identifier(second))
        else:
            names.append("public." + identifier(first))
    return names


def read_arrays(grants_path, array_names, failures):
    """{array name: list of names} for each array of array_names found in grants.sql."""
    text = strip_sql_comments(read_text(grants_path))
    arrays = {}
    for array_name in array_names:
        found = re.search(r"\b" + array_name + r"\s+(?:text\[\]\s*)?:=\s*ARRAY\[(.*?)\];", text, re.DOTALL)
        if found:
            body = found.group(1)
        elif re.search(r"\b" + array_name + r"\s+text\[\]\s*:=\s*'\{\}'\s*;", text):
            body = ""
        else:
            failures.append(f"grants.sql has no array {array_name}")
            continue
        names = re.findall(r"'([^']*)'", body)
        if re.sub(r"'[^']*'|[\s,]", "", body):
            failures.append(f"grants.sql {array_name} holds text that is not a quoted name")
        if not names:
            failures.append(f"grants.sql {array_name} is empty")
        seen = set()
        for name in names:
            if not ENTRY_RE.match(name):
                failures.append(f"grants.sql {array_name} lists {name}, which is not a schema-qualified fn_ name")
            if name in seen:
                failures.append(f"grants.sql {array_name} lists {name} twice")
            seen.add(name)
        arrays[array_name] = names
    return arrays


def c_calls(src_dir):
    """{api.fn_ name: the first .c file whose literals name it}, and the count of .c files."""
    calls = {}
    paths = sorted(glob.glob(os.path.join(src_dir, "**", "*.c"), recursive=True))
    for path in paths:
        for literal in string_literals(read_text(path), '"'):
            for name in C_NAME_RE.findall(literal):
                calls.setdefault(name, path)
    return calls, len(paths)


def function_files(paths, root):
    """{schema-qualified name: [file]} for each CREATE FUNCTION in the files of paths.

    file is named relative to root. A path that does not exist is skipped."""
    files = {}
    for path in paths:
        if os.path.exists(path):
            for name in created_names(read_text(path)):
                files.setdefault(name, []).append(os.path.relpath(path, root))
    return files


def compare(failures, array_name, listed, called, called_by, not_called_by):
    """Fail each name of called that listed lacks, and each name of listed that called lacks."""
    for name in sorted(set(called) - set(listed)):
        failures.append(f"grants.sql {array_name} lacks {name}, which {called_by(name)}")
    for name in sorted(set(listed) - set(called)):
        failures.append(f"grants.sql {array_name} lists {name}, which {not_called_by}")


def main():
    if len(sys.argv) < 3:
        print(USAGE)
        return 2
    src_dir, sql_dir = sys.argv[1:3]
    optional_args = sys.argv[3:]
    if len(optional_args) > 1:
        print(USAGE)
        return 2
    go_path = optional_args[0] if optional_args else None
    failures = []

    grants_path = os.path.join(sql_dir, "grants.sql")
    arrays = read_arrays(grants_path, ARRAY_NAMES, failures)
    api_list = arrays.get("api_role_functions", [])
    web_list = arrays.get("web_role_functions", [])

    calls, c_file_count = c_calls(src_dir)
    if c_file_count == 0:
        failures.append(f"{src_dir} holds no .c file")
    compare(failures, "api_role_functions", api_list, calls,
            lambda name: f"{calls[name]} calls", "no C literal names")

    if go_path is not None:
        go_names = set()
        for literal in string_literals(read_text(go_path), '"`'):
            go_names.update(C_NAME_RE.findall(literal))
        for name in sorted(go_names - set(web_list)):
            failures.append(f"grants.sql web_role_functions lacks {name}, which {go_path} calls")
        for name in sorted(name for name in web_list if name.startswith("api.") and name not in go_names):
            failures.append(f"grants.sql web_role_functions lists {name}, which {go_path} does not call")

    root = os.path.join(sql_dir, os.pardir)
    defined = function_files(sorted(glob.glob(os.path.join(sql_dir, "*.sql"))) + [os.path.join(root, "schema.sql")], root)
    definition_files = "sql/*.sql or schema.sql"
    for array_name in ARRAY_NAMES:
        for name in arrays.get(array_name, []):
            if name not in defined:
                failures.append(f"grants.sql {array_name} lists {name}, which no CREATE FUNCTION of {definition_files} defines")

    for line in failures:
        print("FAIL: " + line)
    if failures:
        return 1
    counts = f"api {len(api_list)}, web {len(web_list)}"
    print(f"PASS: grant lists match: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
