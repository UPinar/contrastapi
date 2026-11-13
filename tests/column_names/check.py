"""Compare each column list of src/ with the api function its query names.

Usage:
  python3 -I tests/column_names/check.py <src dir> <sql dir>

Each reader of src/ (db.c, db_watchlist.c, ratelimit.c, quota.c, cache.c, throttle.c,
cve_exploit.c, x402_ledger.c) sends one query literal per call, and checks the answer's column names with
dbhelper_isColumnListEqual against a <LIST>_COLUMN_NAMES array before it reads a column by
its index. This check reads both sides from the text and refuses a tree where they differ:
  - a call that sends SELECT * FROM api.fn_x(...) names a function that answers a table, and
    the C list equals its RETURNS TABLE: the same names, in the same order, no more, no less;
  - a call that sends SELECT api.fn_x(...) AS <name> names a function that answers one value,
    the C side checks one name, and it is <name>;
  - each column is read by a reader whose type set holds the column's SQL type: a Str reader
    takes text, date, timestamptz and bigint; a Double reader real and double precision; an Int
    reader integer and smallint, and bigint only for the count columns BIGINT_COUNTS names; an
    Int64 reader bigint; a Bool reader boolean; a Strdup reader text and jsonb; jsonread_root,
    which parses the cell in C, jsonb;
  - a Strdup column that serialize.c embeds through jsonbuf_appendJsonText is jsonb, and one
    it escapes through jsonbuf_appendEscaped, or never writes as it is, is text. The chain
    is read from the code, and compared with the three lists STRDUP_RAW_JSON, STRDUP_ESCAPED
    and STRDUP_UNUSED, so a new Strdup column fails until it is listed.
The C side is read after the preprocessor (gcc -E -P), so comments and #if 0 are gone and
the X-macro lists stand as one enum and one array. The SQL side is the files sql/api.sql
loads with \\ir, with their -- comments removed. Every query literal must be classified
(the number of api.fn_ calls in the text equals the number of classified calls), every
function a call names must exist, every list must be used, and every column must be read
by a known reader or stand in UNREAD_COLUMNS. Anything else fails, so a new pattern fails
until this check learns it.

Exit status: 0 when every call, column and type agrees, 1 otherwise. The PASS line counts
the calls, functions, lists and columns it compared.
"""

import os
import re
import subprocess
import sys

C_FILES = ["db.c", "db_watchlist.c", "ratelimit.c", "quota.c", "cache.c", "throttle.c",
           "cve_exploit.c", "x402_ledger.c"]

STR_TYPES = {"text", "date", "timestamptz", "bigint"}
READER_TYPES = {
    "dbhelper_fetchColStr": STR_TYPES,
    "dbhelper_fetchColDouble": {"real", "double precision"},
    "dbhelper_fetchColInt": {"integer", "smallint"},
    "dbhelper_fetchColInt64": {"bigint"},
    "dbhelper_fetchColBool": {"boolean"},
    "dbhelper_fetchColStrdup": {"text", "jsonb"},
    "static_tryReadTextOrEmpty": STR_TYPES,
    "static_tryReadNumberOrUnset": {"real", "double precision"},
    "strcmp": {"boolean"},
    "strtoul": {"integer", "bigint"},
    "jsonread_root": {"jsonb"},
}
LENGTH_READER = "dbhelper_isColWithinLength"
INT_READERS = {"dbhelper_fetchColInt", "strtoul"}
PAGE_READER_RE = re.compile(r"^static_\w+ReadPage$")
SCALAR_HELPERS = {"static_tryReadMatchCount", "dbhelper_runPurgeLoopFrom"}
STATUS_TEXT_COLUMNS = {"WATCHLISTEDIT_COLUMN_EDIT_STATUS", "WATCHLISTEDIT_CVE_ID_COLUMN_EDIT_STATUS",
                       "WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_EDIT_STATUS", "WATCHLISTEDIT_CVE_SEARCH_COLUMN_EDIT_STATUS",
                       "WATCHLISTEDIT_DOMAIN_COLUMN_EDIT_STATUS", "WATCHLISTEDIT_PACKAGE_COLUMN_EDIT_STATUS",
                       "WATCHLISTEDIT_IP_COLUMN_EDIT_STATUS", "WATCHLISTEDIT_PACKAGE_LIST_COLUMN_EDIT_STATUS",
                       "WATCHLISTEVENTS_COLUMN_EVENTS_STATUS"}
SHIFTED_ITEM_COLUMNS = ("WATCHLISTEVENTS", "item_", "WATCHLISTEDIT")
UNREAD_COLUMNS = {("CVETRIAGE", "epss_score"), ("CVETRIAGE", "cvss_v3")}
BIGINT_COUNTS = {
    ("fn_health", "cve_count"), ("fn_health", "kev_count"), ("fn_health", "cwe_count"),
    ("fn_cwe_lookup", "kev_cve_count"), ("fn_cwe_lookup", "cve_count"),
    ("fn_product_exposure", "cve_count"), ("fn_product_exposure", "critical_count"),
    ("fn_product_exposure", "high_count"), ("fn_product_exposure", "medium_count"),
    ("fn_product_exposure", "low_count"), ("fn_product_exposure", "kev_count"),
    ("fn_product_exposure", "poc_backed_count"),
    ("fn_cve_exploit_metasploit_summary", "metasploit_module_count"),
    ("fn_cve_exploit_github_summary", "github_repo_count"),
    ("fn_cve_exploit_exploitdb_summary", "exploitdb_entry_count"),
    ("fn_cve_search_match_count", "cve_count"), ("fn_cve_leading_match_count", "cve_count"),
    ("fn_cve_triage_match_count", "cve_count"), ("fn_cpe_search_match_count", "product_count"),
}
STRDUP_RAW_JSON = {
    ("CPESEARCH", "product_named_by"),
    ("CVELOOKUP", "cwes"), ("CVELOOKUP", "affected_products"), ("CVELOOKUP", "refs"),
    ("CVELOOKUP", "epss_trend"), ("CVELOOKUP", "cve_tags"), ("CVELOOKUP", "nuclei_templates"),
    ("CVELOOKUP", "product_count_by_vendor"), ("CVEPRODUCTS", "affected_products"),
    ("CVELOOKUPGHSA", "advisory"),
    ("KEVLOOKUP", "cwes"), ("CWELOOKUP", "mitigations"), ("CWELOOKUP", "examples"),
    ("D3FENDFORATTACK", "parent_defense_labels"), ("D3FENDFORATTACK", "attack_technique_ids"),
    ("D3FENDFORATTACK", "attack_techniques"), ("DRIVERLOOKUP", "matches"), ("IPLOOKUP", "listed_on"),
    ("ASNLOOKUP", "ipv4_prefixes"), ("ASNLOOKUP", "ipv6_prefixes"),
    ("PACKAGECHECK", "malicious"), ("PACKAGECHECK", "results"), ("PACKAGECHECK", "attribution"),
    ("PACKAGECHECKBULK", "results"), ("PACKAGECHECKBULK", "attribution"),
    ("WATCHLISTEVENTS", "advisory_aliases"), ("WATCHLISTEVENTS", "attribution"),
}
STRDUP_ESCAPED = {
    ("KEVLOOKUP", "notes"), ("CWELOOKUP", "extended_description"),
    ("WATCHLISTEVENTS", "previous_domain_value"), ("WATCHLISTEVENTS", "current_domain_value"),
    ("WATCHLISTEVENTS", "previous_ip_value"), ("WATCHLISTEVENTS", "current_ip_value"),
}
STRDUP_UNUSED = {
    ("CACHE_GET", "body"),
    ("WATCHLISTEVENTS", "dns_presence_value"), ("WATCHLISTEVENTS", "ns_value"),
    ("WATCHLISTEVENTS", "mx_value"), ("WATCHLISTEVENTS", "ip_address_reachability_value"),
    ("WATCHLISTEVENTS", "cname_takeover_value"), ("WATCHLISTEVENTS", "email_auth_value"),
}

TYPE_SYNONYMS = {"int": "integer", "int4": "integer", "int8": "bigint", "float4": "real",
                 "float8": "double precision", "bool": "boolean",
                 "timestamp with time zone": "timestamptz"}
KNOWN_TYPES = {"text", "boolean", "real", "bigint", "double precision", "integer", "smallint",
               "jsonb", "date", "timestamptz", "numeric", "text[]", "bigint[]", "boolean[]"}
RETURNS_END = re.compile(r"\s+(LANGUAGE|AS|SET|STABLE|IMMUTABLE|VOLATILE|STRICT|SECURITY|RETURN|BEGIN|CALLED|PARALLEL)\b")

LIST_RE = re.compile(r"enum \{ ((?:\w+, )+)\}; static const char\* const (\w+)_COLUMN_NAMES\[\] = \{ ((?:\"[^\"]*\", )+)\};")
FUNCTION_RE = re.compile(r"\b(\w+)\s*\(([^(){};]*)\)\s*\{")
KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof"}
EXEC_RE = re.compile(r"dbhelper_executeQueryFrom\(__func__, \(\w+\), \((\"(?:[^\"\\]|\\.)*\"|[^()]*)\)")
PURGE_RE = re.compile(r"dbhelper_runPurgeLoopFrom\(__func__, \(\w+\), \(\"([^\"]*)\"\), \(\"(\w+)\"\)")
MATCH_RE = re.compile(r"static_tryReadMatchCount\(\w+, \"([^\"]*)\", \"(\w+)\"")
PAGE_RE = re.compile(r"(static_\w+ReadPage)\(\w+, \"([^\"]*)\"")
CHECK_RE = re.compile(r"dbhelper_isColumnListEqual\(res, (\w+)_COLUMN_NAMES")
FN_RE = re.compile(r"api\.(fn_\w+)\s*\(")
AS_RE = re.compile(r"\sAS (\w+)\s*$")
READ_RE = re.compile(r"\b(dbhelper_fetchCol\w+|dbhelper_isColWithinLength|static_tryReadTextOrEmpty|static_tryReadNumberOrUnset)\s*\(\s*res\s*,\s*\w+\s*,\s*(\w+_COLUMN_\w+)")
PQGETVALUE_RE = re.compile(r"\b(\w+)\(PQgetvalue\(res, \w+, (\w+_COLUMN_\w+)\)")
STRDUP_FIELD_RE = re.compile(r"dbhelper_fetchColStrdup\s*\(res, \w+, (\w+_COLUMN_\w+), &\w+->(mp_\w+)\)")
RAW_FIELD_RE = re.compile(r"jsonbuf_appendJsonText\(\w+, \(*\s*\w+->(mp_\w+)")
ESCAPED_FIELD_RE = re.compile(r"jsonbuf_appendEscaped\(\w+, \(*\s*\w+->(mp_\w+)")


class Check:
    def __init__(self):
        self.failures = []

    def fail(self, message):
        self.failures.append("FAIL: " + message)


def preprocess(src_dir, name):
    """The file after gcc -E -P, with every run of white space folded to one space."""
    cflags = subprocess.run(["pkg-config", "--cflags", "libpq"], capture_output=True, text=True, check=True).stdout.split()
    run = subprocess.run(["gcc", "-E", "-P", "-I" + src_dir] + cflags + [os.path.join(src_dir, name)],
                         capture_output=True, text=True, check=True)
    return re.sub(r"\s+", " ", run.stdout)


def brace_pairs(text):
    """The (open, close) offsets of each top-level brace pair, skipping string and char
    literals. A text whose braces do not balance answers an empty list."""
    pairs = []
    depth = 0
    open_at = None
    i = 0
    while i < len(text):
        c = text[i]
        if c in "\"'":
            quote = c
            i += 1
            while i < len(text) and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
        elif c == "{":
            if depth == 0:
                open_at = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and open_at is not None:
                pairs.append((open_at, i))
                open_at = None
            if depth < 0:
                return []
        i += 1
    return pairs if depth == 0 else []


def function_bodies(text, check, name):
    """name -> body text of each function definition at the top level."""
    pairs = brace_pairs(text)
    if not pairs:
        check.fail(f"{name}: no function body found, or the braces of the preprocessed text do not balance")
        return {}
    opens = {open_at: close for open_at, close in pairs}
    bodies = {}
    for match in FUNCTION_RE.finditer(text):
        open_at = match.end() - 1
        if open_at in opens and match.group(1) not in KEYWORDS:
            bodies[match.group(1)] = text[open_at:opens[open_at] + 1]
    return bodies


def read_lists(text, lists, check, name):
    for match in LIST_RE.finditer(text):
        enums = match.group(1).rstrip(", ").split(", ")
        columns = [n.strip('"') for n in match.group(3).rstrip(", ").split(", ")]
        list_name = match.group(2)
        if len(enums) != len(columns):
            check.fail(f"{name}: list {list_name} has {len(enums)} indexes and {len(columns)} names")
        if list_name in lists:
            check.fail(f"{name}: list {list_name} is defined twice")
        lists[list_name] = list(zip(enums, columns))


def query_shape(literal, check, where):
    """('table' | 'scalar', function name, AS name or None), or None when the literal is
    not one of the two shapes STYLE.md allows."""
    functions = FN_RE.findall(literal)
    if len(functions) != 1:
        check.fail(f"{where}: the query names {len(functions)} api functions: {literal}")
        return None
    as_name = AS_RE.search(literal)
    if literal.startswith("SELECT * FROM api.") and not as_name:
        return "table", functions[0], None
    if literal.startswith("SELECT api.") and as_name:
        return "scalar", functions[0], as_name.group(1)
    check.fail(f"{where}: the query is neither SELECT * FROM api.fn_x(...) nor SELECT api.fn_x(...) AS name: {literal}")
    return None


def read_calls(bodies, lists, check, name, page_lists):
    """One record per query literal: shape, function, the list it is checked against."""
    calls = []
    for body_name, body in bodies.items():
        where = f"{name}:{body_name}"
        checks = CHECK_RE.findall(body)
        if PAGE_READER_RE.match(body_name) or body_name in SCALAR_HELPERS:
            if PAGE_READER_RE.match(body_name):
                if len(checks) != 1:
                    check.fail(f"{where}: a page reader must check one list, it checks {len(checks)}")
                else:
                    page_lists[body_name] = checks[0]
            continue
        literals = []
        for match in EXEC_RE.finditer(body):
            argument = match.group(1)
            if not (argument.startswith('"') and argument.endswith('"')):
                check.fail(f"{where}: a query that is not a literal: {argument}")
                continue
            literals.append(argument.strip('"'))
        if len(literals) != len(checks):
            check.fail(f"{where}: {len(literals)} query literals and {len(checks)} list checks")
            continue
        for literal, list_name in zip(literals, checks):
            shape = query_shape(literal, check, where)
            if shape:
                calls.append({"where": where, "shape": shape[0], "fn": shape[1], "as": shape[2], "list": list_name, "argument": None})
        for literal, column in PURGE_RE.findall(body) + MATCH_RE.findall(body):
            shape = query_shape(literal, check, where)
            if shape:
                calls.append({"where": where, "shape": shape[0], "fn": shape[1], "as": shape[2], "list": None, "argument": column})
        for reader, literal in PAGE_RE.findall(body):
            shape = query_shape(literal, check, where)
            if shape:
                calls.append({"where": where, "shape": shape[0], "fn": shape[1], "as": shape[2], "list": ("page", reader), "argument": None})
    return calls


def read_readers(text, readers, check, name):
    """enum constant -> set of reader names, over the whole preprocessed file."""
    for reader, enum in READ_RE.findall(text):
        if reader not in READER_TYPES and reader != LENGTH_READER:
            check.fail(f"{name}: unknown reader {reader} of {enum}")
        readers.setdefault(enum, set()).add(reader)
    for reader, enum in PQGETVALUE_RE.findall(text):
        if reader not in READER_TYPES:
            check.fail(f"{name}: unknown PQgetvalue reader {reader} of {enum}")
        readers.setdefault(enum, set()).add(reader)


def copy_shifted_readers(lists, readers, check):
    """Give each shifted item column the readers of its twin, by SHIFTED_ITEM_COLUMNS."""
    shifted_list, prefix, twin_list = SHIFTED_ITEM_COLUMNS
    if shifted_list not in lists or twin_list not in lists:
        check.fail(f"SHIFTED_ITEM_COLUMNS names {shifted_list} and {twin_list}, and a list is not defined")
        return
    twins = {column: enum for enum, column in lists[twin_list]}
    for enum, column in lists[shifted_list]:
        if not column.startswith(prefix) or column[len(prefix):] not in twins:
            continue
        twin_readers = readers.get(twins[column[len(prefix):]], set())
        if not twin_readers:
            check.fail(f"{shifted_list}.{column} takes the readers of {twin_list}.{column[len(prefix):]}, which has none")
        readers.setdefault(enum, set()).update(twin_readers)


def strip_sql_comments(text):
    return "\n".join(line.split("--", 1)[0] for line in text.split("\n"))


def matching_paren(text, open_at):
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def normalize_type(raw, check, where):
    kind = re.sub(r"\s+", " ", raw.strip().lower())
    kind = TYPE_SYNONYMS.get(kind, kind)
    if kind not in KNOWN_TYPES:
        check.fail(f"{where}: unknown SQL type '{raw.strip()}'")
    return kind


def read_sql(sql_dir, check):
    """function name -> ('table', [(column, type)]) or ('scalar', type)."""
    functions = {}
    with open(os.path.join(sql_dir, "api.sql"), encoding="utf-8") as api:
        files = re.findall(r"^\\ir (fn_\w+\.sql)$", api.read(), re.M)
    if not files:
        check.fail("sql/api.sql loads no fn_*.sql file")
    for file_name in files:
        with open(os.path.join(sql_dir, file_name), encoding="utf-8") as sql_file:
            text = re.sub(r"\s+", " ", strip_sql_comments(sql_file.read()))
        for match in re.finditer(r"CREATE FUNCTION api\.(fn_\w+)\s*\(", text):
            fn = match.group(1)
            where = f"{file_name}:{fn}"
            params_end = matching_paren(text, match.end() - 1)
            rest = text[params_end + 1:].lstrip()
            if not rest.startswith("RETURNS "):
                check.fail(f"{where}: no RETURNS after the parameters")
                continue
            rest = rest[len("RETURNS "):]
            if fn in functions:
                check.fail(f"{where}: defined twice")
            if rest.startswith("TABLE"):
                open_at = rest.index("(")
                close_at = matching_paren(rest, open_at)
                columns = []
                for item in re.split(r",(?![^()]*\))", rest[open_at + 1:close_at]):
                    parts = item.strip().split(None, 1)
                    if len(parts) != 2:
                        check.fail(f"{where}: a RETURNS TABLE entry without a name and a type: '{item.strip()}'")
                        continue
                    columns.append((parts[0], normalize_type(parts[1], check, where)))
                functions[fn] = ("table", columns)
            else:
                end = RETURNS_END.search(rest)
                if not end:
                    check.fail(f"{where}: the scalar RETURNS type has no end")
                    continue
                functions[fn] = ("scalar", normalize_type(rest[:end.start()], check, where))
    return functions


def check_column(check, where, fn, list_name, column, sql_type, readers):
    """The type of one column against each of its readers, and the jsonb rule for Strdup."""
    for reader in readers:
        if reader == LENGTH_READER:
            continue
        allowed = READER_TYPES[reader]
        if sql_type in allowed:
            continue
        if sql_type == "bigint" and reader in INT_READERS and (fn, column) in BIGINT_COUNTS:
            continue
        check.fail(f"{where}: {list_name}.{column} is {sql_type} in {fn}, and {reader} reads {sorted(allowed)}")
    if "dbhelper_fetchColStrdup" in readers:
        key = (list_name, column)
        memberships = [key in STRDUP_RAW_JSON, key in STRDUP_ESCAPED, key in STRDUP_UNUSED]
        if sum(memberships) != 1:
            check.fail(f"{where}: {list_name}.{column} is read with Strdup and stands in {sum(memberships)} of the three Strdup lists")
        elif memberships[0] and sql_type != "jsonb":
            check.fail(f"{where}: {list_name}.{column} is embedded as raw JSON, so it must be jsonb, not {sql_type}")
        elif not memberships[0] and sql_type != "text":
            check.fail(f"{where}: {list_name}.{column} is escaped or unused, so it must be text, not {sql_type}")


def check_serialize_chain(src_dir, lists, check):
    """Strdup field -> what serialize.c does with it, against the three lists."""
    text = "".join(preprocess(src_dir, name) for name in C_FILES)
    serialize = preprocess(src_dir, "serialize.c")
    raw_fields = set(RAW_FIELD_RE.findall(serialize))
    escaped_fields = set(ESCAPED_FIELD_RE.findall(serialize))
    enum_to_key = {enum: (list_name, column) for list_name, entries in lists.items() for enum, column in entries}
    seen = set()
    for enum, field in STRDUP_FIELD_RE.findall(text):
        key = enum_to_key.get(enum)
        if key is None:
            check.fail(f"Strdup reads {enum}, which no list defines")
            continue
        seen.add(key)
        in_raw, in_escaped = field in raw_fields, field in escaped_fields
        if in_raw and in_escaped:
            check.fail(f"{key[0]}.{key[1]} ({field}) is both embedded raw and escaped in serialize.c")
        derived = "raw" if in_raw else "escaped" if in_escaped else "unused"
        listed = "raw" if key in STRDUP_RAW_JSON else "escaped" if key in STRDUP_ESCAPED else "unused" if key in STRDUP_UNUSED else None
        if listed != derived:
            check.fail(f"{key[0]}.{key[1]} ({field}) is {derived} in serialize.c and listed as {listed}")
    for key in (STRDUP_RAW_JSON | STRDUP_ESCAPED | STRDUP_UNUSED) - seen:
        check.fail(f"{key[0]}.{key[1]} is listed as a Strdup column, and no Strdup call reads it")
    return len(seen)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src_dir, sql_dir = sys.argv[1], sys.argv[2]
    check = Check()
    lists, readers, calls, page_lists = {}, {}, [], {}
    literal_count = 0
    for name in C_FILES:
        text = preprocess(src_dir, name)
        read_lists(text, lists, check, name)
        read_readers(text, readers, check, name)
        literal_count += len(FN_RE.findall(text))
        calls += read_calls(function_bodies(text, check, name), lists, check, name, page_lists)
    copy_shifted_readers(lists, readers, check)
    if literal_count != len(calls):
        check.fail(f"{literal_count} api.fn_ calls in the text, {len(calls)} classified")
    if not calls:
        check.fail("no query found")
    functions = read_sql(sql_dir, check)

    used_lists = set()
    for call in calls:
        where, fn = call["where"], call["fn"]
        if fn not in functions:
            check.fail(f"{where}: sql/ defines no api.{fn}")
            continue
        sql_shape, sql_body = functions[fn]
        if call["list"] is None:
            c_names = [call["argument"]]
            c_enums = [None]
        else:
            list_name = call["list"][1] if isinstance(call["list"], tuple) else call["list"]
            if isinstance(call["list"], tuple):
                list_name = page_lists.get(list_name)
                if list_name is None:
                    check.fail(f"{where}: page reader {call['list'][1]} has no list")
                    continue
            if list_name not in lists:
                check.fail(f"{where}: list {list_name} is not defined")
                continue
            used_lists.add(list_name)
            c_enums = [enum for enum, _ in lists[list_name]]
            c_names = [column for _, column in lists[list_name]]
        if call["shape"] == "scalar":
            if sql_shape != "scalar":
                check.fail(f"{where}: {fn} is called with AS and answers a table")
                continue
            if c_names != [call["as"]]:
                check.fail(f"{where}: the call names AS {call['as']} and the C side checks {c_names}")
                continue
            column_readers = readers.get(c_enums[0], set()) if c_enums[0] else {"dbhelper_fetchColInt"}
            check_column(check, where, fn, call["list"] or "argument", c_names[0], sql_body, column_readers)
            continue
        if sql_shape != "table":
            check.fail(f"{where}: {fn} is called with SELECT * and answers one value")
            continue
        sql_names = [column for column, _ in sql_body]
        if c_names != sql_names:
            check.fail(f"{where}: C checks {c_names}, {fn} answers {sql_names}")
            continue
        for enum, (column, sql_type) in zip(c_enums, sql_body):
            column_readers = readers.get(enum, set())
            if enum in STATUS_TEXT_COLUMNS:
                column_readers = column_readers | {"dbhelper_fetchColStr"}
            if not column_readers:
                if (list_name, column) not in UNREAD_COLUMNS:
                    check.fail(f"{where}: {list_name}.{column} ({enum}) is read by no known reader and not listed in UNREAD_COLUMNS")
                continue
            check_column(check, where, fn, list_name, column, sql_type, column_readers)
    for list_name in sorted(set(lists) - used_lists):
        check.fail(f"list {list_name} is checked by no call")
    for key in UNREAD_COLUMNS:
        if key[0] in lists and any(readers.get(enum) for enum, column in lists[key[0]] if column == key[1]):
            check.fail(f"{key[0]}.{key[1]} is listed in UNREAD_COLUMNS and a reader reads it")
    strdup_count = check_serialize_chain(src_dir, lists, check)

    for line in check.failures:
        print(line)
    if check.failures:
        return 1
    column_count = sum(len(entries) for entries in lists.values())
    print(f"PASS: {len(calls)} calls name {len({c['fn'] for c in calls})} api functions; "
          f"{len(lists)} lists with {column_count} columns match sql/, {strdup_count} Strdup columns follow the jsonb rule")
    return 0


if __name__ == "__main__":
    sys.exit(main())
