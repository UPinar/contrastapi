"""Compare the terms each WHOIS server of src/external/whois_table.c sends with its snapshot.

Usage:
  python3 -I tests/whois_terms/check.py            ask each server, compare, exit 1 on a change
  python3 -I tests/whois_terms/check.py --write    ask each server, rewrite the snapshots

Each server is asked once about "nic.<tld>", for the first TLD the table lists for it, one
query per second. Only the terms lines of the answer are kept: comment lines, and lines with a
word such as "terms", "lawful" or "automated". A record line such as "Registrar: ..." is
dropped, and so is a line that changes with each query: the time of the last update, the
number of the server that answered (.am answers from #1 or #2 in turn), or a greeting that
names the asking address. tests/whois_terms/<host>.txt holds the kept lines of
the day the terms were read.
"""
import os
import re
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(HERE, "..", "..", "src", "external", "whois_table.c")
ANSWER_MAX_BYTE_COUNT = 65536
TIMEOUT_SECONDS = 15

ROW = re.compile(r'^\s*\{\s*"([a-z0-9-]+)",\s*"([a-z0-9.-]+)",', re.MULTILINE)
KEYWORDS = re.compile(
    r"(?i)\b(terms|conditions|purpose|purposes|prohibit|forbid|automated|high[- ]volume|"
    r"permitted|permission|agree|copyright|reproduc|marketing|unsolicited|spam|"
    r"data protection|privacy|gdpr|lawful|legal|abuse|acceptable use|not allowed|"
    r"may not|must not|shall not|restricted|only for|solely)\b")
NOISE = re.compile(r"(?i)(last update of whois database|>>>.*<<<|\d{4}-\d{2}-\d{2}t\d{2}:\d{2}|whois server #\d+)")
ASKER = re.compile(r"(?i)(your session has been logged|\b\d{1,3}(\.\d{1,3}){3}\b|\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}\b)")


def servers():
    """Return (host, first TLD) for each host of the table, in the table's order."""
    first_tld = {}
    with open(TABLE, encoding="utf-8") as table:
        for tld, host in ROW.findall(table.read()):
            first_tld.setdefault(host, tld)
    return list(first_tld.items())


def ask(host, name):
    """Send one query and read the answer until the server closes the connection."""
    data = b""
    with socket.create_connection((host, 43), timeout=TIMEOUT_SECONDS) as connection:
        connection.settimeout(TIMEOUT_SECONDS)
        connection.sendall(name.encode("ascii") + b"\r\n")
        while len(data) <= ANSWER_MAX_BYTE_COUNT:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode("utf-8", "replace")


def terms_of(text):
    """Keep the terms lines of an answer, without the lines that change with each query."""
    keep = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or ASKER.search(line):
            continue
        is_comment = line[:1] in "%#;"
        if NOISE.search(line) and not KEYWORDS.search(NOISE.sub("", line)):
            continue
        if is_comment or KEYWORDS.search(line):
            if re.match(r"^[A-Za-z][A-Za-z /]{0,40}:\s*\S", line) and not KEYWORDS.search(line.split(":", 1)[0]) and not is_comment:
                if not KEYWORDS.search(line.split(":", 1)[1]) or len(line) < 60:
                    continue
            keep.append(line.lstrip("%#; ").strip())
    return "".join(line + "\n" for line in keep if line)


def main():
    is_writing = sys.argv[1:] == ["--write"]
    changed = []
    for index, (host, tld) in enumerate(servers()):
        if index > 0:
            time.sleep(1)
        path = os.path.join(HERE, host + ".txt")
        try:
            terms = terms_of(ask(host, "nic." + tld))
        except OSError as error:
            print(f"FAIL: {host}: {error}")
            changed.append(host)
            continue
        if is_writing:
            with open(path, "w", encoding="utf-8") as snapshot:
                snapshot.write(terms)
            print(f"wrote {path}")
            continue
        try:
            with open(path, encoding="utf-8") as snapshot:
                kept = snapshot.read()
        except OSError:
            kept = None
        if terms != kept:
            print(f"FAIL: the terms of {host} differ from tests/whois_terms/{host}.txt")
            changed.append(host)
    if changed:
        print("Read the new terms. Then run this script with --write, or take the TLDs out of src/external/whois_table.c.")
        return 1
    print("PASS: the terms of each WHOIS server are the snapshot's")
    return 0


if __name__ == "__main__":
    sys.exit(main())
