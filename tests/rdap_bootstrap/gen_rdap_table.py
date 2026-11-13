"""Write src/external/rdap_table.c from IANA's RDAP bootstrap file for domain names.

Usage:
  python3 -I tests/rdap_bootstrap/gen_rdap_table.py <dns.json> <table.c>
  python3 -I tests/rdap_bootstrap/gen_rdap_table.py --servers <dns.json>

tests/rdap_bootstrap/dns.json holds a copy of https://data.iana.org/rdap/dns.json.
`make rdap-table` runs the first form on that copy. CI runs it again and fails when
src/external/rdap_table.c differs from what it writes. The weekly rdap_bootstrap workflow
runs the second form on the copy and on a fresh download, and compares the two lists.

RFC 9224 gives the form of the file. Its "services" member is a list of services. Each
service is a list of two lists: the TLDs it serves, and the base URLs of its RDAP server.

The table takes one base URL for each TLD: the first one that starts with "https://".
rdap.c sends a trusted request, and http_GETWithOptions sends a trusted request over HTTPS
only. So a TLD whose server has only an "http://" URL is left out, and rdap.c answers it as
a TLD without a server. A base URL must end with "/", because rdap.c appends
"domain/<name>" to it.

A TLD must be one LDH label in lower case. A TLD of more than one label would need a
longest-suffix match, and rdap.c matches the last label of a name only. A TLD must appear in
one service only.

The table quotes the "publication" member of the file. It must have the form PUBLICATION
gives.

The second form prints one line for each TLD of the table, in its order: the TLD, a space
and its base URL. A new publication alone changes no line.

Exit status: 0 when the table or the list was written. 1 on a wrong command line, a file
that cannot be read, or a file that breaks the rules above.
"""

import json
import re
import sys

LDH_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

BASE_URL = re.compile(r"^https://[a-z0-9.-]+(:[0-9]+)?/([A-Za-z0-9._~-]+/)*$")

PUBLICATION = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

HEADER = """\
/*
 * rdap_table.c — the RDAP server of each TLD, for rdap.c.
 *
 * tests/rdap_bootstrap/gen_rdap_table.py writes this file from
 * tests/rdap_bootstrap/dns.json, a copy of IANA's RDAP bootstrap file for domain names.
 * Do not edit it. Run `make rdap-table` after the copy changes.
 *
 * Publication: {publication}
 *
 * rdap_servers holds one entry for each TLD whose server has an https base URL, in the
 * order strcmp sorts the TLDs.
 */

#include "rdap.h"
"""


def read_servers(text):
    """Return the sorted (TLD, base URL) pairs of the file and its publication."""
    bootstrap = json.loads(text)
    publication = bootstrap.get("publication")
    if not isinstance(publication, str) or not PUBLICATION.fullmatch(publication):
        raise ValueError("the file has no publication of the expected form")
    services = bootstrap.get("services")
    if not isinstance(services, list):
        raise ValueError("the file has no list of services")
    servers = {}
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            raise ValueError("a service is not a list of two lists")
        tlds, urls = service
        if not isinstance(tlds, list) or not isinstance(urls, list):
            raise ValueError("a service is not a list of two lists")
        https_urls = [url for url in urls if isinstance(url, str) and url.startswith("https://")]
        if not https_urls:
            continue
        url = https_urls[0]
        if not BASE_URL.fullmatch(url):
            raise ValueError("base URL has another form: " + url)
        for tld in tlds:
            if not isinstance(tld, str) or not LDH_LABEL.fullmatch(tld):
                raise ValueError("TLD is not one LDH label in lower case: " + repr(tld))
            if tld in servers:
                raise ValueError("TLD appears twice: " + tld)
            servers[tld] = url
    return sorted(servers.items(), key=lambda pair: pair[0].encode("ascii")), publication


def write_table(servers, publication):
    """Return the text of src/external/rdap_table.c."""
    lines = [HEADER.format(publication=publication)]
    lines.append("const RdapServer_t rdap_servers[] = {")
    for tld, url in servers:
        lines.append('  { "' + tld + '", "' + url + '" },')
    lines.append("};")
    lines.append("")
    lines.append("const int rdap_serverCount = " + str(len(servers)) + ";")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) == 3 and argv[1] == "--servers":
        with open(argv[2], encoding="utf-8") as bootstrap_file:
            servers, _ = read_servers(bootstrap_file.read())
        for tld, url in servers:
            print(tld + " " + url)
        return 0
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 1
    with open(argv[1], encoding="utf-8") as bootstrap_file:
        servers, publication = read_servers(bootstrap_file.read())
    with open(argv[2], "w", encoding="utf-8", newline="\n") as table_file:
        table_file.write(write_table(servers, publication))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (ValueError, json.JSONDecodeError) as error:
        print("gen_rdap_table: " + str(error), file=sys.stderr)
        sys.exit(1)
