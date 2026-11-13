"""Write the dns_takeoverSuffixes initializer of src/dns_table.c from
can-i-take-over-xyz fingerprints.json (CC BY 4.0, EdOverflow). Usage:
  python3 -I tests/dns_gen/takeover_suffixes_gen.py <path to fingerprints.json>
Keeps the services marked vulnerable whose fingerprint is NXDOMAIN, and each of their
CNAME suffixes once, in the file's order."""
import json, sys
entries = json.load(open(sys.argv[1]))
rows = []
for e in entries:
    if not (e.get('nxdomain') and e.get('vulnerable') and e.get('status') == 'Vulnerable'):
        continue
    for suffix in e['cname']:
        if (e['service'], suffix) not in rows:
            rows.append((e['service'], suffix))
print(len(rows))
width = max(len(s) for s, _ in rows) + 4
for service, suffix in rows:
    name = '"' + service + '",'
    print(f'  {{ {name:<{width}}"{suffix}" }},')
