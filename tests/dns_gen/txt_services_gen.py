"""Write the dns_txtServices initializer of src/dns_table.c from nuclei-templates
dns/txt-service-detect.yaml (MIT, ProjectDiscovery). Usage:
  python3 -I tests/dns_gen/txt_services_gen.py <path to txt-service-detect.yaml>
Each matcher there is one word matched anywhere in a TXT record."""
import sys
lines = open(sys.argv[1]).read().split('\n')
out = []; cur = None; in_words = False
for line in lines:
    t = line.strip()
    if t.startswith('- type:'):
        cur = {'type': t[8:].strip(), 'words': []}; out.append(cur); in_words = False
    elif t.startswith('name:') and cur is not None:
        cur['name'] = t[5:].strip().strip('"')
    elif t == 'words:':
        in_words = True
    elif in_words and t.startswith('- '):
        cur['words'].append(t[2:].strip().strip('"'))
    elif t and not t.startswith('- '):
        in_words = False
assert all(o['type'] == 'word' and len(o['words']) == 1 for o in out)
width = max(len(o['name']) for o in out) + 4
print(len(out))
for o in out:
    name = '"' + o['name'] + '",'
    print(f'  {{ {name:<{width}}"{o["words"][0]}" }},')
