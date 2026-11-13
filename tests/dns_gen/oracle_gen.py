"""Independent oracle for tests/test_dns.c: dnspython 2.8.0 writes answer messages.

Run: python3 -I tests/dns_gen/oracle_gen.py
It needs dnspython 2.8.0 in a virtual environment or installed for the whole system: -I skips
the user's own site-packages. Prints one C array per message and dnspython's own reading of the
records. dnspython writes the records of one answer in random order. So a rerun may order the
records of an answer with more than one record another way than tests/test_dns.c does, as
measured for ORACLE_MX, the CAA and AAAA answers and A_AFTER_CNAME."""
import dns.message, dns.rrset, dns.rdatatype

def answer(qtype, rrsets, qid=0x1234, rcode=0):
    q = dns.message.make_query('example.com', qtype, use_edns=False)
    q.id = qid
    r = dns.message.make_response(q)
    r.set_rcode(rcode)
    for name, rtype, rdatas in rrsets:
        r.answer.append(dns.rrset.from_text(name, 300, 'IN', rtype, *rdatas))
    return r.to_wire()

MESSAGES = {
    "ORACLE_MX": answer('MX', [('example.com.', 'MX', ['10 mail.example.com.', '20 backup.mail.example.net.', '0 .'])]),
    "ORACLE_TXT": answer('TXT', [('example.com.', 'TXT', ['"v=spf1 include:_spf.example.net " "-all"', '"a\\000b\\007c"'])]),
    "ORACLE_SOA": answer('SOA', [('example.com.', 'SOA', ['ns1.example.com. hostmaster.example.com. 2024101301 7200 3600 1209600 300'])]),
    "ORACLE_A_AFTER_CNAME": answer('A', [('example.com.', 'CNAME', ['edge.example.net.']), ('edge.example.net.', 'A', ['192.0.2.10', '198.51.100.7'])]),
    "ORACLE_CAA": answer('CAA', [('example.com.', 'CAA', ['0 issue "letsencrypt.org"', '128 iodef "mailto:security@example.com"', '0 issuewild ";"'])]),
    "ORACLE_AAAA": answer('AAAA', [('example.com.', 'AAAA', ['2001:db8::1', '2001:db8:0:0:1:0:0:1'])]),
}

for cname, wire in MESSAGES.items():
    print(f"/* {cname}: {len(wire)} bytes */")
    print(f"static const unsigned char {cname}[] = {{")
    for i in range(0, len(wire), 16):
        print("  " + ", ".join(f"0x{b:02x}" for b in wire[i:i+16]) + ",")
    print("};")
    m = dns.message.from_wire(wire)
    for rrset in m.answer:
        for rd in rrset:
            print("/*   dnspython reads:", dns.rdatatype.to_text(rrset.rdtype), repr(rd.to_text()) if rrset.rdtype not in (dns.rdatatype.TXT,) else repr(b''.join(rd.strings)), "*/")
