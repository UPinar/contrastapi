#!/usr/bin/env python3
"""Generate tests/test_jsoncanon_vectors.h from the Python canonicalizer.

Run with:
  python3 -I tests/jsoncanon/gen_vectors.py <crypto_billing.py> tests/test_jsoncanon_vectors.h

The canonicalizer source is app/crypto_billing.py of the Python server, at tag v1.36.4 of
github.com/UPinar/contrastapi. The function _canonical_sorted_json is lifted out of that
file with ast, so the fastapi import of the module never runs.
"""
import ast
import json
import sys

def load_canonicalizer(py_source):
    with open(py_source, encoding="utf-8") as handle:
        source = handle.read()
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_canonical_sorted_json":
            namespace = {"json": json}
            exec(compile(ast.Module([node], []), py_source, "exec"), namespace)
            return namespace["_canonical_sorted_json"]
    raise SystemExit("function not found")


def expected(canon, body):
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    return canon(payload).encode("ascii")


NUMBERS = [
    "0", "-0", "1", "-1", "10", "123456789012345678901234567890",
    "100000000000000000000", "-100000000000000000000", "18446744073709551616",
    "0.0", "-0.0", "0e0", "-0e0", "0E+0", "0.000", "1.0", "1.10", "1.100", "15.0",
    "1.5", "-1.5", "0.1", "0.2", "0.3", "0.30000000000000004", "2.5", "1234.5678",
    "1E2", "1e2", "1e+2", "1E-2", "1e0", "1.5e3", "1.5E+3",
    "0.001", "0.0001", "0.00001", "0.000001", "0.00012345", "0.000012345",
    "9.999e-5", "1e-4", "1e-5", "1e-6", "1e-7", "1.5e-7", "1.234567e-5",
    "99999999999999.0", "999999999999999.0", "1e14", "1e15", "1e16", "1e17",
    "1.5e15", "1.5e16", "1.5e17", "9999999999999998.0", "9999999999999999.0",
    "10000000000000000.0", "12345678901234567.0", "1234567890123456.0",
    "123456789012345.0", "1e21", "1e22", "1e23", "1e100", "-1e100", "1.7976931348623157e308",
    "2.2250738585072014e-308", "2.225073858507201e-308", "5e-324", "4.9e-324",
    "1e-323", "1.5e-323", "1e-320", "1e-310", "1e-999", "-1e-999", "0.0e999",
    "9007199254740992.0", "9007199254740993.0", "9007199254740994.0",
    "7.1202363472230444e-307", "7.291122019556398e-304", "8.209073602596753e-289",
    "5.641232424577593e-278", "5.858190679279809e-244",
    "2.2204460492503131e-16", "1.1102230246251565e-16", "4.450147717014403e-308",
    "0.1000000000000000055511151231257827", "1.00000000000000011102230246251565",
    "1.7976931348623158e308", "123456789e-20", "6.02214076e23", "6.62607015e-34",
    "299792458.0", "3.141592653589793", "2.718281828459045", "0.5", "0.25", "0.125",
    "1e1", "1e-1", "1.0e-1", "100.0", "1000.0",
]

STRUCTURES = [
    b'{}', b'{ }', b'{"a":[]}', b'{"a":{}}', b'{"a":[ ]}', b' \t\r\n{ "a" : 1 , "b" : [ 1 , 2 ] } \n',
    b'{"b":1,"a":2}', b'{"b":{"d":1,"c":2},"a":[{"z":1,"y":2},{"x":[{"q":1,"p":2}]}]}',
    b'{"a":true,"b":false,"c":null}', b'{"a":[true,false,null,"x",1,1.5,{}]}',
    b'{"ab":1,"a":2,"":3}', b'{"Z":1,"a":2,"_":3,"0":4}',
    '{"\U0001F600":1,"":2}'.encode(), '{"é":1,"z":2,"ÿ":3,"ā":4}'.encode(),
    '{"€":1,"\U00010000":2,"￿":3,"ࠀ":4}'.encode(),
    '{"k":"é€\U0001F600"}'.encode(), '{"é€\U0001F600":"v"}'.encode(),
    '{"k":"\u0080߿ࠀ￿\U00010000\U0010FFFF"}'.encode(),
    b'{"k":"\x7f"}', b'{"\x7f":1}', b'{"k":"\\u007f"}', b'{"k":"~ !#[]"}', b'{"k":"/"}',
    b'{"k":"\\/"}', b'{"k":"\\""}', b'{"k":"\\\\"}', b'{"k":"\\b\\f\\n\\r\\t"}',
    b'{"k":"\\u0008\\u000c\\u000a\\u000d\\u0009"}', b'{"k":"\\u0001\\u001f\\u0020\\u0021"}',
    b'{"k":"\\u0022\\u005c\\u002f"}', b'{"k":"\\u00e9\\u00E9"}', b'{"k":"\\uABCD\\uabcd"}',
    b'{"k":"\\uD83D\\uDE00"}', b'{"k":"\\ud83d\\ude00"}', b'{"k":"\\uD800\\uDC00"}',
    b'{"k":"\\uDBFF\\uDFFF"}', b'{"k":"a\\nb\\tc"}', b'{"k":""}', b'{"":""}',
    b'{"k":"\\u0041"}', b'{"a":"\\uFFFF"}', b'{"a":"\\uE000"}', b'{"a":"\\uD7FF"}',
    b'{"k":[1,[2,[3,[4]]]]}', b'{"price_amount":15.0,"order_id":"abc","pay_amount":0.00012345,"payment_id":5526781234}',
    b'{"actually_paid":14.99,"invoice_id":1,"outcome_amount":14.5,"payment_status":"finished","fee":{"currency":"usdttrc20","depositFee":0.1,"serviceFee":0}}',
]

BOTH_REFUSE = [
    b'', b' ', b'[]', b'1', b'"a"', b'null', b'true', b'{', b'}', b'{"a"', b'{"a":', b'{"a":1',
    b'{"a":1,}', b'{,"a":1}', b'{"a" 1}', b'{a:1}', b"{'a':1}", b'{"a":1}x', b'{"a":1}{}',
    b'[{"a":1}]', b'{"a":01}', b'{"a":-01}',
    b'{"a":+1}', b'{"a":1.}', b'{"a":.5}', b'{"a":1e}', b'{"a":1e+}', b'{"a":0x10}', b'{"a":--1}',
    b'{"a":1-2}', b'{"a":TRUE}', b'{"a":True}', b'{"a":nul}', b'{"a":tru}', b'{"a":"\x01"}', b'{"a":"\x1f"}',
    b'{"a":"\n"}', b'{"a\t":1}', b'{"a":"\\x41"}', b'{"a":"\\a"}', b'{"a":"\\u12"}', b'{"a":"\\uZZZZ"}',
    b'{"a":"\xff"}', b'{"a":"\xc0\x80"}', b'{"a":"\xf4\x90\x80\x80"}',
    b'{"a":"\xe2\x82"}', b'{"\xff":1}', b'\xff{"a":1}', b'{"a":1}\xff', b'\f{"a":1}', b'{"a":1}\f', b'\x0b{}',
    b'{"a":[1,]}', b'{"a":[,1]}', b'{"a":[1 2]}', b'{"a":1 "b":2}', b'{"a":"unterminated}',
]


def c_literal(raw):
    return '"' + "".join("\\%03o" % byte for byte in raw) + '"'


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py <crypto_billing.py> <out.h>")
    canon = load_canonicalizer(sys.argv[1])
    bodies = [b'{"v":' + text.encode() + b"}" for text in NUMBERS]
    bodies += [b'{"v":[' + text.encode() + b"]}" for text in NUMBERS[:12]]
    bodies += STRUCTURES
    rows = []
    accepted = 0
    for body in bodies + BOTH_REFUSE:
        want = expected(canon, body)
        if want is not None:
            accepted += 1
        rows.append((body, want))
    missing = [body for body in bodies if expected(canon, body) is None]
    if missing:
        raise SystemExit("an accept vector is refused by Python: %r" % missing[:3])
    wrong = [body for body in BOTH_REFUSE if expected(canon, body) is not None]
    if wrong:
        raise SystemExit("a refuse vector is accepted by Python: %r" % wrong[:3])
    with open(sys.argv[2], "w", encoding="ascii") as out:
        out.write("/* Generated file. Do not edit.\n")
        out.write(" * Generator: python3 -I tests/jsoncanon/gen_vectors.py <crypto_billing.py> tests/test_jsoncanon_vectors.h\n")
        out.write(" * Each row holds a body and what Python's canonicalizer makes of it.\n")
        out.write(" * mp_expected is NULL when Python refuses the body. */\n\n")
        out.write("#ifndef TEST_JSONCANON_VECTORS_H\n#define TEST_JSONCANON_VECTORS_H\n\n")
        out.write("#include <stddef.h>  /* size_t, NULL */\n\n")
        out.write("typedef struct\n{\n  const char* mp_body;\n  size_t      m_bodyLen;\n  const char* mp_expected;\n} TestJsonCanonVector_t;\n\n")
        out.write("static const TestJsonCanonVector_t JSONCANON_VECTORS[] = {\n")
        for body, want in rows:
            expected_text = "NULL" if want is None else c_literal(want)
            out.write("  { %s, %d, %s },\n" % (c_literal(body), len(body), expected_text))
        out.write("};\n\n#endif\n")
    print("rows", len(rows), "accepted", accepted, "refused", len(rows) - accepted)


if __name__ == "__main__":
    main()
