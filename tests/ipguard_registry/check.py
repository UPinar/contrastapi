"""Check src/ipguard.c against IANA's special-purpose address registries.

Usage:
  python3 -I tests/ipguard_registry/check.py <registry dir> <ask binary>

The registry dir holds iana-ipv4-special-registry-1.csv and
iana-ipv6-special-registry-1.csv. tests/ipguard_registry holds a snapshot of both.
The weekly iana_registry workflow passes a fresh download instead.

Each row of a registry names a block and whether it is globally reachable. The check
takes the first and the last address of each block, and the address on each side of
them. Each address is judged by the most specific row that holds it:
  - a row with a termination date has ended, so the address is not judged;
  - a row in DELIBERATE must be refused, whatever the registry says;
  - "True" must be accepted, and "False" must be refused;
  - any other value needs a decision, and the check fails.
An address that no row holds is not judged. tests/test_ipguard.c pins those.

Exit status: 0 when ipguard agrees with every judged address, 1 when it does not.
"""

import csv
import ipaddress
import os
import subprocess
import sys

DELIBERATE = {
    "64:ff9b::/96": "NAT64: the registry marks it globally reachable",
    "2001::/32": "Teredo: the registry gives N/A",
    "2002::/16": "6to4: the registry gives N/A",
}

REGISTRY_FILES = ("iana-ipv4-special-registry-1.csv", "iana-ipv6-special-registry-1.csv")


def load_rows(registry_dir):
    """Read both registries into (block, name, globally reachable, has ended) rows.

    A row can name more than one block, separated by commas. Each block gets a row.
    """
    rows = []
    for file_name in REGISTRY_FILES:
        with open(os.path.join(registry_dir, file_name), encoding="utf-8", newline="") as registry:
            for row in csv.DictReader(registry):
                reachable = row["Globally Reachable"].split("[")[0].strip()
                has_ended = row["Termination Date"].strip() not in ("", "N/A")
                name = " ".join(row["Name"].split())
                for block_text in row["Address Block"].split(","):
                    block_text = block_text.split("[")[0].strip()
                    rows.append((ipaddress.ip_network(block_text), name, reachable, has_ended))
    return rows


def edge_addresses(rows):
    """List each block's first and last address, and the address on each side of them."""
    addresses = set()
    for block, _, _, _ in rows:
        for edge in (block.network_address, block.broadcast_address):
            addresses.add(edge)
            for step in (-1, 1):
                try:
                    addresses.add(edge + step)
                except ipaddress.AddressValueError:
                    pass
    return sorted(addresses, key=lambda address: (address.version, int(address)))


def ask_ipguard(ask_binary, addresses):
    """Return ipguard_isGloballyReachableIp's answer for each address."""
    stdin_text = "".join(str(address) + "\n" for address in addresses)
    result = subprocess.run([ask_binary], input=stdin_text, capture_output=True, text=True, check=True)
    answers = {}
    for line in result.stdout.splitlines():
        address_text, answer = line.split()
        answers[address_text] = answer == "1"
    return answers


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    registry_dir, ask_binary = sys.argv[1], sys.argv[2]

    rows = load_rows(registry_dir)
    failures = []
    for block_text in DELIBERATE:
        if not any(str(block) == block_text for block, _, _, _ in rows):
            failures.append(f"DELIBERATE names {block_text}, which the registry no longer lists")

    addresses = edge_addresses(rows)
    answers = ask_ipguard(ask_binary, addresses)
    judged = 0
    for address in addresses:
        holding_rows = [row for row in rows if row[0].version == address.version and address in row[0]]
        if not holding_rows:
            continue
        block, name, reachable, has_ended = max(holding_rows, key=lambda row: row[0].prefixlen)
        if has_ended:
            continue

        if str(block) in DELIBERATE:
            should_accept = False
        elif reachable in ("True", "False"):
            should_accept = reachable == "True"
        else:
            failures.append(f"{address}: {block} ({name}) gives '{reachable}', so it needs a decision")
            continue

        judged += 1
        accepts = answers[str(address)]
        if accepts != should_accept:
            failures.append(f"{address}: ipguard {'accepts' if accepts else 'refuses'} it, "
                            f"but {block} ({name}) says it should be {'accepted' if should_accept else 'refused'}")

    print(f"ipguard registry check: {len(rows)} rows, {len(addresses)} addresses, {judged} judged, "
          f"{len(failures)} failures")
    for failure in failures:
        print("FAIL: " + failure)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
