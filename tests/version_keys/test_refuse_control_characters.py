"""Control character test: refuse_control_characters in the four key tests that write their
versions inline into a psql script.

test_maven_key, test_nuget_key, test_packagist_key and test_rubygems_key send their versions as
COPY data inside the script psql reads. A version with a line break could end that data and make
psql run the rest as its own commands. Each module's refuse_control_characters must exit on a
version with a line break, a carriage return, a NUL or another character below 0x20, and must
accept plain versions. The test needs no database: it imports the modules and calls the function.
Exit 1 when a module accepts one of those versions.

Usage: python3 test_refuse_control_characters.py
"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv = [sys.argv[0], "no_database"]

accepted_count = 0
for module_name in ("test_maven_key", "test_nuget_key", "test_packagist_key", "test_rubygems_key"):
    module = importlib.import_module(module_name)
    module.refuse_control_characters(["1.0", "2.0-rc.1"])
    for version in ("1.0\n2", "1.0\r", "1\x00", "1\x1f"):
        try:
            module.refuse_control_characters([version])
        except SystemExit:
            continue
        print(f"{module_name}: accepted {version!r}")
        accepted_count += 1
print(f"control characters: 4 modules, 4 versions each, {accepted_count} accepted")
sys.exit(1 if accepted_count else 0)
