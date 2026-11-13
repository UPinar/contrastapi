"""Run exiftool on the fixture images the way the exif service does, and compare its keys.

Usage:
  python3 -I tests/fixtures/check_exiftool.py <exiftool> <fixture dir> [<contrastapi-exif@.service>]

For each image that expected.json lists, the check feeds the image to exiftool on stdin
with the arguments of the exif service (expected.json "arguments"), reads the JSON
answer, and checks that
  - each key under "present" is answered, with the value given, or with any value when
    the value is null;
  - no key under "absent" is answered;
  - a number is compared with a tolerance of 0.0001, every other value by equality.
With a unit file, the check also reads its ExecStart line and refuses the unit when the
arguments after the program differ from the ones it ran: src/exifclient.c reads the answer
of exactly these arguments.
The exiftool updater runs this check before it switches versions.

Exit status: 0 when every image and the unit pass, 1 otherwise.
"""

import json
import shlex
import subprocess
import sys


def answer(exiftool, arguments, image_path):
    """exiftool's JSON answer for one image fed on stdin: a list with one object."""
    with open(image_path, "rb") as image:
        data = image.read()
    try:
        run = subprocess.run([exiftool] + arguments, input=data, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, f"exiftool did not run: {error}"
    if run.returncode != 0:
        return None, f"exiftool exited {run.returncode}: {run.stderr.decode('utf-8', 'replace').strip()}"
    try:
        parsed = json.loads(run.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, f"the answer is not JSON: {error}"
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        return None, "the answer is not a list of one object"
    return parsed[0], None


def values_equal(expected, actual):
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return isinstance(actual, (int, float)) and abs(float(actual) - float(expected)) <= 0.0001
    return expected == actual


def check_image(exiftool, arguments, directory, name, rules):
    failures = []
    tags, error = answer(exiftool, arguments, f"{directory}/{name}")
    if error:
        return [f"FAIL: {name}: {error}"]
    for key, value in rules["present"].items():
        if key not in tags:
            failures.append(f"FAIL: {name}: exiftool answers no {key}")
        elif value is not None and not values_equal(value, tags[key]):
            failures.append(f"FAIL: {name}: {key} is {tags[key]!r}, expected {value!r}")
    for key in rules["absent"]:
        if key in tags:
            failures.append(f"FAIL: {name}: exiftool answers {key}, which the image does not carry")
    return failures


def unit_arguments(unit_path):
    """The arguments after the program on the ExecStart line of the unit."""
    with open(unit_path, encoding="utf-8") as unit:
        for line in unit:
            if line.startswith("ExecStart="):
                return shlex.split(line[len("ExecStart="):])[1:]
    return None


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    exiftool, directory = sys.argv[1], sys.argv[2]
    with open(f"{directory}/expected.json", encoding="utf-8") as expected_file:
        expected = json.load(expected_file)
    arguments = expected["arguments"]
    failures = []
    for name, rules in expected["images"].items():
        failures += check_image(exiftool, arguments, directory, name, rules)
    if len(sys.argv) == 4:
        found = unit_arguments(sys.argv[3])
        if found != arguments:
            failures.append(f"FAIL: {sys.argv[3]} runs exiftool with {found}, this check with {arguments}")
    for line in failures:
        print(line)
    if failures:
        return 1
    print(f"PASS: {exiftool} answers the {len(expected['images'])} fixture images as expected.json says")
    return 0


if __name__ == "__main__":
    sys.exit(main())
