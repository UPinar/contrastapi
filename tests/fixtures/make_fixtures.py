"""Write the fixture images of tests/fixtures/ and expected.json.

Usage:
  python3 -I tests/fixtures/make_fixtures.py tests/fixtures

The images are small JPEGs that Pillow draws. The script writes their metadata itself, as
an Exif APP1 segment (a TIFF with IFD0, the Exif IFD and the GPS IFD) and an XMP APP1
segment, so each image carries the tags expected.json checks:
  - exif_gps.jpg: camera make and model, software, dates, a time offset and a GPS position;
  - xmp_creator_tool.jpg: an XMP packet with a creator tool and a digital source type;
  - plain.jpg: no metadata at all.
expected.json lists, for each image, the -G1 keys exiftool must answer and their values,
and the keys it must not answer. check_exiftool.py reads it. expected.json takes its values
from the constants below, so a change here changes both.

The script reads exif_gps.jpg back with Pillow after it wrote the four files, and exits 1
when IFD0 lacks the make, so a broken Exif writer is reported.

Exit status: 0 when the four files are written, 1 otherwise.
"""

import json
import struct
import sys

from PIL import Image

ASCII, SHORT, LONG, RATIONAL, BYTE = 2, 3, 4, 5, 1
EXIF_IFD_TAG, GPS_IFD_TAG = 0x8769, 0x8825

MAKE = "Canon"
MODEL = "EOS R5"
SOFTWARE = "Adobe Photoshop 25.0"
DATE = "2026:01:02 03:04:05"
OFFSET = "+03:00"
GPS_DATE = "2026:01:02"
CREATOR_TOOL = "Adobe Firefly"
DIGITAL_SOURCE_TYPE = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"

XMP_PACKET = (
    '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    '<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/"'
    ' xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/"'
    f' xmp:CreatorTool="{CREATOR_TOOL}" Iptc4xmpExt:DigitalSourceType="{DIGITAL_SOURCE_TYPE}"/>'
    '</rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
)


def ifd_bytes(entries, ifd_offset):
    """Write one IFD at ifd_offset: the entry table, a zero next-IFD offset, then the values
    longer than four bytes. entries are (tag, type, values) with values a list; an ASCII
    value is one str. The entries are written in tag order, as TIFF requires."""
    sizes = {ASCII: 1, SHORT: 2, LONG: 4, RATIONAL: 8, BYTE: 1}
    table = b""
    data = b""
    data_offset = ifd_offset + 2 + 12 * len(entries) + 4
    for tag, kind, values in sorted(entries):
        if kind == ASCII:
            payload = values.encode("ascii") + b"\x00"
            count = len(payload)
        elif kind == RATIONAL:
            payload = b"".join(struct.pack("<II", n, d) for n, d in values)
            count = len(values)
        elif kind == SHORT:
            payload = b"".join(struct.pack("<H", v) for v in values)
            count = len(values)
        elif kind == LONG:
            payload = b"".join(struct.pack("<I", v) for v in values)
            count = len(values)
        else:
            payload = bytes(values)
            count = len(values)
        assert count * sizes[kind] == len(payload)
        if len(payload) <= 4:
            table += struct.pack("<HHI", tag, kind, count) + payload.ljust(4, b"\x00")
        else:
            table += struct.pack("<HHII", tag, kind, count, data_offset + len(data))
            data += payload
    return struct.pack("<H", len(entries)) + table + struct.pack("<I", 0) + data


def exif_app1():
    """Build the Exif APP1 segment: IFD0 points at the Exif IFD and the GPS IFD, which
    follow it. The pointer values need the block sizes, so IFD0 is laid out twice."""
    exif_ifd = [(0x9003, ASCII, DATE), (0x9011, ASCII, OFFSET)]
    gps_ifd = [
        (0x0000, BYTE, [2, 3, 0, 0]),
        (0x0001, ASCII, "N"),
        (0x0002, RATIONAL, [(41, 1), (0, 1), (2952, 100)]),
        (0x0003, ASCII, "E"),
        (0x0004, RATIONAL, [(28, 1), (58, 1), (4224, 100)]),
        (0x0007, RATIONAL, [(12, 1), (0, 1), (0, 1)]),
        (0x001D, ASCII, GPS_DATE),
    ]

    def ifd0(exif_offset, gps_offset):
        return ifd_bytes([
            (0x010F, ASCII, MAKE), (0x0110, ASCII, MODEL), (0x0131, ASCII, SOFTWARE),
            (0x0132, ASCII, DATE), (EXIF_IFD_TAG, LONG, [exif_offset]), (GPS_IFD_TAG, LONG, [gps_offset]),
        ], 8)

    exif_offset = 8 + len(ifd0(0, 0))
    gps_offset = exif_offset + len(ifd_bytes(exif_ifd, exif_offset))
    tiff = b"II*\x00" + struct.pack("<I", 8) + ifd0(exif_offset, gps_offset) \
        + ifd_bytes(exif_ifd, exif_offset) + ifd_bytes(gps_ifd, gps_offset)
    return app1(b"Exif\x00\x00" + tiff)


def xmp_app1():
    return app1(b"http://ns.adobe.com/xap/1.0/\x00" + XMP_PACKET.encode("utf-8"))


def app1(payload):
    """One APP1 marker segment: FF E1, the length that counts itself, the payload."""
    return b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload


def jpeg_bytes(color):
    """A 16 by 16 baseline JPEG from Pillow, with no metadata of its own."""
    import io
    image = Image.new("RGB", (16, 16), color)
    out = io.BytesIO()
    image.save(out, "JPEG", quality=75)
    return out.getvalue()


def write(path, data):
    with open(path, "wb") as out:
        out.write(data)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    directory = sys.argv[1]
    plain = jpeg_bytes((40, 80, 160))
    write(f"{directory}/plain.jpg", plain)
    write(f"{directory}/exif_gps.jpg", plain[:2] + exif_app1() + plain[2:])
    write(f"{directory}/xmp_creator_tool.jpg", plain[:2] + xmp_app1() + plain[2:])

    exif_keys = ["IFD0:Make", "IFD0:Model", "IFD0:Software", "IFD0:ModifyDate",
                 "ExifIFD:DateTimeOriginal", "ExifIFD:OffsetTimeOriginal",
                 "Composite:GPSLatitude", "Composite:GPSLongitude", "Composite:GPSDateTime"]
    xmp_keys = ["XMP-xmp:CreatorTool", "XMP-iptcExt:DigitalSourceType"]
    expected = {
        "arguments": ["-config", "", "-json", "-G1", "-n", "-struct", "-"],
        "images": {
            "exif_gps.jpg": {
                "present": {"IFD0:Make": MAKE, "IFD0:Model": MODEL, "IFD0:Software": SOFTWARE,
                            "IFD0:ModifyDate": DATE, "ExifIFD:DateTimeOriginal": DATE,
                            "ExifIFD:OffsetTimeOriginal": OFFSET,
                            "Composite:GPSLatitude": 41.0082, "Composite:GPSLongitude": 28.9784,
                            "Composite:GPSDateTime": "2026:01:02 12:00:00Z",
                            "File:JPEGQualityEstimate": None},
                "absent": xmp_keys,
            },
            "xmp_creator_tool.jpg": {
                "present": {"XMP-xmp:CreatorTool": CREATOR_TOOL,
                            "XMP-iptcExt:DigitalSourceType": DIGITAL_SOURCE_TYPE,
                            "File:JPEGQualityEstimate": None},
                "absent": exif_keys,
            },
            "plain.jpg": {
                "present": {"File:JPEGQualityEstimate": None},
                "absent": exif_keys + xmp_keys,
            },
        },
    }
    with open(f"{directory}/expected.json", "w", encoding="utf-8") as out:
        json.dump(expected, out, indent=2)
        out.write("\n")

    back = Image.open(f"{directory}/exif_gps.jpg").getexif()
    if back.get(0x010F) != MAKE:
        print("FAIL: Pillow reads no make from exif_gps.jpg")
        return 1
    print("PASS: wrote plain.jpg, exif_gps.jpg, xmp_creator_tool.jpg and expected.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
