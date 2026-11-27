"""dissect.ntfs stops reading the whole USN journal at one record whose file name is not valid UTF-16 (seen on
the Windows VM: a file named 'f\\udc80.txt'). One such file must not blind the analysis."""
import io
import struct

import investigation.modules.parsers.dissect_adapter
from dissect.ntfs.usnjrnl import UsnJrnl


def _record(usn: int, name: bytes) -> bytes:
    length = (60 + len(name) + 7) & ~7
    head = struct.pack("<IHHQQqqIIII HH", length, 2, 0, 5, 5, usn, 132000000000000000, 0x100, 0, 0, 0x20,
                       len(name), 60)
    return (head + name).ljust(length, b"\0")


def test_bad_utf16_name_does_not_stop_journal():
    data = (_record(1, "a.txt".encode("utf-16-le")) + _record(2, b"f\x00\x80\xdc.\x00t\x00x\x00t\x00")
            + _record(3, "c.txt".encode("utf-16-le")))
    names = [r.filename for r in UsnJrnl(io.BytesIO(data.ljust(4096, b"\0"))).records()]
    assert names[0] == "a.txt" and names[2] == "c.txt"
    assert names[1].startswith("f") and names[1].endswith(".txt") and "\\x80\\xdc" in names[1]
