"""Small, targeted fixes for dissect behaviour seen on real evidence. Imported by the dissect adapter.

USN journal: dissect.ntfs decodes each record's file name with strict UTF-16. A single name that is not valid
UTF-16 (e.g. a lone surrogate, which NTFS allows) raises inside UsnJrnl.records() and ends the generator, so the
rest of the journal is never read. An attacker can blind USN analysis with one such file. Undecodable bytes are
kept visible as backslash escapes instead.
"""

from __future__ import annotations

from dissect.ntfs import usnjrnl as _usnjrnl

_Original = _usnjrnl.UsnRecord


class _TolerantUsnRecord(_Original):
    def __init__(self, usnjrnl, fh, offset: int):
        try:
            super().__init__(usnjrnl, fh, offset)
        except UnicodeDecodeError:
            fh.seek(offset + self.record.FileNameOffset)
            self.filename = fh.read(self.record.FileNameLength).decode("utf-16-le", "backslashreplace")


if not issubclass(_usnjrnl.UsnRecord, _TolerantUsnRecord):
    _usnjrnl.UsnRecord = _TolerantUsnRecord
