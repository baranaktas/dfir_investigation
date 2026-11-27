"""Authenticode signature status via WinVerifyTrust: embedded signature, then catalog fallback.

No UI, no revocation checks and cache-only URL retrieval, so the suspect host never does network lookups.
"""

from __future__ import annotations

import os

TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_NOSIGNATURE = 0x800B0100

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
PROV_FLAGS = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL


def member_tag(digest: bytes) -> str:
    """Catalog member tag: the file hash as an uppercase hex string."""
    return bytes(digest).hex().upper()


def classify_result(code: int) -> str:
    code &= 0xFFFFFFFF
    if code == 0:
        return "signed"
    if code in (TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN):
        return "unsigned"
    return "error"


def signature_status(path: str) -> str:
    """Return "signed", "unsigned", "error", or "" when not applicable (non-Windows / no path)."""
    if os.name != "nt" or not path:
        return ""
    try:
        return _status_windows(path)
    except Exception:
        return "error"


def _status_windows(path: str) -> str:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]

    class FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", ctypes.c_void_p)]

    class CATINFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]

    class DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pUnion", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD)]

    wt = ctypes.WinDLL("wintrust", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    wt.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    wt.WinVerifyTrust.restype = ctypes.c_long
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    def verify(choice: int, info: ctypes.Structure) -> int:
        data = DATA()
        data.cbStruct = ctypes.sizeof(DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = choice
        data.pUnion = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
        data.dwProvFlags = PROV_FLAGS
        return wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) & 0xFFFFFFFF

    fi = FILE_INFO(ctypes.sizeof(FILE_INFO), path, None, None)
    res = verify(WTD_CHOICE_FILE, fi)
    if res != TRUST_E_NOSIGNATURE:
        return classify_result(res)

    vp = ctypes.c_void_p
    for fn, args, ret in (
        ("CryptCATAdminAcquireContext2", [ctypes.POINTER(vp), vp, wintypes.LPCWSTR, vp, wintypes.DWORD], wintypes.BOOL),
        ("CryptCATAdminAcquireContext", [ctypes.POINTER(vp), vp, wintypes.DWORD], wintypes.BOOL),
        ("CryptCATAdminCalcHashFromFileHandle2",
         [vp, vp, ctypes.POINTER(wintypes.DWORD), vp, wintypes.DWORD], wintypes.BOOL),
        ("CryptCATAdminCalcHashFromFileHandle", [vp, vp, ctypes.POINTER(wintypes.DWORD), vp, wintypes.DWORD],
         wintypes.BOOL),
        ("CryptCATAdminEnumCatalogFromHash", [vp, vp, wintypes.DWORD, wintypes.DWORD, vp], vp),
        ("CryptCATCatalogInfoFromContext", [vp, ctypes.POINTER(CATINFO), wintypes.DWORD], wintypes.BOOL),
        ("CryptCATAdminReleaseCatalogContext", [vp, vp, wintypes.DWORD], wintypes.BOOL),
        ("CryptCATAdminReleaseContext", [vp, wintypes.DWORD], wintypes.BOOL),
    ):
        try:
            f = getattr(wt, fn)
        except AttributeError:
            continue
        f.argtypes, f.restype = args, ret

    hadmin = vp()
    use2 = hasattr(wt, "CryptCATAdminAcquireContext2")
    if use2:
        ok = wt.CryptCATAdminAcquireContext2(ctypes.byref(hadmin), None, "SHA256", None, 0)
    else:
        ok = False
    if not ok:
        use2 = False
        hadmin = vp()
        if not wt.CryptCATAdminAcquireContext(ctypes.byref(hadmin), None, 0):
            return "unsigned"
    hfile = k32.CreateFileW(path, 0x80000000, 7, None, 3, 0, None)
    if hfile in (None, vp(-1).value):
        wt.CryptCATAdminReleaseContext(hadmin, 0)
        return "unsigned"
    hcat = None
    try:
        calc = wt.CryptCATAdminCalcHashFromFileHandle2 if use2 else wt.CryptCATAdminCalcHashFromFileHandle
        size = wintypes.DWORD(0)
        args = (hadmin, vp(hfile))
        calc(*args, ctypes.byref(size), None, 0)
        if not size.value:
            return "unsigned"
        buf = (ctypes.c_ubyte * size.value)()
        if not calc(*args, ctypes.byref(size), buf, 0):
            return "unsigned"
        digest = bytes(buf[: size.value])
        hcat = wt.CryptCATAdminEnumCatalogFromHash(hadmin, buf, size.value, 0, None)
        if not hcat:
            return "unsigned"
        ci = CATINFO()
        ci.cbStruct = ctypes.sizeof(CATINFO)
        if not wt.CryptCATCatalogInfoFromContext(hcat, ctypes.byref(ci), 0):
            return "error"
        cat = CATALOG_INFO(ctypes.sizeof(CATALOG_INFO), 0, ci.wszCatalogFile, member_tag(digest), path,
                           None, ctypes.cast(buf, ctypes.c_void_p), size.value, None, hadmin)
        return classify_result(verify(WTD_CHOICE_CATALOG, cat))
    finally:
        if hcat:
            wt.CryptCATAdminReleaseCatalogContext(hadmin, hcat, 0)
        k32.CloseHandle(hfile)
        wt.CryptCATAdminReleaseContext(hadmin, 0)
