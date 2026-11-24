# Anti-Logging Bear by Priest

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass

VALID = "valid"
UNSIGNED = "unsigned"
TAMPERED = "tampered"
DISTRUSTED = "distrusted"
UNTRUSTED = "untrusted"
UNKNOWN = "unknown"

_RESULTS = {
    0: VALID,
    0x800B0100: UNSIGNED,
    0x80096010: TAMPERED,
    0x80096019: TAMPERED,
    0x800B0111: DISTRUSTED,
    0x800B010C: DISTRUSTED,
    0x800B0109: UNTRUSTED,
    0x800B0101: UNTRUSTED,
    0x800B0004: UNTRUSTED,
}
_NAMED = {0, 0x800B0109, 0x800B0101, 0x800B0111, 0x800B010C}


@dataclass
class Signature:
    status: str
    signer: str = ""


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, text: str) -> _GUID:
        parts = text.strip("{}").split("-")
        tail = bytes.fromhex(parts[3] + parts[4])
        return cls(int(parts[0], 16), int(parts[1], 16), int(parts[2], 16), (ctypes.c_ubyte * 8)(*tail))


class _FileInfo(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class _TrustData(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(_FileInfo)), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


class _ProviderCert(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


class _ProviderSigner(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("sftVerifyAsOf", wintypes.FILETIME),
                ("csCertChain", wintypes.DWORD), ("pasCertChain", ctypes.POINTER(_ProviderCert))]


_ACTION = "{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"
_UI_NONE = 2
_CHOICE_FILE = 1
_VERIFY, _CLOSE = 1, 2
_CACHE_ONLY = 0x00001000
_api = None


def _load():
    global _api
    if _api is None:
        wintrust = ctypes.WinDLL("wintrust")
        crypt32 = ctypes.WinDLL("crypt32")
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.POINTER(_TrustData)]
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
        wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
        wintrust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
                                                            wintypes.DWORD]
        wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(_ProviderSigner)
        crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                               wintypes.LPWSTR, wintypes.DWORD]
        crypt32.CertGetNameStringW.restype = wintypes.DWORD
        _api = (wintrust, crypt32)
    return _api


def supported() -> bool:
    return sys.platform == "win32"


def verify_file(path: str) -> Signature:
    if not supported():
        return Signature(UNKNOWN)
    try:
        wintrust, crypt32 = _load()
    except OSError:
        return Signature(UNKNOWN)
    info = _FileInfo(ctypes.sizeof(_FileInfo), path, None, None)
    trust = _TrustData(cbStruct=ctypes.sizeof(_TrustData), dwUIChoice=_UI_NONE, fdwRevocationChecks=0,
                       dwUnionChoice=_CHOICE_FILE, pFile=ctypes.pointer(info), dwStateAction=_VERIFY,
                       dwProvFlags=_CACHE_ONLY)
    action = _GUID.parse(_ACTION)
    result = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust)) & 0xFFFFFFFF
    signer = ""
    try:
        if result in _NAMED and trust.hWVTStateData:
            provider = wintrust.WTHelperProvDataFromStateData(trust.hWVTStateData)
            if provider:
                sgnr = wintrust.WTHelperGetProvSignerFromChain(provider, 0, False, 0)
                if sgnr and sgnr.contents.csCertChain:
                    text = ctypes.create_unicode_buffer(256)
                    if crypt32.CertGetNameStringW(sgnr.contents.pasCertChain[0].pCert, 4, 0, None, text, 256) > 1:
                        signer = text.value
    finally:
        trust.dwStateAction = _CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust))
    return Signature(_RESULTS.get(result, UNKNOWN), signer)
