"""Handle-pinned, owner-private Windows cache for public destination lists only.

No generic process-store support is enabled. Only local fixed NTFS/ReFS volumes,
protected current-user/SYSTEM DACLs and ordinary single-link files are accepted.
"""
from contextlib import contextmanager
import ctypes as ct
from ctypes import wintypes as wt
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import threading
import time

_LOCK = threading.Lock()
_NAMES = {"current.json", "previous.json", "attempt.json", ".lock"}
_TEMP = re.compile(r"\.[0-9a-f]{32}\.tmp\Z")
READ, WRITE, DELETE, CONTROL = 0x80000000, 0x40000000, 0x10000, 0x20000


def managed(name):
    return name in _NAMES or bool(_TEMP.fullmatch(name))


class Info(ct.Structure):
    _fields_ = [("attributes", wt.DWORD), ("created", wt.FILETIME), ("accessed", wt.FILETIME),
                ("modified", wt.FILETIME), ("volume", wt.DWORD), ("high", wt.DWORD),
                ("low", wt.DWORD), ("links", wt.DWORD), ("index_high", wt.DWORD), ("index_low", wt.DWORD)]

    @property
    def size(self):
        return self.high << 32 | self.low

    @property
    def revision(self):
        return (self.volume, self.index_high, self.index_low, self.size,
                self.modified.dwHighDateTime, self.modified.dwLowDateTime)


class Native:
    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows APIs unavailable")
        self.k = ct.WinDLL("kernel32", use_last_error=True)
        self.a = ct.WinDLL("advapi32", use_last_error=True)
        ptr, handle, dword, boolean = ct.c_void_p, wt.HANDLE, wt.DWORD, wt.BOOL
        signatures = {
            "CreateFileW": ([wt.LPCWSTR, dword, dword, ptr, dword, dword, handle], handle),
            "CreateDirectoryW": ([wt.LPCWSTR, ptr], boolean), "CloseHandle": ([handle], boolean),
            "GetFileInformationByHandle": ([handle, ct.POINTER(Info)], boolean),
            "GetFileType": ([handle], dword), "LocalFree": ([ptr], ptr),
            "GetCurrentProcess": ([], handle), "GetCurrentThread": ([], handle),
            "ReadFile": ([handle, ptr, dword, ct.POINTER(dword), ptr], boolean),
            "WriteFile": ([handle, ptr, dword, ct.POINTER(dword), ptr], boolean),
            "FlushFileBuffers": ([handle], boolean),
            "SetFileInformationByHandle": ([handle, ct.c_int, ptr, dword], boolean),
            "LockFileEx": ([handle, dword, dword, dword, dword, ptr], boolean),
            "GetDriveTypeW": ([wt.LPCWSTR], wt.UINT),
            "GetVolumeInformationByHandleW": ([handle, wt.LPWSTR, dword, ptr, ptr, ptr, wt.LPWSTR, dword], boolean),
        }
        for name, (args, returns) in signatures.items():
            f = getattr(self.k, name); f.argtypes, f.restype = args, returns
        signatures = {
            "OpenThreadToken": ([handle, dword, boolean, ct.POINTER(handle)], boolean),
            "OpenProcessToken": ([handle, dword, ct.POINTER(handle)], boolean),
            "GetTokenInformation": ([handle, ct.c_int, ptr, dword, ct.POINTER(dword)], boolean),
            "ConvertSidToStringSidW": ([ptr, ct.POINTER(ptr)], boolean),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW": ([wt.LPCWSTR, dword, ct.POINTER(ptr), ptr], boolean),
            "GetSecurityInfo": ([handle, dword, dword, ptr, ptr, ptr, ptr, ct.POINTER(ptr)], dword),
            "GetSecurityDescriptorControl": ([ptr, ct.POINTER(ct.c_ushort), ct.POINTER(dword)], boolean),
            "GetSecurityDescriptorDacl": ([ptr, ct.POINTER(boolean), ct.POINTER(ptr), ct.POINTER(boolean)], boolean),
            "GetAce": ([ptr, dword, ct.POINTER(ptr)], boolean),
        }
        for name, (args, returns) in signatures.items():
            f = getattr(self.a, name); f.argtypes, f.restype = args, returns
        self.user = self.user_sid()

    def require(self, value):
        if not value:
            raise ct.WinError(ct.get_last_error())
        return value

    def sid(self, pointer):
        value = ct.c_void_p()
        self.require(self.a.ConvertSidToStringSidW(pointer, ct.byref(value)))
        try:
            return ct.wstring_at(value)
        finally:
            self.k.LocalFree(value)

    def user_sid(self):
        token = wt.HANDLE()
        if not self.a.OpenThreadToken(self.k.GetCurrentThread(), 8, True, ct.byref(token)):
            if ct.get_last_error() != 1008:
                raise ct.WinError(ct.get_last_error())
            self.require(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 8, ct.byref(token)))
        try:
            size = wt.DWORD()
            self.a.GetTokenInformation(token, 1, None, 0, ct.byref(size))
            if not size.value or size.value > 65536:
                raise OSError("Token unavailable")
            buf = ct.create_string_buffer(size.value)
            self.require(self.a.GetTokenInformation(token, 1, buf, size, ct.byref(size)))
            return self.sid(ct.c_void_p.from_buffer(buf))
        finally:
            self.close(token)

    @contextmanager
    def security_attributes(self):
        class Attributes(ct.Structure):
            _fields_ = [("length", wt.DWORD), ("descriptor", ct.c_void_p), ("inherit", wt.BOOL)]
        descriptor = ct.c_void_p()
        # Protected ACL at creation: no interval with inherited broad permissions.
        sddl = f"D:P(A;OICI;FA;;;{self.user})(A;OICI;FA;;;SY)"
        self.require(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ct.byref(descriptor), None))
        try:
            attrs = Attributes(ct.sizeof(Attributes), descriptor, False)
            yield ct.byref(attrs)
        finally:
            self.k.LocalFree(descriptor)

    def close(self, handle):
        self.k.CloseHandle(handle)

    def create_directory(self, path):
        with self.security_attributes() as attrs:
            if not self.k.CreateDirectoryW(str(path), attrs) and ct.get_last_error() != 183:
                raise ct.WinError(ct.get_last_error())

    def open_directory(self, path, final=False, writable=False):
        # Ancestors deny write/delete sharing. The private final directory allows concurrent
        # cache handles but never delete sharing; writers need add-file/delete-child for rename.
        return self.open(path, CONTROL | 0x81 | (0x42 if writable else 0),
                         3 if final else 1, 3, directory=True)

    def open(self, path, access=READ | CONTROL, share=5, disposition=3, directory=False, private=False):
        @contextmanager
        def attributes():
            if private:
                with self.security_attributes() as value:
                    yield value
            else:
                yield None
        with attributes() as attrs:
            handle = self.k.CreateFileW(str(path), access, share, attrs, disposition,
                                       0x00300000 | (0x02000000 if directory else 0), None)
        if handle == ct.c_void_p(-1).value:
            raise ct.WinError(ct.get_last_error())
        return handle

    def info(self, handle, directory=False, private=True):
        info = Info()
        self.require(self.k.GetFileInformationByHandle(handle, ct.byref(info)))
        # Reject reparse points and cloud offline/recall placeholders without reading data.
        if info.attributes & (0x400 | 0x1000 | 0x40000 | 0x400000) or bool(info.attributes & 0x10) != directory:
            raise OSError("Cache type or residency unavailable")
        if not directory and (self.k.GetFileType(handle) != 1 or info.links != 1):
            raise OSError("Cache must be a single-link disk file")
        if private:
            self.private_acl(handle)
        return info

    def private_acl(self, handle):
        from .windows_owner import owns_handle
        if not owns_handle(handle):
            raise OSError("Cache owner unavailable")
        descriptor = ct.c_void_p()
        code = self.a.GetSecurityInfo(handle, 1, 4, None, None, None, None, ct.byref(descriptor))
        if code:
            raise ct.WinError(code)
        try:
            control, revision = ct.c_ushort(), wt.DWORD()
            self.require(self.a.GetSecurityDescriptorControl(descriptor, ct.byref(control), ct.byref(revision)))
            present, defaulted, acl = wt.BOOL(), wt.BOOL(), ct.c_void_p()
            self.require(self.a.GetSecurityDescriptorDacl(descriptor, ct.byref(present), ct.byref(acl), ct.byref(defaulted)))
            if not control.value & 0x1000 or not present.value or not acl:
                raise OSError("Cache requires a protected private DACL")
            # ACL header: BYTE revision, BYTE reserved, WORD size, WORD AceCount.
            count = ct.c_ushort.from_address(acl.value + 4).value
            if not 1 <= count <= 64:
                raise OSError("Cache DACL unavailable")
            for i in range(count):
                ace = ct.c_void_p()
                self.require(self.a.GetAce(acl, i, ct.byref(ace)))
                kind, flags = ct.c_ubyte.from_address(ace.value).value, ct.c_ubyte.from_address(ace.value + 1).value
                # Only ordinary allow ACEs for the effective user and SYSTEM. Unknown/object/callback
                # ACEs and inherit-only entries cannot establish this cache's privacy.
                if kind != 0 or flags & 8 or self.sid(ct.c_void_p(ace.value + 8)) not in {self.user, "S-1-5-18"}:
                    raise OSError("Cache DACL is not private")
        finally:
            self.k.LocalFree(descriptor)

    def local_volume(self, handle, anchor):
        if self.k.GetDriveTypeW(str(anchor)) != 3:
            raise OSError("Cache requires a local fixed volume")
        filesystem = ct.create_unicode_buffer(64)
        self.require(self.k.GetVolumeInformationByHandleW(handle, None, 0, None, None, None, filesystem, 64))
        if filesystem.value not in {"NTFS", "ReFS"}:
            raise OSError("Cache filesystem unavailable")

    def read(self, handle, size):
        buf, got = ct.create_string_buffer(size), wt.DWORD()
        self.require(self.k.ReadFile(handle, buf, size, ct.byref(got), None))
        return buf.raw[:got.value]

    def write(self, handle, data):
        written = wt.DWORD()
        self.require(self.k.WriteFile(handle, data, len(data), ct.byref(written), None))
        if written.value != len(data):
            raise OSError("Short cache write")

    def flush(self, handle):
        self.require(self.k.FlushFileBuffers(handle))

    def lock(self, handle):
        class Overlapped(ct.Structure):
            _fields_ = [("internal", ct.c_size_t), ("high", ct.c_size_t), ("offset", wt.DWORD),
                        ("offset_high", wt.DWORD), ("event", wt.HANDLE)]
        overlap = Overlapped()
        if not self.k.LockFileEx(handle, 3, 0, 1, 0, ct.byref(overlap)):
            if ct.get_last_error() in {32, 33}:
                return False
            raise ct.WinError(ct.get_last_error())
        return True

    def rename(self, handle, parent, name):
        class Rename(ct.Structure):
            _fields_ = [("flags", wt.DWORD), ("root", wt.HANDLE), ("length", wt.DWORD), ("name", wt.WCHAR * 1)]
        encoded = name.encode("utf-16-le")
        value = ct.create_string_buffer(ct.sizeof(Rename) + len(encoded))
        info = Rename.from_buffer(value)
        info.flags, info.root, info.length = 1, parent, len(encoded)
        ct.memmove(ct.addressof(value) + Rename.name.offset, encoded, len(encoded))
        self.require(self.k.SetFileInformationByHandle(handle, 3, value, len(value)))

    def remove(self, handle):
        value = ct.c_ubyte(1)
        self.require(self.k.SetFileInformationByHandle(handle, 4, ct.byref(value), ct.sizeof(value)))


class Store:
    def __init__(self, settings, cancel=None, deadline=None):
        self.settings, self.cancel = settings, cancel
        self.deadline = deadline if deadline is not None else time.monotonic() + 5
        self.api = None
        self.handles = []

    def check(self):
        if (self.cancel is not None and self.cancel.is_set()) or time.monotonic() >= self.deadline:
            raise OSError("Cache interrupted")

    @contextmanager
    def open(self, create=False, file_lock=True):
        self.check()
        if not _LOCK.acquire(False):
            raise OSError("Cache busy")
        try:
            self.api = Native()
            self.path = Path(self.settings["directory"])
            parsed = PureWindowsPath(str(self.path))
            if (not parsed.is_absolute() or not re.fullmatch(r"[A-Za-z]:\\", parsed.anchor)
                    or any(part in {"..", "."} or ":" in part or part.endswith((" ", ".")) for part in parsed.parts[1:])
                    or len(parsed.parts) < 2):
                raise OSError("Invalid local cache path")
            current = Path(parsed.anchor)
            for i, part in enumerate((None, *parsed.parts[1:])):
                self.check()
                if part:
                    current /= part
                if part in {"CloudStorage", "Mobile Documents"} or (part and part.lower().startswith("onedrive")):
                    raise OSError("Cloud cache unavailable")
                final = i == len(parsed.parts) - 1
                try:
                    handle = self.api.open_directory(current, final=final, writable=final and file_lock)
                except FileNotFoundError:
                    if not final or not create:
                        if not create:
                            yield None
                            return
                        from .process_store import MissingParent
                        raise MissingParent("Cache parent missing") from None
                    self.api.create_directory(current)
                    handle = self.api.open_directory(current, final=final, writable=final and file_lock)
                self.handles.append(handle)
                self.api.info(handle, directory=True, private=final)
                if i == 0:
                    self.api.local_volume(handle, parsed.anchor)
            self.parent = self.handles[-1]
            if file_lock:
                lock = self.api.open(self.path / ".lock", READ | WRITE | CONTROL, 3, 4, private=True)
                self.handles.append(lock)
                self.api.info(lock)
                until = min(self.deadline, time.monotonic() + 1)
                while not self.api.lock(lock):
                    self.check()
                    if time.monotonic() >= until:
                        raise OSError("Cache busy")
                    time.sleep(.01)
            yield self
        finally:
            for handle in reversed(self.handles):
                self.api.close(handle)
            self.handles.clear()
            _LOCK.release()

    def name(self, name):
        if not isinstance(name, str) or not managed(name):
            raise OSError("Invalid cache entry")
        return self.path / name

    def unchanged(self):
        self.check()
        self.api.info(self.parent, directory=True)

    def names(self):
        self.unchanged()
        names = []
        for entry in self.path.iterdir():
            self.check()
            names.append(entry.name)
            if len(names) > 1000:
                raise OSError("Cache enumeration limit")
        return names

    def read(self, name, limit):
        self.unchanged()
        handle = self.api.open(self.name(name))
        try:
            before = self.api.info(handle)
            if before.size > limit:
                raise OSError("Cache read limit")
            data = bytearray()
            while len(data) <= limit:
                self.check()
                block = self.api.read(handle, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = self.api.info(handle)
            if len(data) > limit or before.revision != after.revision or len(data) != before.size:
                raise OSError("Cache changed during read")
            return bytes(data), before
        finally:
            self.api.close(handle)

    def used(self):
        total = 0
        for name in self.names():
            if managed(name):
                handle = self.api.open(self.name(name), share=3 if name == ".lock" else 5)
                try:
                    total += self.api.info(handle).size
                finally:
                    self.api.close(handle)
        return total

    def cleanup(self):
        for name in self.names():
            if _TEMP.fullmatch(name):
                self.unchanged()
                handle = self.api.open(self.name(name), READ | DELETE | CONTROL, 1)
                try:
                    self.api.info(handle)
                    self.api.remove(handle)
                finally:
                    self.api.close(handle)

    def atomic(self, name, data, limit):
        if name not in {"current.json", "previous.json", "attempt.json"}:
            raise OSError("Invalid cache publication target")
        self.name(name)
        self.unchanged()
        if len(data) > limit or self.used() + len(data) > self.settings["max_total_mb"] * 1024 * 1024:
            raise OSError("Cache capacity reached")
        try:
            self.read(name, limit)
        except FileNotFoundError:
            pass
        temp = "." + secrets.token_hex(16) + ".tmp"
        handle = self.api.open(self.name(temp), WRITE | READ | DELETE | CONTROL, 1, 1, private=True)
        published = False
        try:
            self.api.info(handle)
            for offset in range(0, len(data), 65536):
                self.check()
                self.api.write(handle, data[offset:offset + 65536])
            self.api.flush(handle)
            self.unchanged()
            self.api.rename(handle, self.parent, name)
            published = True
            # Publication is the commit point: no cancellation check after successful rename.
        finally:
            try:
                if not published:
                    self.api.remove(handle)
            finally:
                self.api.close(handle)
