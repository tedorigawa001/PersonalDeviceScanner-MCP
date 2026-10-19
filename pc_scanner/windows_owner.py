"""Windows ownership checks on already opened handles; no optional packages needed."""
import ctypes
from ctypes import wintypes


def owns_handle(handle: int) -> bool:
    """Accept the token user, or Administrators only for an elevated token's default owner.

    Token groups alone are insufficient: an unelevated administrator must not trust an
    Administrators-owned file. API failures raise OSError and callers fail closed.
    """
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.POINTER(pointer), pointer, pointer, pointer, ctypes.POINTER(pointer)]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.OpenThreadToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL,
                                      ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenThreadToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.EqualSid.argtypes = [pointer, pointer]
    advapi.EqualSid.restype = wintypes.BOOL
    advapi.IsWellKnownSid.argtypes = [pointer, ctypes.c_int]
    advapi.IsWellKnownSid.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetCurrentThread.argtypes = []
    kernel.GetCurrentThread.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    owner, descriptor, token = pointer(), pointer(), wintypes.HANDLE()
    code = advapi.GetSecurityInfo(handle, 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor))
    if code:
        raise ctypes.WinError(code)
    try:
        if not owner:
            return False
        if not advapi.OpenThreadToken(kernel.GetCurrentThread(), 0x0008, True, ctypes.byref(token)):
            error = ctypes.get_last_error()
            if error != 1008:  # ERROR_NO_TOKEN; other errors must not fall back to a stronger identity.
                raise ctypes.WinError(error)
            if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
                raise ctypes.WinError(ctypes.get_last_error())
        try:
            def information(kind):
                size = wintypes.DWORD()
                advapi.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
                if not size.value:
                    raise ctypes.WinError(ctypes.get_last_error())
                buffer = ctypes.create_string_buffer(size.value)
                if not advapi.GetTokenInformation(token, kind, buffer, size, ctypes.byref(size)):
                    raise ctypes.WinError(ctypes.get_last_error())
                return buffer

            user = information(1)  # TOKEN_USER starts with SID_AND_ATTRIBUTES.Sid.
            if advapi.EqualSid(owner, pointer.from_buffer(user)):
                return True
            elevation = information(20)  # TOKEN_ELEVATION.TokenIsElevated.
            if not wintypes.DWORD.from_buffer(elevation).value or not advapi.IsWellKnownSid(owner, 26):
                return False
            default_owner = information(4)  # TOKEN_OWNER.Owner.
            return bool(advapi.EqualSid(owner, pointer.from_buffer(default_owner)))
        finally:
            kernel.CloseHandle(token)
    finally:
        kernel.LocalFree(descriptor)


def owns_fd(fd: int) -> bool:
    import msvcrt
    return owns_handle(msvcrt.get_osfhandle(fd))


def owns_directory(path) -> bool:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    # READ_CONTROL; share read/write/delete; OPEN_EXISTING; BACKUP_SEMANTICS and OPEN_REPARSE_POINT.
    handle = kernel.CreateFileW(str(path), 0x20000, 7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return owns_handle(handle)
    finally:
        kernel.CloseHandle(handle)
