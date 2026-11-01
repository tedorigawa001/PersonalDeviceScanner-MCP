"""Read-only macOS extended-ACL guard shared by local stores.

An allow ACE can grant access despite 0600/0700 mode bits. Do not strip ACLs:
unknown states and any non-deny entry are unsafe. Other platforms retain their
existing mode/ownership or native Windows policies.
"""
import errno
import os
import sys


def acl_allows(fd):
    return _query(fd)


def acl_allows_path(path):
    """Metadata-only pathname query for directories/targets without read-data permission."""
    return _query(os.fsencode(path), pathname=True)


def _query(value, *, pathname=False):
    """Whether a macOS ACL on fd allows anything; such entries apply regardless of the 0600/0700 mode.

    A folder's inheritable entry is copied to new records, so others could read them. Linux needs no check:
    its ACL entries are limited by the group mode bits, which the store requires to be 0.
    """
    if sys.platform != "darwin":
        return False
    import ctypes as c
    lib = c.CDLL(None, use_errno=True)
    getter = lib.acl_get_file if pathname else lib.acl_get_fd_np
    getter.argtypes = [c.c_char_p if pathname else c.c_int, c.c_int]
    getter.restype = c.c_void_p
    lib.acl_get_entry.argtypes = [c.c_void_p, c.c_int, c.POINTER(c.c_void_p)]
    lib.acl_get_tag_type.argtypes = [c.c_void_p, c.POINTER(c.c_int)]
    lib.acl_free.argtypes = [c.c_void_p]
    # Darwin SDK sys/acl.h: ACL_TYPE_EXTENDED = 0x100, ACL_FIRST_ENTRY = 0, ACL_NEXT_ENTRY = -1, ACL_EXTENDED_DENY = 2.
    c.set_errno(0)
    acl = getter(value, 0x100)
    if not acl:
        return c.get_errno() != errno.ENOENT
    try:
        entry, tag, index = c.c_void_p(), c.c_int(), 0
        for _ in range(1024):
            c.set_errno(0)
            if lib.acl_get_entry(acl, index, c.byref(entry)) != 0:
                # Darwin uses -1/EINVAL for the end, unlike Linux's 0.
                return c.get_errno() != errno.EINVAL
            if lib.acl_get_tag_type(entry, c.byref(tag)) != 0 or tag.value != 2:
                return True
            index = -1
        return True  # unexpected/unbounded ACL iteration
    finally:
        lib.acl_free(acl)
