"""Read-only macOS extended-ACL guard shared by local stores.

An allow ACE can grant access despite 0600/0700 mode bits. Do not strip ACLs:
unknown states and any non-deny entry are unsafe. Other platforms retain their
existing mode/ownership or native Windows policies.
"""
import errno
import os
import sys

# Darwin SDK sys/acl.h: ACL_ADD_FILE, ACL_DELETE, ACL_ADD_SUBDIRECTORY, ACL_DELETE_CHILD, ACL_WRITE_SECURITY and
# ACL_CHANGE_OWNER. Any of them lets another account add, remove or rename entries, or take over the folder.
REDIRECT = 1 << 2 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 12 | 1 << 13


def acl_allows(fd):
    return _query(fd)


def acl_allows_redirect(fd):
    """For folders above a store: read-only allow entries are harmless, but changing entries redirects the path."""
    return _query(fd, mask=REDIRECT)


def acl_allows_path(path):
    """Metadata-only pathname query for directories/targets without read-data permission."""
    return _query(os.fsencode(path), pathname=True)


def _query(value, *, pathname=False, mask=None):
    """Whether a macOS ACL on fd allows anything (or anything in mask); such entries apply regardless of the mode.

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
    lib.acl_get_permset_mask_np.argtypes = [c.c_void_p, c.POINTER(c.c_uint64)]
    lib.acl_free.argtypes = [c.c_void_p]
    # Darwin SDK sys/acl.h: ACL_TYPE_EXTENDED = 0x100, ACL_FIRST_ENTRY = 0, ACL_NEXT_ENTRY = -1,
    # ACL_EXTENDED_ALLOW = 1, ACL_EXTENDED_DENY = 2.
    c.set_errno(0)
    acl = getter(value, 0x100)
    if not acl:
        return c.get_errno() != errno.ENOENT
    try:
        entry, tag, perms, index = c.c_void_p(), c.c_int(), c.c_uint64(), 0
        for _ in range(1024):
            c.set_errno(0)
            if lib.acl_get_entry(acl, index, c.byref(entry)) != 0:
                # Darwin uses -1/EINVAL for the end, unlike Linux's 0.
                return c.get_errno() != errno.EINVAL
            if lib.acl_get_tag_type(entry, c.byref(tag)) != 0:
                return True
            if tag.value != 2 and (mask is None or tag.value != 1
                                   or lib.acl_get_permset_mask_np(entry, c.byref(perms)) != 0 or perms.value & mask):
                return True
            index = -1
        return True  # unexpected/unbounded ACL iteration
    finally:
        lib.acl_free(acl)
