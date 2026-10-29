"""Small synchronous WSARecvMsg adapter. No worker thread or overlapped I/O survives cancellation."""
import ctypes
import socket
import struct
import uuid


def controls(data, word_size=struct.calcsize("P")):
    """WSACMSGHDR uses SIZE_T then two ints, padded to pointer alignment."""
    header = word_size + 8
    aligned = (header + word_size - 1) // word_size * word_size
    offset, values = 0, []
    while offset + header <= len(data):
        length = int.from_bytes(data[offset:offset + word_size], "little")
        if length < aligned or offset + length > len(data):
            raise OSError("Invalid Winsock ancillary length")
        level, kind = struct.unpack_from("=ii", data, offset + word_size)
        values.append((level, kind, data[offset + aligned:offset + length]))
        offset += (length + word_size - 1) // word_size * word_size
    return values


class Buffer(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint32), ("buf", ctypes.c_void_p)]


class Message(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_int), ("buffers", ctypes.POINTER(Buffer)),
                ("count", ctypes.c_uint32), ("control", Buffer), ("flags", ctypes.c_uint32)]


class Receiver:
    Buffer, Message = Buffer, Message

    def __init__(self, sock):
        self.socket = sock
        uint = ctypes.c_uint32
        self.ws = ctypes.WinDLL("Ws2_32.dll", use_last_error=True)
        ioctl = self.ws.WSAIoctl
        ioctl.argtypes = [ctypes.c_size_t, uint, ctypes.c_void_p, uint, ctypes.c_void_p, uint,
                          ctypes.POINTER(uint), ctypes.c_void_p, ctypes.c_void_p]
        ioctl.restype = ctypes.c_int
        guid = ctypes.create_string_buffer(uuid.UUID("f689d7c8-6f1f-436b-8a53-e54fe351c322").bytes_le)
        pointer, returned = ctypes.c_void_p(), uint()
        if ioctl(sock.fileno(), 0xC8000006, guid, 16, ctypes.byref(pointer), ctypes.sizeof(pointer),
                 ctypes.byref(returned), None, None) != 0 or not pointer.value:
            raise OSError("WSARecvMsg is unavailable")
        self.receive = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(Message),
                                         ctypes.POINTER(uint), ctypes.c_void_p, ctypes.c_void_p)(pointer.value)
        self.ws.WSAGetLastError.restype = ctypes.c_int

    def sendmsg(self, buffers, ancillary, flags, destination):
        """Only used for IPv6: specify the authorized source address and interface with IPV6_PKTINFO."""
        uint = ctypes.c_uint32
        guid = ctypes.create_string_buffer(uuid.UUID("a441e712-754f-43ca-84a7-0dee44cf606d").bytes_le)
        pointer, returned = ctypes.c_void_p(), uint()
        if self.ws.WSAIoctl(self.socket.fileno(), 0xC8000006, guid, 16, ctypes.byref(pointer),
                           ctypes.sizeof(pointer), ctypes.byref(returned), None, None) != 0 or not pointer.value:
            raise OSError("WSASendMsg is unavailable")
        send = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(self.Message), uint,
                                 ctypes.POINTER(uint), ctypes.c_void_p, ctypes.c_void_p)(pointer.value)
        data = ctypes.create_string_buffer(b"".join(buffers))
        level, kind, value = ancillary[0]
        word = ctypes.sizeof(ctypes.c_size_t)
        header = word + 8
        length = header + len(value)
        control = length.to_bytes(word, "little") + struct.pack("=ii", level, kind) + value
        control += b"\0" * (-len(control) % word)
        control = ctypes.create_string_buffer(control)
        # sockaddr_in6: family native, port network, flowinfo, address, scope native.
        peer = ctypes.create_string_buffer(struct.pack("=H", socket.AF_INET6) + struct.pack("!H", destination[1])
            + b"\0" * 4 + socket.inet_pton(socket.AF_INET6, destination[0]) + struct.pack("=I", destination[3]))
        buf = self.Buffer(len(data.raw) - 1, ctypes.addressof(data))
        msg = self.Message(ctypes.addressof(peer), 28, ctypes.pointer(buf), 1,
                           self.Buffer(len(control.raw) - 1, ctypes.addressof(control)), 0)
        count = uint()
        if send(self.socket.fileno(), ctypes.byref(msg), flags, ctypes.byref(count), None, None) != 0:
            raise OSError(self.ws.WSAGetLastError(), "WSASendMsg failed")
        return count.value

    def __getattr__(self, name):
        return getattr(self.socket, name)

    def recvmsg(self, size, control_size):
        payload, control, peer = (ctypes.create_string_buffer(size), ctypes.create_string_buffer(control_size),
                                  ctypes.create_string_buffer(128))
        buf = self.Buffer(size, ctypes.addressof(payload))
        msg = self.Message(ctypes.addressof(peer), len(peer), ctypes.pointer(buf), 1,
                           self.Buffer(control_size, ctypes.addressof(control)), 0)
        count, truncated = ctypes.c_uint32(), 0
        if self.receive(self.socket.fileno(), ctypes.byref(msg), ctypes.byref(count), None, None) != 0:
            code = self.ws.WSAGetLastError()
            if code == 10035:
                raise BlockingIOError
            if code != 10040:
                raise OSError(code, "WSARecvMsg failed")
            # WSAEMSGSIZE: the datagram was cut to the buffer. Report it truncated, as recvmsg does elsewhere,
            # so the collector applies its limit instead of failing the whole method.
            count.value, truncated = size, 0x0100
        family = struct.unpack_from("=H", peer.raw)[0]
        port = struct.unpack_from("!H", peer.raw, 2)[0]
        if family == socket.AF_INET:
            source = (socket.inet_ntop(family, peer.raw[4:8]), port)
        elif family == socket.AF_INET6:
            source = (socket.inet_ntop(family, peer.raw[8:24]), port, 0, struct.unpack_from("=I", peer.raw, 24)[0])
        else:
            raise OSError("Unexpected address family")
        return payload.raw[:count.value], controls(control.raw[:msg.control.len]), msg.flags | truncated, source
