# secure memory helpers
import ctypes
import hmac


def _buffer_addr_len(buf):
    arr = (ctypes.c_char * len(buf)).from_buffer(buf)
    return ctypes.addressof(arr), len(buf)


def _libc():
    return ctypes.CDLL("libc.so.6", use_errno=True)


def _try_mlock(buf):
    if len(buf) == 0:
        return False
    try:
        addr, length = _buffer_addr_len(buf)
        return _libc().mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)) == 0
    except Exception:
        return False


def _try_munlock(buf):
    if len(buf) == 0:
        return
    try:
        addr, length = _buffer_addr_len(buf)
        _libc().munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
    except Exception:
        pass


def _zero(buf):
    length = len(buf)
    if length == 0:
        return
    try:
        ctypes.memset((ctypes.c_char * length).from_buffer(buf), 0, length)
    except Exception:
        for i in range(length):
            buf[i] = 0


class Secret:
    __slots__ = ("_buf", "_locked", "_wiped")

    def __init__(self, buf):
        if not isinstance(buf, bytearray):
            raise TypeError("Secret requires a bytearray")
        self._buf = buf
        self._wiped = False
        self._locked = _try_mlock(buf)

    @property
    def bytes(self):
        if self._wiped:
            raise ValueError("secret has been wiped")
        return bytes(self._buf)

    @property
    def raw(self):
        if self._wiped:
            raise ValueError("secret has been wiped")
        return self._buf

    def __len__(self):
        return 0 if self._wiped else len(self._buf)

    def wipe(self):
        if self._wiped:
            return
        _zero(self._buf)
        if self._locked:
            _try_munlock(self._buf)
            self._locked = False
        self._wiped = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.wipe()
        return False

    def __del__(self):
        try:
            self.wipe()
        except Exception:
            pass


def constant_time_eq(a, b):
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)
