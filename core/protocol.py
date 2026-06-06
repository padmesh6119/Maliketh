# ipc framing, paths and shared constants
import asyncio
import json
import os
import struct

HOST_NAME = "com.maliketh.host"
MAX_FRAME = 4 * 1024 * 1024

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MALIKETH_HOME = os.environ.get("MALIKETH_HOME") or os.path.join(
    os.path.expanduser("~"), ".local", "share", "maliketh"
)
VAULT_PATH = os.environ.get("MALIKETH_VAULT") or os.path.join(MALIKETH_HOME, "vault.mlkv")
CONFIG_PATH = os.path.join(MALIKETH_HOME, "config.json")
AGENT_LOG = os.path.join(MALIKETH_HOME, "agent.log")
HOST_LOG = os.path.join(MALIKETH_HOME, "native_host.log")

_RUNTIME = os.environ.get("XDG_RUNTIME_DIR") or MALIKETH_HOME
SOCKET_PATH = os.environ.get("MALIKETH_SOCKET") or os.path.join(_RUNTIME, "maliketh-agent.sock")


def ensure_home():
    os.makedirs(MALIKETH_HOME, mode=0o700, exist_ok=True)
    try:
        os.chmod(MALIKETH_HOME, 0o700)
    except OSError:
        pass
    rt = os.path.dirname(SOCKET_PATH)
    if rt and rt != MALIKETH_HOME:
        os.makedirs(rt, mode=0o700, exist_ok=True)


def send_frame(sock, obj):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock):
    hdr = _recv_exact(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    if n == 0 or n > MAX_FRAME:
        return None
    data = _recv_exact(sock, n)
    if data is None:
        return None
    return json.loads(data.decode("utf-8"))


async def read_frame(reader):
    try:
        hdr = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    (n,) = struct.unpack(">I", hdr)
    if n == 0 or n > MAX_FRAME:
        return None
    try:
        data = await reader.readexactly(n)
    except asyncio.IncompleteReadError:
        return None
    return json.loads(data.decode("utf-8"))


async def write_frame(writer, obj):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


def read_native(stream):
    raw = stream.read(4)
    if raw is None or len(raw) < 4:
        return None
    (n,) = struct.unpack("@I", raw)
    if n == 0 or n > MAX_FRAME:
        return None
    data = stream.read(n)
    if data is None or len(data) < n:
        return None
    return json.loads(data.decode("utf-8"))


def write_native(stream, obj):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("@I", len(data)))
    stream.write(data)
    stream.flush()
