# persistent session agent — sole holder of the unlocked key
import asyncio
import json
import logging
import os
import socket
import struct
import time

from . import protocol as P
from .vault import BadPassword, Locked, Vault, VaultError, generate_passphrase, generate_password

log = logging.getLogger("maliketh.agent")

DEFAULT_TIMEOUT = 600
ACTIVITY_METHODS = {
    "unlock", "init", "list", "get", "add", "update", "delete",
    "match", "fill", "capture", "totp", "export", "import", "generate",
}
KDF_METHODS = {"unlock", "init", "change_password"}


def _load_config():
    try:
        with open(P.CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_config(cfg):
    try:
        with open(P.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        os.chmod(P.CONFIG_PATH, 0o600)
    except OSError:
        pass


def _peer_uid_ok(sock):
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        return uid == os.getuid()
    except (OSError, AttributeError):
        return True


class Agent:
    def __init__(self):
        self.vault = Vault(P.VAULT_PATH)
        self.kdf_lock = asyncio.Lock()
        self.last_activity = time.time()
        self.fail_count = 0
        self.fail_until = 0.0
        cfg = _load_config()
        self.timeout = int(cfg.get("auto_lock_seconds", DEFAULT_TIMEOUT))
        self.allow_browser_unlock = bool(cfg.get("allow_browser_unlock", False))

    def touch(self):
        self.last_activity = time.time()

    async def idle_loop(self):
        while True:
            await asyncio.sleep(5)
            if self.vault.unlocked and self.timeout > 0:
                if time.time() - self.last_activity > self.timeout:
                    self.vault.lock()
                    log.info("auto-locked after %ss idle", self.timeout)

    async def handle(self, reader, writer):
        sock = writer.get_extra_info("socket")
        if sock is not None and not _peer_uid_ok(sock):
            log.warning("rejected connection from foreign uid")
            writer.close()
            return
        try:
            while True:
                msg = await P.read_frame(reader)
                if msg is None:
                    break
                resp = await self.dispatch(msg)
                await P.write_frame(writer, resp)
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def dispatch(self, msg):
        method = msg.get("method")
        if not isinstance(method, str):
            return {"ok": False, "error": "missing method"}
        if method in ACTIVITY_METHODS:
            self.touch()
        try:
            if method in KDF_METHODS:
                async with self.kdf_lock:
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, self._handle_sync, method, msg
                    )
            else:
                result = self._handle_sync(method, msg)
            if result is None:
                result = {}
            result.setdefault("ok", True)
            return result
        except Locked:
            return {"ok": False, "error": "vault is locked", "locked": True}
        except BadPassword as e:
            return {"ok": False, "error": str(e), "bad_password": True}
        except VaultError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:  # noqa: BLE001
            log.exception("dispatch error")
            return {"ok": False, "error": "internal error: %s" % e}

    def _handle_sync(self, method, msg):
        v = self.vault
        if method == "ping":
            return {"pong": True, "version": __import__("core").__version__}
        if method == "status":
            return {
                "locked": not v.unlocked,
                "vault_exists": v.exists(),
                "entry_count": len(v.entries) if v.unlocked else None,
                "timeout": self.timeout,
                "allow_browser_unlock": self.allow_browser_unlock,
            }
        if method == "init":
            v.create(msg.get("password", ""))
            return {"created": True}
        if method == "unlock":
            if msg.get("source") == "browser" and not self.allow_browser_unlock:
                raise VaultError("browser unlock is disabled; enable it in the desktop app settings")
            wait = self.fail_until - time.time()
            if wait > 0:
                raise BadPassword("too many attempts; wait %ds" % int(wait + 1))
            try:
                v.unlock(msg.get("password", ""))
            except BadPassword:
                self.fail_count += 1
                if self.fail_count >= 5:
                    self.fail_until = time.time() + min(60, 2 ** (self.fail_count - 5))
                raise
            self.fail_count = 0
            self.fail_until = 0.0
            return {"unlocked": True, "entry_count": len(v.entries)}
        if method == "lock":
            v.lock()
            return {"locked": True}
        if method == "list":
            return {"entries": v.list()}
        if method == "get":
            return {"entry": v.get(msg["id"])}
        if method == "add":
            return {"id": v.add(msg.get("entry", {}))}
        if method == "update":
            return {"id": v.update(msg["id"], msg.get("entry", {}))}
        if method == "delete":
            v.delete(msg["id"])
            return {"deleted": True}
        if method == "match":
            return {"entries": v.match(msg.get("url", ""))}
        if method == "fill":
            return {"entry": v.fill(msg["id"], msg.get("url", ""))}
        if method == "capture":
            return v.capture(msg.get("url", ""), msg.get("username", ""), msg.get("password", ""))
        if method == "totp":
            return v.totp(msg["id"])
        if method == "generate":
            opts = dict(msg.get("opts", {}))
            if opts.pop("mode", "") == "passphrase":
                return {"password": generate_passphrase(
                    words=msg.get("length", 5),
                    sep=opts.get("sep", "-"),
                    capitalize=opts.get("capitalize", True),
                    add_number=opts.get("add_number", True),
                )}
            return {"password": generate_password(msg.get("length", 20), **opts)}
        if method == "change_password":
            v.change_password(msg.get("old", ""), msg.get("new", ""))
            return {"changed": True}
        if method == "export":
            return {"vault": v.export()}
        if method == "import":
            return {"imported": v.import_entries(msg.get("entries", []), msg.get("replace", False))}
        if method == "set_timeout":
            self.timeout = max(0, int(msg.get("seconds", DEFAULT_TIMEOUT)))
            cfg = _load_config()
            cfg["auto_lock_seconds"] = self.timeout
            _save_config(cfg)
            return {"timeout": self.timeout}
        if method == "set_browser_unlock":
            self.allow_browser_unlock = bool(msg.get("enabled"))
            cfg = _load_config()
            cfg["allow_browser_unlock"] = self.allow_browser_unlock
            _save_config(cfg)
            return {"allow_browser_unlock": self.allow_browser_unlock}
        raise VaultError("unknown method: %s" % method)


def _another_instance_live():
    if not os.path.exists(P.SOCKET_PATH):
        return False
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(P.SOCKET_PATH)
        probe.close()
        return True
    except OSError:
        try:
            os.unlink(P.SOCKET_PATH)
        except OSError:
            pass
        return False


async def main():
    P.ensure_home()
    logging.basicConfig(
        filename=P.AGENT_LOG,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if _another_instance_live():
        log.info("agent already running, exiting")
        return
    agent = Agent()
    server = await asyncio.start_unix_server(agent.handle, path=P.SOCKET_PATH)
    try:
        os.chmod(P.SOCKET_PATH, 0o600)
    except OSError:
        pass
    log.info("maliketh agent listening on %s", P.SOCKET_PATH)
    asyncio.create_task(agent.idle_loop())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
