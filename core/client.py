# client for talking to the agent (used by ui + native host)
import os
import socket
import subprocess
import sys
import time

from . import protocol as P


def _raw_connect():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(P.SOCKET_PATH)
    return s


def agent_running():
    try:
        s = _raw_connect()
        s.close()
        return True
    except OSError:
        return False


def ensure_agent(timeout=15.0):
    if agent_running():
        return True
    P.ensure_home()
    logf = open(P.AGENT_LOG, "ab")
    subprocess.Popen(
        [sys.executable, "-m", "core.agent"],
        cwd=P.PROJECT_ROOT,
        stdout=logf,
        stderr=logf,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        if agent_running():
            return True
        time.sleep(0.1)
    return False


class AgentClient:
    def __init__(self, autostart=True):
        self.autostart = autostart

    def _connect(self):
        try:
            return _raw_connect()
        except OSError:
            if self.autostart and ensure_agent():
                return _raw_connect()
            raise

    def request(self, obj):
        s = self._connect()
        try:
            P.send_frame(s, obj)
            resp = P.recv_frame(s)
            return resp if resp is not None else {"ok": False, "error": "no response from agent"}
        finally:
            try:
                s.close()
            except OSError:
                pass

    def status(self):
        return self.request({"method": "status"})

    def unlock(self, password):
        return self.request({"method": "unlock", "password": password})

    def init(self, password):
        return self.request({"method": "init", "password": password})

    def lock(self):
        return self.request({"method": "lock"})

    def list(self):
        return self.request({"method": "list"})

    def get(self, entry_id):
        return self.request({"method": "get", "id": entry_id})

    def add(self, entry):
        return self.request({"method": "add", "entry": entry})

    def update(self, entry_id, entry):
        return self.request({"method": "update", "id": entry_id, "entry": entry})

    def delete(self, entry_id):
        return self.request({"method": "delete", "id": entry_id})

    def match(self, url):
        return self.request({"method": "match", "url": url})

    def fill(self, entry_id, url):
        return self.request({"method": "fill", "id": entry_id, "url": url})

    def totp(self, entry_id):
        return self.request({"method": "totp", "id": entry_id})

    def generate(self, length=20, **opts):
        return self.request({"method": "generate", "length": length, "opts": opts})

    def change_password(self, old, new):
        return self.request({"method": "change_password", "old": old, "new": new})

    def export(self):
        return self.request({"method": "export"})

    def import_entries(self, entries, replace=False):
        return self.request({"method": "import", "entries": entries, "replace": replace})

    def set_timeout(self, seconds):
        return self.request({"method": "set_timeout", "seconds": seconds})

    def set_browser_unlock(self, enabled):
        return self.request({"method": "set_browser_unlock", "enabled": bool(enabled)})
