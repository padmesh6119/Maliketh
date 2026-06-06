# browser bridge — native messaging host with a restricted, origin-scoped command set
import logging
import sys

from . import protocol as P
from .client import AgentClient

log = logging.getLogger("maliketh.host")

BROWSER_METHODS = {"status", "match", "fill", "capture", "generate", "lock", "unlock", "ping"}


def _scope(msg):
    mtype = msg.get("type")
    origin = msg.get("origin") or msg.get("url") or ""
    if mtype not in BROWSER_METHODS:
        return None, {"ok": False, "error": "method not permitted from browser"}
    if mtype in ("status", "ping", "lock"):
        return {"method": mtype}, None
    if mtype == "unlock":
        if not msg.get("password"):
            return None, {"ok": False, "error": "missing password"}
        return {"method": "unlock", "password": msg["password"], "source": "browser"}, None
    if mtype == "match":
        if not origin:
            return None, {"ok": False, "error": "missing origin"}
        return {"method": "match", "url": origin}, None
    if mtype == "fill":
        if not origin or not msg.get("entryId"):
            return None, {"ok": False, "error": "missing entryId/origin"}
        return {"method": "fill", "id": msg["entryId"], "url": origin}, None
    if mtype == "capture":
        if not origin or not msg.get("password"):
            return None, {"ok": False, "error": "missing origin/password"}
        return {
            "method": "capture",
            "url": origin,
            "username": msg.get("username", ""),
            "password": msg["password"],
        }, None
    if mtype == "generate":
        return {"method": "generate", "length": msg.get("length", 20), "opts": msg.get("opts", {})}, None
    return None, {"ok": False, "error": "unhandled type"}


def handle(client, msg):
    request, err = _scope(msg)
    if err is not None:
        return err
    try:
        resp = client.request(request)
    except OSError as e:
        return {"ok": False, "error": "agent unavailable: %s" % e}
    if msg.get("type") == "match" and resp.get("ok"):
        resp["entries"] = [
            {"id": e["id"], "title": e["title"], "username": e["username"], "has_totp": e["has_totp"]}
            for e in resp.get("entries", [])
        ]
    return resp


def main():
    P.ensure_home()
    logging.basicConfig(
        filename=P.HOST_LOG,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    client = AgentClient(autostart=True)
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    log.info("native host started")
    while True:
        try:
            msg = P.read_native(stdin)
        except Exception:
            log.exception("failed to read frame")
            break
        if msg is None:
            break
        try:
            resp = handle(client, msg)
        except Exception as e:  # noqa: BLE001
            log.exception("handler error")
            resp = {"ok": False, "error": "host error: %s" % e}
        if "reqId" in msg:
            resp["reqId"] = msg["reqId"]
        try:
            P.write_native(stdout, resp)
        except Exception:
            log.exception("failed to write frame")
            break
    log.info("native host exiting")


if __name__ == "__main__":
    main()
