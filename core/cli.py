# command-line interface
import argparse
import getpass
import json
import sys

from . import audit as audit_mod
from .client import AgentClient
from .importers import csv_to_entries


def _print(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _need_ok(resp):
    if not resp.get("ok"):
        sys.stderr.write("error: %s\n" % resp.get("error", "failed"))
        sys.exit(1)
    return resp


def main(argv=None):
    ap = argparse.ArgumentParser(prog="maliketh", description="Maliketh vault CLI")
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")
    sub.add_parser("lock")
    sub.add_parser("init")
    sub.add_parser("unlock")

    p = sub.add_parser("list")
    p.add_argument("-q", "--query", default="")

    p = sub.add_parser("get")
    p.add_argument("id")
    p.add_argument("--show", action="store_true", help="reveal password")
    p.add_argument("--field", help="print only one field")

    p = sub.add_parser("add")
    p.add_argument("--title", default="")
    p.add_argument("--username", default="")
    p.add_argument("--url", default="")
    p.add_argument("--totp", default="")
    p.add_argument("--password")
    p.add_argument("--generate", type=int, metavar="LEN", help="generate a password of LEN")

    p = sub.add_parser("rm")
    p.add_argument("id")

    p = sub.add_parser("gen")
    p.add_argument("-n", "--length", type=int, default=None)
    p.add_argument("--passphrase", action="store_true")

    p = sub.add_parser("audit")
    p.add_argument("--breach", action="store_true", help="check Have I Been Pwned (sends a SHA1 prefix only)")

    p = sub.add_parser("import-csv")
    p.add_argument("file")

    args = ap.parse_args(argv)
    c = AgentClient()

    if args.cmd == "status":
        return _print(c.status())

    if args.cmd == "lock":
        return _print(c.lock())

    if args.cmd == "init":
        pw = getpass.getpass("New master password: ")
        if pw != getpass.getpass("Confirm: "):
            sys.exit("passwords do not match")
        return _print(_need_ok(c.init(pw)))

    if args.cmd == "unlock":
        return _print(_need_ok(c.unlock(getpass.getpass("Master password: "))))

    if args.cmd == "list":
        resp = _need_ok(c.list())
        entries = [e for e in resp["entries"] if args.query.lower() in (e["title"] + e["username"]).lower()]
        if args.json:
            return _print(entries)
        for e in entries:
            print("%s  %-28s %s" % (e["id"][:8], e["title"][:28], e["username"]))
        return None

    if args.cmd == "get":
        resp = _need_ok(c.get(args.id))
        e = resp["entry"]
        if not args.show:
            e = dict(e, password="••••••••")
        if args.field:
            return print(e.get(args.field, ""))
        if args.json:
            return _print(e)
        for k in ("title", "username", "password", "url", "totp", "notes"):
            print("%-9s %s" % (k + ":", e.get(k, "")))
        return None

    if args.cmd == "add":
        pw = args.password
        if args.generate:
            pw = _need_ok(c.generate(args.generate))["password"]
        elif pw is None:
            pw = getpass.getpass("Password (blank to generate): ") or _need_ok(c.generate(20))["password"]
        entry = {"title": args.title, "username": args.username, "url": args.url, "totp": args.totp, "password": pw}
        resp = _need_ok(c.add(entry))
        return _print(resp) if args.json else print(resp["id"])

    if args.cmd == "rm":
        return _print(_need_ok(c.delete(args.id)))

    if args.cmd == "gen":
        opts = {"mode": "passphrase"} if args.passphrase else {}
        length = args.length if args.length is not None else (6 if args.passphrase else 20)
        resp = _need_ok(c.generate(length, **opts))
        return print(resp["password"])

    if args.cmd == "audit":
        resp = _need_ok(c.export())
        report = audit_mod.audit(resp["vault"]["entries"], check_breach=args.breach)
        if args.json:
            return _print(report)
        print("entries: %d   weak: %d   reused groups: %d\n" % (report["total"], report["weak"], report["reused_groups"]))
        for i in report["items"]:
            flags = " ".join(f for f, on in [("WEAK", i["weak"]), ("REUSED", i["reused"]), ("PWNED", bool(i["pwned"]))] if on)
            pwned = "" if i["pwned"] in (None, 0) else ("  pwned=%s" % i["pwned"])
            print("  [%3d %-9s] %-28s %-20s %s%s" % (i["score"], i["label"], i["title"][:28], i["username"][:20], flags, pwned))
        return None

    if args.cmd == "import-csv":
        entries = csv_to_entries(args.file)
        resp = _need_ok(c.import_entries(entries))
        return _print(resp) if args.json else print("imported %d entries" % resp["imported"])

    return None


if __name__ == "__main__":
    main()
