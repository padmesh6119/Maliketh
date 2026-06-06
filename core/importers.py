# importers — map common browser/manager CSV exports into vault entries
import csv


def _pick(row, *needles):
    for needle in needles:
        for key, value in row.items():
            if needle in key:
                return value or ""
    return ""


def csv_to_entries(path):
    entries = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            row = {(k or "").strip().lower(): (v or "") for k, v in raw.items()}
            entry = {
                "title": (_pick(row, "name", "title") or _pick(row, "url", "uri")).strip(),
                "username": _pick(row, "username", "user", "email", "login_username").strip(),
                "password": _pick(row, "password", "login_password"),
                "url": _pick(row, "login_uri", "url", "uri", "website").strip(),
                "totp": _pick(row, "totp", "otpauth", "authenticator").strip(),
                "notes": _pick(row, "notes", "note", "comment"),
            }
            if entry["password"] or entry["username"] or entry["title"]:
                entries.append(entry)
    return entries
