# password health — local strength/reuse + opt-in HIBP k-anonymity breach check
import hashlib
import urllib.request

COMMON = {
    "password", "123456", "12345678", "qwerty", "letmein", "admin", "welcome",
    "iloveyou", "monkey", "dragon", "abc123", "111111", "123123", "000000",
    "qwerty123", "password1", "123456789", "1234567890", "passw0rd",
}

LOWER = set("abcdefghijklmnopqrstuvwxyz")
UPPER = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
DIGIT = set("0123456789")
SYMBOL = set("!@#$%^&*()-_=+[]{};:,.<>?/|`~'\"\\ ")


def strength(pw):
    if not pw:
        return 0, "empty"
    score = min(len(pw), 24) * 2.5
    classes = sum(bool(set(pw) & s) for s in (LOWER, UPPER, DIGIT, SYMBOL))
    score += classes * 9
    if len(set(pw)) <= 2:
        score = min(score, 10)
    if pw.lower() in COMMON:
        score = 5
    score = int(max(0, min(100, score)))
    label = (
        "very weak" if score < 30
        else "weak" if score < 50
        else "fair" if score < 70
        else "strong" if score < 90
        else "excellent"
    )
    return score, label


def find_reused(entries):
    by_pw = {}
    for e in entries:
        pw = e.get("password")
        if pw:
            by_pw.setdefault(pw, []).append(e["id"])
    return {pw: ids for pw, ids in by_pw.items() if len(ids) > 1}


def pwned_count(pw, timeout=6):
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        "https://api.pwnedpasswords.com/range/" + prefix,
        headers={"User-Agent": "Maliketh-audit", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "ignore")
    for line in body.splitlines():
        h, _, count = line.partition(":")
        if h.strip().upper() == suffix:
            return int((count or "0").strip() or 0)
    return 0


def audit(entries, check_breach=False):
    reused = find_reused(entries)
    reused_ids = {i for ids in reused.values() for i in ids}
    items = []
    for e in entries:
        score, label = strength(e.get("password", ""))
        item = {
            "id": e["id"],
            "title": e.get("title", ""),
            "username": e.get("username", ""),
            "score": score,
            "label": label,
            "reused": e["id"] in reused_ids,
            "weak": score < 50,
            "pwned": None,
        }
        if check_breach and e.get("password"):
            try:
                item["pwned"] = pwned_count(e["password"])
            except Exception:
                item["pwned"] = -1
        items.append(item)
    items.sort(key=lambda i: (i["score"], not i["reused"]))
    return {
        "items": items,
        "reused_groups": len(reused),
        "weak": sum(1 for i in items if i["weak"]),
        "total": len(items),
    }
