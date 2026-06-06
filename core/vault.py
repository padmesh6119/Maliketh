# crypto + session engine
import base64
import glob
import hashlib
import hmac
import json
import os
import secrets
import shutil
import string
import struct
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit

from argon2.low_level import Type, hash_secret_raw
from nacl import bindings
from nacl.exceptions import CryptoError

from .secure import Secret

MAGIC = "MLKV"
VERSION = 1
KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

ARGON_DEFAULTS = {
    "alg": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
}

AMBIGUOUS = set("O0oIl1|`'\";:.,{}[]()")


class VaultError(Exception):
    pass


class BadPassword(VaultError):
    pass


class Locked(VaultError):
    pass


def _b64e(b):
    return base64.b64encode(b).decode("ascii")


def _b64d(s):
    return base64.b64decode(s.encode("ascii"))


def _now():
    return time.time()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive_key(password, salt, kdf):
    raw = hash_secret_raw(
        secret=password.encode("utf-8") if isinstance(password, str) else password,
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost"],
        parallelism=kdf["parallelism"],
        hash_len=KEY_BYTES,
        type=Type.ID,
    )
    return Secret(bytearray(raw))


def host_of(url):
    if not url:
        return ""
    u = url.strip()
    if "://" not in u and not u.startswith("//"):
        u = "//" + u
    netloc = urlsplit(u).netloc.lower()
    if "@" in netloc:
        netloc = netloc.split("@")[-1]
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return netloc


def domain_matches(entry_url, page_url):
    a = host_of(entry_url)
    b = host_of(page_url)
    if not a or not b:
        return False
    return a == b or b.endswith("." + a) or a.endswith("." + b)


def generate_password(length=20, lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=True):
    length = max(4, min(int(length), 256))
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?/")
    if not pools:
        pools = [string.ascii_letters + string.digits]
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) or p for p in pools]
    chars = "".join(pools)
    while True:
        pw = [secrets.choice(p) for p in pools]
        pw += [secrets.choice(chars) for _ in range(length - len(pw))]
        secrets.SystemRandom().shuffle(pw)
        out = "".join(pw)
        if not avoid_ambiguous or len(out) >= 4:
            return out


_FALLBACK_WORDS = (
    "able acid aged army away baby back ball band bank base bath bear beat been beer "
    "bell belt best bird blue boat body bone book boot born boss both bowl bulk bush "
    "call calm came camp card care case cash cell chat chip city clay club coal coat "
    "code cold come cook cool cope copy core corn cost crew crop dark data date dawn "
    "days dead deal dear debt deep deer desk dial diet dirt dish dive does done door "
    "dose down draw drew drop drum dual duck dust duty each earn ease east easy edge "
    "fail fair fall farm fast fate fear feed feel feet fell felt file fill film find "
    "fine fire firm fish five flat flag flow folk food foot ford form fort four free "
    "frog fuel full fund gain game gate gave gear gene gift girl give glad goal goat "
    "gold golf gone good gray grew grid grow gulf hair half hall hand hang hard harm "
    "lake lamp land lane last late lawn lead leaf lean leap left lend lens less life "
    "lift like line link lion list live load loan lock loft long look loop lord lose "
    "moon moss most move much mule muse must nail name navy near neat neck need nest "
    "rain rank rare rate read real reap rely rest rice rich ride ring rise risk road "
    "rock role roll roof room root rope rose ruby rule rush safe sail salt same sand "
    "wave ways weak wear week well went were west what when whom wide wife wild will "
    "wind wine wing wire wise wish wolf wood wool word wore work yard yarn year zero"
).split()

_WORDLIST_CACHE = None


def _wordlist():
    global _WORDLIST_CACHE
    if _WORDLIST_CACHE is not None:
        return _WORDLIST_CACHE
    words = []
    for path in ("/usr/share/dict/words", "/usr/share/dict/american-english"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip().lower() for w in f if 4 <= len(w.strip()) <= 8 and w.strip().isalpha()]
            if len(words) > 500:
                break
        except OSError:
            continue
    _WORDLIST_CACHE = sorted(set(words)) if len(words) > 500 else list(_FALLBACK_WORDS)
    return _WORDLIST_CACHE


def generate_passphrase(words=5, sep="-", capitalize=True, add_number=True):
    words = max(3, min(int(words), 12))
    pool = _wordlist()
    chosen = [secrets.choice(pool) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = sep.join(chosen)
    if add_number:
        phrase += sep + str(secrets.randbelow(90) + 10)
    return phrase


def parse_totp_secret(value):
    if not value:
        return ""
    v = value.strip()
    if v.lower().startswith("otpauth://"):
        query = urlsplit(v).query
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        return params.get("secret", "").strip()
    return v


def totp_now(secret_b32, digits=6, period=30, algo="SHA1"):
    s = secret_b32.strip().replace(" ", "").upper()
    pad = (-len(s)) % 8
    try:
        key = base64.b32decode(s + "=" * pad)
    except Exception:
        raise VaultError("invalid TOTP secret")
    digestmod = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}.get(
        algo.upper(), hashlib.sha1
    )
    counter = int(time.time() // period)
    mac = hmac.new(key, struct.pack(">Q", counter), digestmod).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    code %= 10 ** digits
    remaining = period - int(time.time()) % period
    return str(code).zfill(digits), remaining


@dataclass
class Entry:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    totp: str = ""
    tags: list = field(default_factory=list)
    password_history: list = field(default_factory=list)
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)

    def public(self):
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "url": self.url,
            "tags": list(self.tags),
            "has_totp": bool(self.totp),
            "updated_at": self.updated_at,
        }


def _atomic_write(path, data):
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".vault-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Vault:
    def __init__(self, path):
        self.path = path
        self._key = None
        self._salt = None
        self._kdf = dict(ARGON_DEFAULTS)
        self.entries = {}
        self.meta = {}

    @property
    def unlocked(self):
        return self._key is not None

    def exists(self):
        return os.path.exists(self.path)

    def _require(self):
        if not self.unlocked:
            raise Locked("vault is locked")

    def create(self, password):
        if self.exists():
            raise VaultError("vault already exists")
        if not password:
            raise VaultError("empty master password")
        self._salt = secrets.token_bytes(SALT_BYTES)
        self._kdf = dict(ARGON_DEFAULTS)
        if self._key:
            self._key.wipe()
        self._key = derive_key(password, self._salt, self._kdf)
        self.entries = {}
        self.meta = {"created_at": _now()}
        self._save()

    def unlock(self, password):
        if self.unlocked:
            return
        if not self.exists():
            raise VaultError("no vault to unlock")
        with open(self.path, "rb") as f:
            doc = json.loads(f.read().decode("utf-8"))
        if doc.get("magic") != MAGIC or int(doc.get("version", 0)) != VERSION:
            raise VaultError("unrecognised vault format")
        kdf = doc["kdf"]
        salt = _b64d(kdf["salt"])
        params = {
            "alg": kdf.get("alg", "argon2id"),
            "time_cost": int(kdf["time_cost"]),
            "memory_cost": int(kdf["memory_cost"]),
            "parallelism": int(kdf["parallelism"]),
        }
        nonce = _b64d(doc["aead"]["nonce"])
        ciphertext = _b64d(doc["ciphertext"])
        header = {k: doc[k] for k in ("magic", "version", "kdf", "aead")}
        aad = _canonical(header)
        key = derive_key(password, salt, params)
        try:
            plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext, aad, nonce, key.bytes
            )
        except CryptoError:
            key.wipe()
            raise BadPassword("incorrect master password or corrupt vault")
        data = json.loads(plaintext.decode("utf-8"))
        self._salt = salt
        self._kdf = params
        self._key = key
        self.entries = {e["id"]: Entry(**e) for e in data.get("entries", [])}
        self.meta = data.get("meta", {})

    def lock(self):
        if self._key:
            self._key.wipe()
        self._key = None
        self.entries = {}
        self.meta = {}

    def _rotate_backup(self, keep=5):
        if not os.path.exists(self.path):
            return
        backup_dir = os.path.join(os.path.dirname(self.path) or ".", "backups")
        try:
            os.makedirs(backup_dir, mode=0o700, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
            dest = os.path.join(backup_dir, "vault-%s.mlkv" % stamp)
            shutil.copy2(self.path, dest)
            os.chmod(dest, 0o600)
            for old in sorted(glob.glob(os.path.join(backup_dir, "vault-*.mlkv")))[:-keep]:
                os.unlink(old)
        except OSError:
            pass

    def _save(self):
        self._require()
        self._rotate_backup()
        payload = {
            "entries": [asdict(e) for e in self.entries.values()],
            "meta": {**self.meta, "updated_at": _now()},
        }
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(NONCE_BYTES)
        header = {
            "magic": MAGIC,
            "version": VERSION,
            "kdf": {
                "alg": self._kdf["alg"],
                "salt": _b64e(self._salt),
                "time_cost": self._kdf["time_cost"],
                "memory_cost": self._kdf["memory_cost"],
                "parallelism": self._kdf["parallelism"],
            },
            "aead": {"alg": "xchacha20poly1305-ietf", "nonce": _b64e(nonce)},
        }
        aad = _canonical(header)
        ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, self._key.bytes
        )
        doc = dict(header)
        doc["ciphertext"] = _b64e(ciphertext)
        _atomic_write(self.path, json.dumps(doc, separators=(",", ":")).encode("utf-8"))

    def list(self):
        self._require()
        return sorted(
            (e.public() for e in self.entries.values()),
            key=lambda x: (x["title"].lower(), x["username"].lower()),
        )

    def get(self, entry_id):
        self._require()
        e = self.entries.get(entry_id)
        if not e:
            raise VaultError("no such entry")
        return asdict(e)

    def add(self, fields):
        self._require()
        e = Entry(**self._clean(fields))
        e.created_at = _now()
        e.updated_at = e.created_at
        self.entries[e.id] = e
        self._save()
        return e.id

    def update(self, entry_id, fields):
        self._require()
        e = self.entries.get(entry_id)
        if not e:
            raise VaultError("no such entry")
        clean = self._clean(fields)
        if "password" in clean and clean["password"] != e.password and e.password:
            e.password_history = ([{"password": e.password, "changed_at": e.updated_at}] + list(e.password_history))[:10]
        for k in ("title", "username", "password", "url", "notes", "totp", "tags"):
            if k in clean:
                setattr(e, k, clean[k])
        e.updated_at = _now()
        self._save()
        return e.id

    def delete(self, entry_id):
        self._require()
        if entry_id not in self.entries:
            raise VaultError("no such entry")
        del self.entries[entry_id]
        self._save()

    def match(self, url):
        self._require()
        return sorted(
            (e.public() for e in self.entries.values() if domain_matches(e.url, url)),
            key=lambda x: x["title"].lower(),
        )

    def fill(self, entry_id, url):
        self._require()
        e = self.entries.get(entry_id)
        if not e:
            raise VaultError("no such entry")
        if not domain_matches(e.url, url):
            raise VaultError("origin does not match stored entry")
        out = {"id": e.id, "username": e.username, "password": e.password}
        if e.totp:
            try:
                code, remaining = totp_now(e.totp)
                out["totp"] = code
                out["totp_remaining"] = remaining
            except VaultError:
                pass
        return out

    def capture(self, url, username, password):
        self._require()
        for e in self.entries.values():
            if domain_matches(e.url, url) and e.username == username:
                if e.password == password:
                    return {"status": "unchanged", "id": e.id}
                if e.password:
                    e.password_history = ([{"password": e.password, "changed_at": e.updated_at}] + list(e.password_history))[:10]
                e.password = password
                e.updated_at = _now()
                self._save()
                return {"status": "updated", "id": e.id}
        title = host_of(url) or url or "Saved login"
        e = Entry(title=title, username=username, password=password, url=url)
        self.entries[e.id] = e
        self._save()
        return {"status": "created", "id": e.id}

    def totp(self, entry_id):
        self._require()
        e = self.entries.get(entry_id)
        if not e or not e.totp:
            raise VaultError("no TOTP for entry")
        code, remaining = totp_now(e.totp)
        return {"code": code, "remaining": remaining}

    def change_password(self, old_password, new_password):
        self._require()
        if not new_password:
            raise VaultError("empty new password")
        check = derive_key(old_password, self._salt, self._kdf)
        try:
            if not hmac.compare_digest(check.bytes, self._key.bytes):
                raise BadPassword("current master password is incorrect")
        finally:
            check.wipe()
        self._salt = secrets.token_bytes(SALT_BYTES)
        self._kdf = dict(ARGON_DEFAULTS)
        new_key = derive_key(new_password, self._salt, self._kdf)
        self._key.wipe()
        self._key = new_key
        self._save()

    def export(self):
        self._require()
        return {"entries": [asdict(e) for e in self.entries.values()], "meta": dict(self.meta)}

    def import_entries(self, entries, replace=False):
        self._require()
        if replace:
            self.entries = {}
        count = 0
        for raw in entries:
            e = Entry(**self._clean(raw, keep_id=True))
            self.entries[e.id] = e
            count += 1
        self._save()
        return count

    @staticmethod
    def _clean(fields, keep_id=False):
        allowed = {"title", "username", "password", "url", "notes", "totp", "tags"}
        if keep_id:
            allowed = allowed | {"id", "created_at", "updated_at", "password_history"}
        out = {}
        for k, v in (fields or {}).items():
            if k not in allowed:
                continue
            if k == "tags":
                out[k] = [str(t) for t in (v or [])]
            elif k == "password_history":
                out[k] = list(v or [])
            elif k == "totp":
                out[k] = parse_totp_secret("" if v is None else str(v))
            elif k in ("created_at", "updated_at"):
                out[k] = float(v)
            else:
                out[k] = "" if v is None else str(v)
        return out
