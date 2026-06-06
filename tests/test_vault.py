import json
import os
import tempfile
import unittest
from unittest import mock

from core import audit
from core.vault import (
    BadPassword,
    Vault,
    VaultError,
    domain_matches,
    generate_passphrase,
    generate_password,
    parse_totp_secret,
    totp_now,
)


class CryptoTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "v.mlkv")

    def test_roundtrip_across_instances(self):
        v = Vault(self.path)
        v.create("hunter2")
        eid = v.add({"title": "GH", "username": "neo", "password": "s3cret", "url": "https://github.com"})
        v.lock()
        w = Vault(self.path)
        w.unlock("hunter2")
        self.assertEqual(w.get(eid)["password"], "s3cret")

    def test_wrong_password(self):
        Vault(self.path).create("right")
        w = Vault(self.path)
        with self.assertRaises(BadPassword):
            w.unlock("wrong")

    def test_tamper_detection(self):
        v = Vault(self.path)
        v.create("pw")
        v.add({"title": "x", "password": "y"})
        import base64
        with open(self.path) as f:
            doc = json.loads(f.read())
        ct = bytearray(base64.b64decode(doc["ciphertext"]))
        ct[10] ^= 0x01
        doc["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        with open(self.path, "w") as f:
            f.write(json.dumps(doc))
        with self.assertRaises(BadPassword):
            Vault(self.path).unlock("pw")

    def test_password_history(self):
        v = Vault(self.path)
        v.create("pw")
        eid = v.add({"title": "x", "password": "first"})
        v.update(eid, {"password": "second"})
        v.update(eid, {"password": "third"})
        hist = [h["password"] for h in v.get(eid)["password_history"]]
        self.assertEqual(hist, ["second", "first"])

    def test_locked_requires_unlock(self):
        v = Vault(self.path)
        v.create("pw")
        v.lock()
        with self.assertRaises(VaultError):
            v.list()


class HelpersTest(unittest.TestCase):
    def test_domain_matches(self):
        self.assertTrue(domain_matches("https://github.com/login", "https://github.com"))
        self.assertTrue(domain_matches("github.com", "https://sub.github.com/x"))
        self.assertFalse(domain_matches("https://github.com", "https://evil.com"))
        self.assertFalse(domain_matches("", "https://x.com"))

    def test_generate_password(self):
        pw = generate_password(32, symbols=False)
        self.assertEqual(len(pw), 32)
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertFalse(any(c in "!@#$%" for c in pw))

    def test_generate_passphrase(self):
        ph = generate_passphrase(words=5, sep="-")
        self.assertGreaterEqual(len(ph.split("-")), 5)

    def test_parse_otpauth(self):
        uri = "otpauth://totp/GitHub:neo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        self.assertEqual(parse_totp_secret(uri), "JBSWY3DPEHPK3PXP")
        self.assertEqual(parse_totp_secret("JBSWY3DPEHPK3PXP"), "JBSWY3DPEHPK3PXP")

    def test_totp_rfc6238_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        with mock.patch("core.vault.time.time", return_value=59):
            code, _ = totp_now(secret, digits=6)
        self.assertEqual(code, "287082")


class AuditTest(unittest.TestCase):
    def test_strength(self):
        self.assertEqual(audit.strength("password")[1], "very weak")
        self.assertGreater(audit.strength("Tr0ub4dor&3xKj#9zQ")[0], 70)

    def test_reuse(self):
        entries = [
            {"id": "1", "password": "same"},
            {"id": "2", "password": "same"},
            {"id": "3", "password": "unique"},
        ]
        report = audit.audit(entries)
        self.assertEqual(report["reused_groups"], 1)
        flagged = {i["id"] for i in report["items"] if i["reused"]}
        self.assertEqual(flagged, {"1", "2"})


if __name__ == "__main__":
    unittest.main()
