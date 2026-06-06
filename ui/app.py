# Qt (PySide6) desktop interface
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import audit as audit_mod
from core.client import AgentClient
from core.importers import csv_to_entries

STYLE = """
QWidget { background:#15131c; color:#e9e6f0; font-size:13px; }
QLineEdit, QPlainTextEdit, QSpinBox { background:#0f0d15; border:1px solid #2a2735; border-radius:6px; padding:6px; }
QLineEdit:focus, QPlainTextEdit:focus { border:1px solid #b5179e; }
QListWidget { background:#0f0d15; border:1px solid #2a2735; border-radius:8px; }
QListWidget::item { padding:9px 10px; border-bottom:1px solid #1d1a26; }
QListWidget::item:selected { background:#2a1f33; color:#fff; }
QPushButton { background:#b5179e; border:none; border-radius:7px; padding:7px 12px; color:#fff; }
QPushButton:hover { background:#c81fae; }
QPushButton[flat="true"], QPushButton.ghost { background:#241f30; color:#cfc8dc; }
QLabel#title { color:#b5179e; font-size:18px; font-weight:700; }
QLabel.h { color:#9a93a8; }
"""


class PasswordPrompt(QDialog):
    def __init__(self, title, confirm=False, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(340)
        form = QFormLayout(self)
        self.pw = QLineEdit(echoMode=QLineEdit.Password)
        form.addRow("Master password", self.pw)
        self.confirm = None
        if confirm:
            self.confirm = QLineEdit(echoMode=QLineEdit.Password)
            form.addRow("Confirm", self.confirm)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)
        self.pw.setFocus()

    def _accept(self):
        if not self.pw.text():
            QMessageBox.warning(self, "Maliketh", "Password cannot be empty.")
            return
        if self.confirm is not None and self.pw.text() != self.confirm.text():
            QMessageBox.warning(self, "Maliketh", "Passwords do not match.")
            return
        self.accept()

    def value(self):
        return self.pw.text()


class GeneratorDialog(QDialog):
    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self.setWindowTitle("Password generator")
        self.setMinimumWidth(380)
        v = QVBoxLayout(self)
        self.out = QLineEdit(readOnly=True)
        v.addWidget(self.out)
        self.length = QSpinBox()
        self.length.setRange(4, 128)
        self.length.setValue(20)
        row = QHBoxLayout()
        row.addWidget(QLabel("Length"))
        row.addWidget(self.length)
        v.addLayout(row)
        self.passphrase = QCheckBox("passphrase (dictionary words; length = word count)")
        v.addWidget(self.passphrase)
        self.boxes = {}
        for key, label in [("lower", "a-z"), ("upper", "A-Z"), ("digits", "0-9"), ("symbols", "!@#"), ("avoid_ambiguous", "avoid ambiguous")]:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self.boxes[key] = cb
            v.addWidget(cb)
        btns = QHBoxLayout()
        regen = QPushButton("Regenerate")
        copy = QPushButton("Copy")
        regen.clicked.connect(self.generate)
        copy.clicked.connect(lambda: parent.copy_secret(self.out.text(), "Password"))
        btns.addWidget(regen)
        btns.addWidget(copy)
        v.addLayout(btns)
        for w in [self.length] + list(self.boxes.values()):
            sig = w.valueChanged if isinstance(w, QSpinBox) else w.toggled
            sig.connect(self.generate)
        self.passphrase.toggled.connect(self.generate)
        self.generate()

    def generate(self):
        if self.passphrase.isChecked():
            resp = self.client.generate(self.length.value(), mode="passphrase")
        else:
            opts = {k: b.isChecked() for k, b in self.boxes.items()}
            resp = self.client.generate(self.length.value(), **opts)
        if resp.get("ok"):
            self.out.setText(resp["password"])


class EntryDialog(QDialog):
    def __init__(self, client, entry=None, parent=None):
        super().__init__(parent)
        self.client = client
        self.setWindowTitle("Edit entry" if entry else "New entry")
        self.setMinimumWidth(420)
        entry = entry or {}
        form = QFormLayout(self)
        self.title = QLineEdit(entry.get("title", ""))
        self.username = QLineEdit(entry.get("username", ""))
        self.password = QLineEdit(entry.get("password", ""))
        self.password.setEchoMode(QLineEdit.Password)
        self.url = QLineEdit(entry.get("url", ""))
        self.totp = QLineEdit(entry.get("totp", ""))
        self.tags = QLineEdit(", ".join(entry.get("tags", [])))
        self.notes = QPlainTextEdit(entry.get("notes", ""))
        self.notes.setFixedHeight(80)
        pwrow = QWidget()
        h = QHBoxLayout(pwrow)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(self.password)
        show = QPushButton("👁")
        show.setCheckable(True)
        show.setFixedWidth(40)
        show.toggled.connect(lambda c: self.password.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password))
        gen = QPushButton("⚙")
        gen.setFixedWidth(40)
        gen.clicked.connect(self._gen)
        h.addWidget(show)
        h.addWidget(gen)
        form.addRow("Title", self.title)
        form.addRow("Username", self.username)
        form.addRow("Password", pwrow)
        form.addRow("URL", self.url)
        form.addRow("TOTP secret", self.totp)
        form.addRow("Tags", self.tags)
        form.addRow("Notes", self.notes)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def _gen(self):
        resp = self.client.generate(20)
        if resp.get("ok"):
            self.password.setText(resp["password"])

    def value(self):
        return {
            "title": self.title.text().strip(),
            "username": self.username.text().strip(),
            "password": self.password.text(),
            "url": self.url.text().strip(),
            "totp": self.totp.text().strip(),
            "tags": [t.strip() for t in self.tags.text().split(",") if t.strip()],
            "notes": self.notes.toPlainText(),
        }


class Maliketh(QMainWindow):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.current = None
        self.setWindowTitle("Maliketh")
        self.resize(820, 560)
        self._build()
        self.refresh()
        self._totp_timer = QTimer(self)
        self._totp_timer.timeout.connect(self._tick_totp)
        self._totp_timer.start(1000)

    def _build(self):
        tb = self.addToolBar("main")
        tb.setMovable(False)
        for text, slot in [("Add", self.add_entry), ("Generate", self.open_generator), ("Audit", self.open_audit), ("Settings", self.open_settings), ("Lock", self.lock)]:
            act = QAction(text, self)
            act.triggered.connect(slot)
            tb.addAction(act)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        self.search = QLineEdit(placeholderText="Search…")
        self.search.textChanged.connect(self._filter)
        root.addWidget(self.search)

        split = QSplitter()
        self.list = QListWidget()
        self.list.currentItemChanged.connect(self._select)
        split.addWidget(self.list)

        self.detail = QWidget()
        d = QFormLayout(self.detail)
        self.d_title = QLabel("")
        self.d_title.setObjectName("title")
        self.d_user = QLineEdit(readOnly=True)
        self.d_pass = QLineEdit(readOnly=True, echoMode=QLineEdit.Password)
        self.d_url = QLabel("")
        self.d_url.setOpenExternalLinks(True)
        self.d_totp = QLabel("")
        self.d_notes = QPlainTextEdit(readOnly=True)
        self.d_notes.setFixedHeight(90)

        d.addRow(self.d_title)
        d.addRow("User", self._with_copy(self.d_user, lambda: self.copy_secret(self.d_user.text(), "Username")))
        d.addRow("Pass", self._with_pass_controls())
        d.addRow("URL", self.d_url)
        d.addRow("TOTP", self.d_totp)
        d.addRow("Notes", self.d_notes)
        edit = QPushButton("Edit")
        delete = QPushButton("Delete")
        history = QPushButton("History")
        delete.setObjectName("ghost")
        history.setObjectName("ghost")
        edit.clicked.connect(self.edit_entry)
        delete.clicked.connect(self.delete_entry)
        history.clicked.connect(self.show_history)
        actions = QHBoxLayout()
        actions.addWidget(edit)
        actions.addWidget(history)
        actions.addWidget(delete)
        d.addRow(actions)
        split.addWidget(self.detail)
        split.setSizes([300, 520])
        root.addWidget(split)
        self.detail.setEnabled(False)

    def _with_copy(self, widget, slot):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(widget)
        b = QPushButton("Copy")
        b.setFixedWidth(60)
        b.clicked.connect(slot)
        h.addWidget(b)
        return w

    def _with_pass_controls(self):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(self.d_pass)
        show = QPushButton("👁")
        show.setCheckable(True)
        show.setFixedWidth(40)
        show.toggled.connect(lambda c: self.d_pass.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password))
        copy = QPushButton("Copy")
        copy.setFixedWidth(60)
        copy.clicked.connect(lambda: self.copy_secret(self.d_pass.text(), "Password"))
        h.addWidget(show)
        h.addWidget(copy)
        return w

    def api(self, method, *args, **kwargs):
        resp = getattr(self.client, method)(*args, **kwargs)
        if isinstance(resp, dict) and resp.get("locked"):
            self.lock(prompt=True)
        return resp

    def refresh(self, select_id=None):
        resp = self.api("list")
        self.list.clear()
        if not resp.get("ok"):
            return
        for e in resp.get("entries", []):
            item = QListWidgetItem(self._label(e))
            item.setData(Qt.UserRole, e["id"])
            self.list.addItem(item)
            if e["id"] == select_id:
                self.list.setCurrentItem(item)
        self._filter(self.search.text())

    def _label(self, e):
        base = e.get("title") or e.get("username") or "(entry)"
        return base + (("  ·  " + e["username"]) if e.get("username") and e.get("title") else "")

    def _filter(self, text):
        text = (text or "").lower()
        for i in range(self.list.count()):
            item = self.list.item(i)
            item.setHidden(text not in item.text().lower())

    def _select(self, item):
        if not item:
            self.current = None
            self.detail.setEnabled(False)
            return
        entry_id = item.data(Qt.UserRole)
        resp = self.api("get", entry_id)
        if not resp.get("ok"):
            return
        e = resp["entry"]
        self.current = e
        self.detail.setEnabled(True)
        self.d_title.setText(e.get("title") or "(entry)")
        self.d_user.setText(e.get("username", ""))
        self.d_pass.setText(e.get("password", ""))
        self.d_pass.setEchoMode(QLineEdit.Password)
        url = e.get("url", "")
        self.d_url.setText('<a href="%s" style="color:#b5179e">%s</a>' % (url, url) if url else "")
        self.d_notes.setPlainText(e.get("notes", ""))
        self._tick_totp()

    def _tick_totp(self):
        if not self.current or not self.current.get("totp"):
            self.d_totp.setText("—")
            return
        resp = self.client.totp(self.current["id"])
        if resp.get("ok"):
            self.d_totp.setText("%s   (%ss)" % (resp["code"], resp["remaining"]))
        else:
            self.d_totp.setText("—")

    def add_entry(self):
        dlg = EntryDialog(self.client, parent=self)
        if dlg.exec() == QDialog.Accepted:
            resp = self.api("add", dlg.value())
            if resp.get("ok"):
                self.refresh(resp["id"])
            else:
                QMessageBox.warning(self, "Maliketh", resp.get("error", "failed"))

    def edit_entry(self):
        if not self.current:
            return
        dlg = EntryDialog(self.client, self.current, parent=self)
        if dlg.exec() == QDialog.Accepted:
            resp = self.api("update", self.current["id"], dlg.value())
            if resp.get("ok"):
                self.refresh(self.current["id"])

    def delete_entry(self):
        if not self.current:
            return
        if QMessageBox.question(self, "Maliketh", "Delete '%s'?" % (self.current.get("title") or "entry")) != QMessageBox.Yes:
            return
        resp = self.api("delete", self.current["id"])
        if resp.get("ok"):
            self.current = None
            self.refresh()

    def open_generator(self):
        GeneratorDialog(self.client, self).exec()

    def open_audit(self):
        AuditDialog(self.client, self).exec()

    def open_settings(self):
        SettingsDialog(self.client, self).exec()

    def show_history(self):
        if not self.current:
            return
        hist = self.current.get("password_history", [])
        if not hist:
            QMessageBox.information(self, "Maliketh", "No previous passwords recorded.")
            return
        import time as _t

        lines = []
        for h in hist:
            ts = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(h.get("changed_at", 0)))
            lines.append("%s    %s" % (ts, h.get("password", "")))
        dlg = QDialog(self)
        dlg.setWindowTitle("Password history")
        lay = QVBoxLayout(dlg)
        box = QPlainTextEdit("\n".join(lines))
        box.setReadOnly(True)
        lay.addWidget(box)
        dlg.resize(440, 240)
        dlg.exec()

    def copy_secret(self, text, label="Value"):
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage("%s copied — clipboard clears in 20s" % label, 5000)
        QTimer.singleShot(20000, lambda: self._clear_clip(text))

    def _clear_clip(self, text):
        cb = QGuiApplication.clipboard()
        if cb.text() == text:
            cb.clear()

    def lock(self, prompt=True):
        self.client.lock()
        self.current = None
        self.list.clear()
        self.detail.setEnabled(False)
        if prompt:
            if not unlock_flow(self.client, self):
                self.close()
                return
            self.refresh()


class SettingsDialog(QDialog):
    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self.parent_window = parent
        self.setWindowTitle("Settings")
        self.setMinimumWidth(360)
        v = QVBoxLayout(self)
        st = client.status()
        v.addWidget(QLabel("Auto-lock after idle (minutes, 0 = never)"))
        self.timeout = QSpinBox()
        self.timeout.setRange(0, 1440)
        self.timeout.setValue(int(st.get("timeout", 600)) // 60)
        v.addWidget(self.timeout)
        save_to = QPushButton("Apply auto-lock")
        save_to.clicked.connect(self._save_timeout)
        v.addWidget(save_to)
        self.browser_unlock = QCheckBox("Allow unlocking from the browser extension")
        self.browser_unlock.setChecked(bool(st.get("allow_browser_unlock")))
        self.browser_unlock.toggled.connect(self.client.set_browser_unlock)
        v.addWidget(self.browser_unlock)
        for label, slot in [("Change master password", self._change_pw), ("Export vault (plaintext)…", self._export), ("Import entries (JSON)…", self._import), ("Import CSV (Chrome/Bitwarden)…", self._import_csv)]:
            b = QPushButton(label)
            b.setObjectName("ghost")
            b.clicked.connect(slot)
            v.addWidget(b)

    def _save_timeout(self):
        self.client.set_timeout(self.timeout.value() * 60)
        QMessageBox.information(self, "Maliketh", "Auto-lock updated.")

    def _change_pw(self):
        old, ok = QInputDialog.getText(self, "Current password", "Current master password", QLineEdit.Password)
        if not ok:
            return
        dlg = PasswordPrompt("New master password", confirm=True, parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        resp = self.client.change_password(old, dlg.value())
        if resp.get("ok"):
            QMessageBox.information(self, "Maliketh", "Master password changed.")
        else:
            QMessageBox.warning(self, "Maliketh", resp.get("error", "failed"))

    def _export(self):
        if QMessageBox.warning(self, "Maliketh", "Export writes ALL secrets as plaintext JSON. Continue?", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export vault", "maliketh-export.json", "JSON (*.json)")
        if not path:
            return
        resp = self.client.export()
        if resp.get("ok"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(resp["vault"], f, indent=2)
            os.chmod(path, 0o600)
            QMessageBox.information(self, "Maliketh", "Exported.")

    def _import(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import entries", "", "JSON (*.json)")
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("entries", data if isinstance(data, list) else [])
        resp = self.client.import_entries(entries)
        if resp.get("ok"):
            QMessageBox.information(self, "Maliketh", "Imported %d entries." % resp["imported"])
            if self.parent_window:
                self.parent_window.refresh()

    def _import_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import CSV", "", "CSV (*.csv)")
        if not path:
            return
        try:
            entries = csv_to_entries(path)
        except Exception as e:
            QMessageBox.warning(self, "Maliketh", "Could not parse CSV: %s" % e)
            return
        resp = self.client.import_entries(entries)
        if resp.get("ok"):
            QMessageBox.information(self, "Maliketh", "Imported %d entries." % resp["imported"])
            if self.parent_window:
                self.parent_window.refresh()


class AuditDialog(QDialog):
    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self.setWindowTitle("Vault health")
        self.resize(580, 440)
        v = QVBoxLayout(self)
        self.summary = QLabel("…")
        v.addWidget(self.summary)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Score", "Title", "Username", "Flags"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.table)
        breach = QPushButton("Check breaches online (HIBP — sends only a hash prefix)")
        breach.setObjectName("ghost")
        breach.clicked.connect(lambda: self.run(check_breach=True))
        v.addWidget(breach)
        self.run(check_breach=False)

    def run(self, check_breach):
        resp = self.client.export()
        if not resp.get("ok"):
            self.summary.setText(resp.get("error", "failed"))
            return
        if check_breach and QMessageBox.warning(
            self,
            "Maliketh",
            "This sends the first 5 characters of each password's SHA-1 hash to "
            "api.pwnedpasswords.com (k-anonymity — the password never leaves your machine). Continue?",
            QMessageBox.Yes | QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        report = audit_mod.audit(resp["vault"]["entries"], check_breach=check_breach)
        self.summary.setText(
            "Entries: %d     Weak: %d     Reused groups: %d"
            % (report["total"], report["weak"], report["reused_groups"])
        )
        self.table.setRowCount(len(report["items"]))
        for r, it in enumerate(report["items"]):
            flags = []
            if it["weak"]:
                flags.append("WEAK")
            if it["reused"]:
                flags.append("REUSED")
            if it.get("pwned"):
                flags.append("PWNED×%s" % it["pwned"] if it["pwned"] > 0 else "PWNED?")
            cells = ["%d  %s" % (it["score"], it["label"]), it["title"], it["username"], ", ".join(flags)]
            for col, text in enumerate(cells):
                self.table.setItem(r, col, QTableWidgetItem(text))


def unlock_flow(client, parent=None):
    st = client.status()
    if not st.get("ok"):
        QMessageBox.critical(parent, "Maliketh", "Cannot reach the Maliketh agent.\n%s" % st.get("error", ""))
        return False
    if not st.get("vault_exists"):
        dlg = PasswordPrompt("Create your vault", confirm=True, parent=parent)
        if dlg.exec() != QDialog.Accepted:
            return False
        resp = client.init(dlg.value())
        if not resp.get("ok"):
            QMessageBox.warning(parent, "Maliketh", resp.get("error", "failed"))
            return False
        return True
    if st.get("locked"):
        while True:
            dlg = PasswordPrompt("Unlock Maliketh", parent=parent)
            if dlg.exec() != QDialog.Accepted:
                return False
            resp = client.unlock(dlg.value())
            if resp.get("ok"):
                return True
            QMessageBox.warning(parent, "Maliketh", resp.get("error", "incorrect password"))
    return True


ICON_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets", "icons", "icon-256.png",
)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Maliketh")
    if os.path.exists(ICON_PATH):
        app.setWindowIcon(QIcon(ICON_PATH))
    app.setStyleSheet(STYLE)
    client = AgentClient(autostart=True)
    if not unlock_flow(client):
        return 0
    win = Maliketh(client)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
