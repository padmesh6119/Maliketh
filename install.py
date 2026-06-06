#!/usr/bin/env python3
# register the native messaging host for installed chromium-family browsers
import argparse
import json
import os
import stat
import sys

HOST_NAME = "com.maliketh.host"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
MALIKETH_HOME = os.environ.get("MALIKETH_HOME") or os.path.join(HOME, ".local", "share", "maliketh")
LAUNCHER = os.path.join(MALIKETH_HOME, "maliketh-host")

CHROMIUM_DIRS = {
    "google-chrome": "~/.config/google-chrome/NativeMessagingHosts",
    "chromium": "~/.config/chromium/NativeMessagingHosts",
    "brave": "~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
    "edge": "~/.config/microsoft-edge/NativeMessagingHosts",
    "vivaldi": "~/.config/vivaldi/NativeMessagingHosts",
}
FIREFOX_DIR = "~/.mozilla/native-messaging-hosts"


def write_launcher():
    os.makedirs(MALIKETH_HOME, mode=0o700, exist_ok=True)
    script = "#!/usr/bin/env bash\ncd %s\nexec %s -m core.native_host\n" % (
        json.dumps(PROJECT_ROOT),
        json.dumps(sys.executable),
    )
    with open(LAUNCHER, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(LAUNCHER, 0o755)
    return LAUNCHER


def chromium_manifest(extension_id):
    return {
        "name": HOST_NAME,
        "description": "Maliketh native vault bridge",
        "path": LAUNCHER,
        "type": "stdio",
        "allowed_origins": ["chrome-extension://%s/" % extension_id],
    }


def firefox_manifest(extension_id):
    return {
        "name": HOST_NAME,
        "description": "Maliketh native vault bridge",
        "path": LAUNCHER,
        "type": "stdio",
        "allowed_extensions": [extension_id],
    }


def install_chromium(extension_id, only=None):
    written = []
    for name, raw in CHROMIUM_DIRS.items():
        if only and name not in only:
            continue
        parent = os.path.expanduser(os.path.dirname(raw))
        if not os.path.isdir(parent):
            continue
        target_dir = os.path.expanduser(raw)
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, HOST_NAME + ".json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(chromium_manifest(extension_id), f, indent=2)
        written.append(path)
    return written


def install_firefox(extension_id):
    parent = os.path.expanduser(os.path.dirname(FIREFOX_DIR))
    if not os.path.isdir(parent):
        return []
    target_dir = os.path.expanduser(FIREFOX_DIR)
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, HOST_NAME + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(firefox_manifest(extension_id), f, indent=2)
    return [path]


def update_repo_template(extension_id):
    path = os.path.join(PROJECT_ROOT, "maliketh_host.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(chromium_manifest(extension_id), f, indent=2)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser(description="Register the Maliketh native messaging host.")
    ap.add_argument("--extension-id", required=True, help="chrome-extension ID (chrome://extensions)")
    ap.add_argument("--firefox-id", help="Firefox add-on ID, e.g. maliketh@example.com")
    ap.add_argument("--only", nargs="*", help="limit to specific chromium browsers", choices=list(CHROMIUM_DIRS))
    args = ap.parse_args()

    launcher = write_launcher()
    written = install_chromium(args.extension_id, args.only)
    if args.firefox_id:
        written += install_firefox(args.firefox_id)
    update_repo_template(args.extension_id)

    print("launcher: %s" % launcher)
    if written:
        print("registered host manifest at:")
        for p in written:
            print("  " + p)
    else:
        print("no supported browsers detected under ~/.config — manifest not installed.")
    print("\nNext: reload the extension, then unlock the vault from the desktop app (python ui/app.py).")


if __name__ == "__main__":
    main()
