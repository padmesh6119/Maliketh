#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv --system-site-packages .venv
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -r requirements.txt
echo
echo "Setup complete."
echo "  1. Load extension/ at chrome://extensions (Developer mode > Load unpacked), copy the ID"
echo "  2. .venv/bin/python install.py --extension-id <ID>"
echo "  3. .venv/bin/python ui/app.py"
