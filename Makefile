PY := .venv/bin/python

.PHONY: setup run agent cli test lint clean

setup:
	./setup.sh

run:
	$(PY) ui/app.py

agent:
	$(PY) -m core.agent

cli:
	$(PY) -m core.cli $(ARGS)

test:
	$(PY) -m unittest discover -s tests -v

lint:
	$(PY) -m py_compile core/*.py ui/app.py install.py

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
