# skillvet developer tasks. No dependencies required beyond Python 3.8+.
PY ?= python3

.PHONY: help test check scan lint docs clean all

help:
	@echo "make test    run the test suite"
	@echo "make check   scan this repository's own skills with itself"
	@echo "make lint    byte-compile every module and check formatting basics"
	@echo "make docs    regenerate docs/rules.md from the rule registry"
	@echo "make all     test + lint + check"

all: lint test check

test:
	$(PY) -m pytest tests/ -q

check:
	@echo "--- skills/ must be clean ---"
	$(PY) -m skillvet scan skills/ --fail-on high --min-score 90
	@echo "--- the good example must pass ---"
	$(PY) -m skillvet scan examples/pdf-invoice-extractor --fail-on medium
	@echo "--- the hostile fixture must still be blocked ---"
	@$(PY) -m skillvet scan examples/risky-web-scraper --quiet >/dev/null 2>&1; \
	  code=$$?; \
	  if [ $$code -eq 1 ]; then echo "blocked as expected"; else echo "REGRESSION: fixture no longer blocks"; exit 1; fi

scan:
	$(PY) -m skillvet scan . --no-capabilities

lint:
	$(PY) -m compileall -q skillvet tests
	$(PY) -m skillvet rules --json > /dev/null
	@echo "compile + catalogue ok"

docs:
	$(PY) scripts/gen_rule_docs.py > docs/rules.md
	@echo "docs/rules.md regenerated"

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache *.egg-info
