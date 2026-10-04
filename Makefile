.PHONY: install install-dev install-production test demo sandbox-selftest lint clean

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

install-production:
	pip install -e ".[production]"

test:
	python -m unittest discover -s tests -v

demo:
	python examples/run_demo.py

sandbox-selftest:
	python shadow_strike/execution/sandbox.py

lint:
	ruff check shadow_strike/ --line-length 110

clean:
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -f shadow_strike_knowledge.sqlite3
	rm -rf contracts/test/generated
	rm -rf *.egg-info build dist
