# Contributing

Thanks for helping make smart contracts safer!

## Setup

```bash
git clone https://github.com/yassinEe123/chainmail
cd chainmail
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check src tests        # lint
ruff format src tests       # format
mypy src                    # types
pytest --cov=chainmail      # tests (coverage must stay ≥ 85 %)
python scripts/benchmark.py # optional: false-positive check on real code (needs npm)
```

## Guidelines

* Every detector needs at least one **positive** and one **negative** test.
* Prefer precision over recall: a noisy detector gets disabled by users. If a
  heuristic is uncertain, lower the finding's confidence instead of dropping it.
* Messages should name the function, the variable and the exact expression so the
  reader can act without opening the file.
* Keep the core dependency-free beyond `click`, `jinja2` and `pyyaml`.

See [docs/writing-detectors.md](docs/writing-detectors.md) for the detector API.
