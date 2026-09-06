# Contributing to CryptoRadar

Thanks for taking a look. This started as a focused tool for one problem
(crypto-agility assessment on mixed legacy-core + API fintech stacks), and
it stays useful by staying focused — please keep PRs scoped.

## Setup

```bash
git clone https://github.com/bennybriel/cryptoradar.git
cd cryptoradar
pip install -e .
pip install pytest
python -m pytest tests/ -v
```

## Adding a detection signature

Signatures live in `cryptoradar/detectors.py` as `Signature` objects. Each
needs: the regex pattern, a `Category`, a severity (1–5), whether it's
quantum-relevant, a plain-language `note` on why it matters, and a
`migration_hint`. Add a corresponding case to `demo_repo/` and a test in
`tests/test_basic.py` asserting the signature fires (and, ideally, that it
doesn't false-positive on an adjacent safe pattern).

## Reporting a false positive / false negative

Open an issue with a minimal code snippet that reproduces it. Regex-based
detection will always have edge cases — the goal is "good enough for a
first-pass inventory," not zero false positives, but repeated false
positives on common patterns are worth fixing.

## What's out of scope for the core (for now)

Full AST-based parsing per language, a hosted dashboard, and PDF export are
on the roadmap in `README.md` but are bigger efforts — open an issue to
discuss approach before sending a large PR for any of these so it doesn't
go to waste.

## Code of conduct

Be respectful, assume good faith, keep discussion technical.
