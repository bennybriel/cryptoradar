"""
redact.py — Masks sensitive matched values (secrets, keys, IVs) before they
are ever written into a CBOM, an HTML report, or a client-facing document.

The scanner's job is to prove *that* a secret is hardcoded and *where* —
not to hand a fresh copy of that secret to everyone who reads the report.
A report is a sensitive artifact in its own right and should be safe to
put in front of a client's security team without also being a leak vector.
"""

from __future__ import annotations
import re

# Matches the quoted literal value inside an assignment-style match, e.g.
#   private String secret = "E_yJCBAM5VPuq..."
#   SECRET: "sk_live_...."
_VALUE_PATTERN = re.compile(r'''(["'])((?:(?!\1).){6,})\1''')


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"


def redact_snippet(snippet: str) -> str:
    """Replace quoted literal values in a matched code line with a masked
    version, preserving enough context (length, first/last chars) to be
    useful for verification without reproducing the secret itself."""
    def _replace(m: re.Match) -> str:
        quote, value = m.group(1), m.group(2)
        return f"{quote}{_mask(value)}{quote}"
    return _VALUE_PATTERN.sub(_replace, snippet)


# Categories whose snippets should always be redacted before leaving the
# scanner, regardless of downstream consumer (JSON CBOM, HTML, docx).
REDACT_SIGNATURE_IDS = {"HARDCODED-KEY", "STATIC-IV"}


def redact_finding(finding: dict) -> dict:
    if finding.get("signature_id") in REDACT_SIGNATURE_IDS:
        finding = dict(finding)
        finding["snippet"] = redact_snippet(finding["snippet"])
        finding["redacted"] = True
    return finding
