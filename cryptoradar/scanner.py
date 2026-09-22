"""
scanner.py — Walks a repository, applies detector signatures, and produces
a Crypto Bill of Materials (CBOM): a structured inventory of every
cryptographic primitive reference found, with file/line provenance.
"""

from __future__ import annotations
import os
import bisect
from datetime import datetime, timezone

from .detectors import SIGNATURES, Category
from .risk import score_finding
from .redact import redact_finding
from .comments import mask_comments

# Extensions worth scanning across a typical mixed African fintech stack:
# Java/Kotlin (core + middleware), COBOL (mainframe cores), JS/TS (API/mobile),
# Python (data/ML/API), PHP (legacy web portals), Go, C#, config/YAML/props,
# and SQL (stored-proc based crypto is common in older cores).
DEFAULT_EXTENSIONS = {
    ".java", ".kt", ".cbl", ".cob", ".cpy",
    ".js", ".ts", ".jsx", ".tsx",
    ".py", ".php", ".go", ".cs",
    ".yml", ".yaml", ".properties", ".conf", ".ini", ".env",
    ".sql", ".xml", ".json",
}

DEFAULT_IGNORE_DIRS = {
    ".git", "node_modules", "target", "build", "dist", "venv", ".venv",
    "__pycache__", ".idea", ".vscode", "vendor", "coverage",
}


def _iter_files(root: str, extensions: set[str], ignore_dirs: set[str]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs and not d.startswith(".")]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in extensions:
                yield os.path.join(dirpath, fn)


def _line_starts(text: str) -> list[int]:
    """Offset (into `text`) where each line begins, 0-indexed, plus a
    trailing sentinel equal to len(text). Built with a single pass over
    newline positions rather than reconstructing the file from readlines()."""
    starts = [0]
    idx = text.find("\n")
    while idx != -1:
        starts.append(idx + 1)
        idx = text.find("\n", idx + 1)
    return starts


def _line_number(line_starts: list[int], offset: int) -> int:
    """O(log n) lookup via bisect instead of the previous O(n) linear scan
    per match — matters once a file has many lines and many findings,
    since this was previously O(matches x lines) for a single file."""
    return bisect.bisect_right(line_starts, offset)


def scan_file(path: str, rel_path: str) -> list[dict]:
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return findings

    ext = os.path.splitext(path)[1]
    scan_text = mask_comments(text, ext)
    line_starts = _line_starts(text)
    raw_lines = None  # populated lazily only if a match is actually found

    for sig in SIGNATURES:
        for m in sig.finditer(scan_text):
            offset = m.start()
            line_no = _line_number(line_starts, offset)
            if raw_lines is None:
                raw_lines = text.splitlines()
            snippet = raw_lines[line_no - 1].strip() if 0 < line_no <= len(raw_lines) else m.group(0)
            finding = {
                "signature_id": sig.id,
                "file": rel_path,
                "line": line_no,
                "snippet": snippet[:160],
                "category": sig.category.value,
                "primitive": sig.primitive,
                "severity": sig.severity,
                "quantum_relevant": sig.quantum_relevant,
                "note": sig.note,
                "migration_hint": sig.migration_hint,
                "weighted_score": score_finding(sig.severity, sig.category),
            }
            findings.append(redact_finding(finding))
    return findings


def scan_repo(root: str, extensions: set[str] | None = None,
               ignore_dirs: set[str] | None = None,
               component_name: str | None = None) -> dict:
    extensions = extensions or DEFAULT_EXTENSIONS
    ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS

    findings = []
    files_scanned = 0
    for path in _iter_files(root, extensions, ignore_dirs):
        rel = os.path.relpath(path, root)
        files_scanned += 1
        findings.extend(scan_file(path, rel))

    return {
        "component": component_name or os.path.basename(os.path.abspath(root)),
        "scanned_path": os.path.abspath(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files_scanned": files_scanned,
        "findings": findings,
    }


def scan_multi(components: list[tuple[str, str]]) -> dict:
    """components: list of (component_name, path) — e.g. multiple services
    in a mixed legacy-core + API-layer estate, scanned together into one CBOM."""
    results = [scan_repo(path, component_name=name) for name, path in components]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "components": results,
    }
