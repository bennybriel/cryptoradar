"""
comments.py — Single-pass, offset-preserving comment masking.

Why this exists: the scanner previously ran signatures directly against
raw file text, so a comment like `// RSA-1024 message signing...` fired
the exact same finding as the real `KeyPairGenerator.getInstance("RSA")`
line below it — duplicate noise at best, and in demo_repo's
pqc-pilot-service (a file with NO actual legacy crypto), a comment
mentioning the old service's RS256 JWKS produced a pure false positive
with no real code behind it at all.

Design constraints:
  - Output text must be the SAME LENGTH as the input, with newlines at
    the same offsets, so existing line/offset bookkeeping (line_starts)
    needs no changes and stays valid for the masked text.
  - String literals are NOT masked. A hardcoded secret or an algorithm
    name inside a quoted string ("RSA", "sk_live_...") is exactly what
    the scanner needs to find — only comments are noise.
  - Single pass, O(n) in file length, no backtracking regex — this is
    the efficiency half of the fix alongside scanner.py's bisect change.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class CommentStyle:
    line_prefixes: tuple = ()      # e.g. ("//",) or ("#",) or ("//", "#")
    block_pairs: tuple = ()        # e.g. (("/*", "*/"),)
    string_quotes: tuple = ("\"", "'")
    inline_marker: tuple = ()      # e.g. COBOL free-form "*>"


_C_STYLE = CommentStyle(line_prefixes=("//",), block_pairs=(("/*", "*/"),),
                        string_quotes=("\"", "'", "`"))
_HASH_STYLE = CommentStyle(line_prefixes=("#",), string_quotes=("\"", "'"))
_PHP_STYLE = CommentStyle(line_prefixes=("//", "#"), block_pairs=(("/*", "*/"),),
                          string_quotes=("\"", "'"))
_SQL_STYLE = CommentStyle(line_prefixes=("--",), block_pairs=(("/*", "*/"),),
                          string_quotes=("\"", "'"))
_XML_STYLE = CommentStyle(block_pairs=(("<!--", "-->"),), string_quotes=("\"", "'"))
_COBOL_STYLE = CommentStyle(line_prefixes=("*>",), string_quotes=("\"", "'"))
_NONE_STYLE = CommentStyle()  # no known comment syntax -> mask is a no-op

_EXT_STYLE = {
    ".java": _C_STYLE, ".kt": _C_STYLE, ".js": _C_STYLE, ".jsx": _C_STYLE,
    ".ts": _C_STYLE, ".tsx": _C_STYLE, ".go": _C_STYLE, ".cs": _C_STYLE,
    ".php": _PHP_STYLE,
    ".py": _HASH_STYLE, ".yml": _HASH_STYLE, ".yaml": _HASH_STYLE,
    ".properties": _HASH_STYLE, ".conf": _HASH_STYLE, ".ini": _HASH_STYLE,
    ".env": _HASH_STYLE,
    ".sql": _SQL_STYLE,
    ".xml": _XML_STYLE,
    ".cbl": _COBOL_STYLE, ".cob": _COBOL_STYLE, ".cpy": _COBOL_STYLE,
    ".json": _NONE_STYLE,  # JSON has no comment syntax; strings still scanned as-is
}


def style_for_ext(ext: str) -> CommentStyle:
    return _EXT_STYLE.get(ext.lower(), _NONE_STYLE)


def mask_comments(text: str, ext: str) -> str:
    """Return a same-length copy of `text` with comment contents replaced
    by spaces. Newlines are always preserved so line numbers computed
    against the result line up exactly with the original file. String
    literals are copied through unmodified."""
    style = style_for_ext(ext)
    if not style.line_prefixes and not style.block_pairs:
        return text

    out = list(text)
    n = len(text)
    i = 0
    in_string = None  # the quote char currently open, or None

    while i < n:
        ch = text[i]

        if in_string is not None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_string:
                in_string = None
            elif ch == "\n" and in_string != "`":
                # Unterminated single/double-quoted string hitting a
                # newline — bail out of "in string" rather than risk
                # masking real code on the next line. Backtick (JS
                # template literals) may legitimately span lines.
                in_string = None
            i += 1
            continue

        # Block comment start?
        matched_block = None
        for start, end in style.block_pairs:
            if text.startswith(start, i):
                matched_block = (start, end)
                break
        if matched_block:
            start, end = matched_block
            j = i + len(start)
            end_idx = text.find(end, j)
            stop = end_idx + len(end) if end_idx != -1 else n
            for k in range(i, stop):
                if text[k] != "\n":
                    out[k] = " "
            i = stop
            continue

        # Line comment (including COBOL's inline "*>") start?
        matched_line = next((p for p in style.line_prefixes if text.startswith(p, i)), None)
        if matched_line:
            nl_idx = text.find("\n", i)
            stop = nl_idx if nl_idx != -1 else n
            for k in range(i, stop):
                out[k] = " "
            i = stop
            continue

        if ch in style.string_quotes:
            in_string = ch
            i += 1
            continue

        i += 1

    return "".join(out)
