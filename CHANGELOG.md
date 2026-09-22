# Changelog

## v0.2.0

### Fixed — false negative (coverage gap)
- **New `JCA-COMPOUND-SIG-ALG` signature.** Java's convention of naming a
  signature algorithm as one concatenated token — `SHA256withRSA`,
  `SHA1withECDSA`, `NONEwithECDSA`, etc. — was **completely undetected**
  by every prior signature. Word-boundary rules (`\b`) fail between
  `with` and the algorithm name because both sides are letters with no
  separator, so neither the standalone hash signature nor the standalone
  RSA/ECDSA signature could match. This is arguably the single most
  common way Java code names a signing algorithm, so this was a real
  coverage gap, not an edge case. Confirmed empirically against
  `SHA256withRSA`, `SHA1withECDSA`, `SHA256withECDSA`, `NONEwithECDSA`,
  `MD5withRSA`, `SHA1withDSA` — all previously produced zero findings.

### Fixed — false positives / noise
- **New `comments.py`: single-pass, offset-preserving comment masking.**
  Signatures previously matched raw file text, so a comment describing
  legacy crypto (`// RSA-1024 message signing...`) fired the identical
  finding as the real code beneath it — duplicate noise at minimum, and
  in one demo_repo case (`pqc-pilot-service`, a file with no legacy
  crypto at all) produced a **pure false positive** sourced entirely
  from a comment mentioning another service's old algorithm for context.
  String literals are deliberately NOT masked — a secret or algorithm
  name inside a quoted string is exactly what the scanner exists to find.
  Supports `//` and `/* */` (Java/Kotlin/JS/TS/Go/C#), `#` (Python/YAML/
  properties/conf/ini/env), PHP's combined style, SQL `--`, XML
  `<!-- -->`, and COBOL free-form `*>`.
- Measured impact on `demo_repo` (4 components, 6 files): total findings
  20 -> 17. Two were exact duplicates of a real finding one line away
  (comment + code both matching), one was the pure false positive above,
  and the new compound-signature detector added one previously-missed
  true positive.

### Changed — performance
- **`scanner.py`: O(log n) line-number lookup via `bisect` instead of
  O(n) linear scan per match.** Previously, every single regex match
  re-scanned the file's line-start table from the beginning to find its
  line number — O(matches x lines) for one file. Verified correctness
  (identical output to the old linear scan on 16,667 lookups against a
  50,000-line synthetic file) and measured a **~2,760x** speedup on that
  same benchmark. Real-world impact scales with file size and match
  density; negligible on small files, significant on large generated
  configs or monolith files.
- `scan_file()` now reads each file once (`fh.read()`) instead of
  `readlines()` followed by immediately re-joining the lines back into
  a single string.

### Housekeeping
- Fixed `__init__.__version__` (was still `"0.1.0"`, out of sync with
  `pyproject.toml`'s `"0.2.0"`).
- Added `demo_repo/legacy-core-java/.../SignatureAlgorithms.java` per
  `CONTRIBUTING.md`'s convention of a demo fixture per new signature.
- Added 8 regression tests (comment masking x4, compound-signature
  detection, string-literal-not-masked, line-number correctness
  cross-checked against a naive re-implementation, and a scan-speed
  guard) — 16 tests total, all passing.

## v0.1.0
- Initial release: signature-based scanning across Java/Kotlin, COBOL,
  JS/TS, Python, PHP, Go, C#, and config files; CBOM (JSON) output;
  HTML report with per-component readiness grading; Mosca-inequality
  exposure calculator.
