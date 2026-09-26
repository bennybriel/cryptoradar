# CryptoRadar

**A crypto-agility and quantum-readiness assessment toolkit built for mixed
legacy-core + modern-API fintech stacks — the reality of most African
fintech and banking estates.**

Current release: **v0.2.0** — see [CHANGELOG.md](CHANGELOG.md) for what
changed (a compound Java signature-algorithm detection fix, comment-aware
false-positive reduction, and a scanner performance fix).

Most crypto-inventory tools (IBM's CBOM tooling, Microsoft's SymCrypt
scanners, various OSS "crypto grep" scripts) are written for a single
modern language and a single clean repo. That's not what a Nigerian,
Kenyan, or Ghanaian bank or fintech actually runs: a COBOL or old-Java
core from a switch vendor, a Spring Boot or Node middleware layer bolted
on top, a PHP admin portal from 2014, and a mobile wallet client — often
four different teams, four different repos, four different crypto
postures. CryptoRadar scans all of it together and gives you one report.

## What it does

1. **Scans** a repo (or several components at once) for cryptographic
   primitive usage across Java/Kotlin, COBOL, JS/TS, Python, PHP, Go, C#,
   and config files — RSA/ECDSA/DH, weak hashes (MD5/SHA-1), weak ciphers
   (DES/3DES/RC4/ECB mode), old TLS versions, hardcoded secrets, static
   IVs, and non-cryptographic PRNGs used near security-relevant code.
2. **Builds a Crypto Bill of Materials (CBOM)** — a structured JSON
   inventory with file/line provenance, suitable for CI pipelines or
   feeding into a GRC tool.
3. **Scores readiness** per component (A–F) using severity-weighted
   findings, so you know which of your four repos to fix first.
4. **Runs a Mosca-inequality exposure check** (`X + Y > Z`) using
   your own shelf-life and migration-time estimates against a
   conservative range for "years until a cryptographically relevant
   quantum computer," so the report answers *when this actually needs to
   happen*, not just *what's wrong*.
5. **Recognizes PQC when it's already there** — ML-KEM, ML-DSA, SLH-DSA,
   Kyber/Dilithium/Falcon/SPHINCS+ — and flags it as a positive signal
   with a parameter-set sanity note, instead of just reporting absence of bugs.

## Quick start

```bash
pip install -e .

# Single component
cryptoradar scan ./identity-service --name "identity-service" -o report.html

# A whole mixed estate at once
cryptoradar scan-multi \
  "legacy-core:./core-banking" \
  "api-layer:./middleware-api" \
  "mobile-adapter:./wallet-bridge" \
  --shelf-life 15 --migration-time 4 \
  -o estate_report.html

# CI-friendly machine-readable output
cryptoradar cbom ./identity-service -o cbom.json
```

`demo_repo/` contains a small fictional four-component estate (a legacy
Java core with DES/MD5/RSA-1024, a Node API layer with RS256/SHA-1/ECB,
a Python mobile-bridge with MD5/3DES, and a pilot ML-KEM/ML-DSA service)
so you can see real output without pointing it at production code:

```bash
cryptoradar scan-multi \
  "legacy-core:demo_repo/legacy-core-java" \
  "api-layer:demo_repo/api-layer-node" \
  "mobile-adapter:demo_repo/mobile-adapter-python" \
  "pqc-pilot:demo_repo/pqc-pilot-service" \
  --shelf-life 15 --migration-time 4 -o demo_report.html
```

## Running a real client engagement (scan → review → roadmap)

A raw scan is a list of pattern matches, not a finding a bank should act
on. **The deliverable that's actually sellable is a document where every
item has been personally verified by a consultant** — this workflow makes
that the only path the tool supports; there is no CLI command that turns
an unreviewed CBOM directly into a client document.

```bash
# 1. Scan the client's full estate into one machine-readable CBOM.
#    Hardcoded secrets/IVs are redacted automatically at this step —
#    the raw values never get written to disk from here on.
cryptoradar cbom-multi \
  "legacy-core:./client-core-banking" \
  "api-layer:./client-middleware" \
  "mobile-adapter:./client-wallet-bridge" \
  -o cbom.json

# 2. Walk through every finding yourself. For each one: confirm it,
#    mark it a false positive, mark it an accepted (deferred) risk, or
#    mark it already remediated — with a note and, for confirmed items,
#    a priority phase. Progress saves after every single item, so it's
#    safe to Ctrl+C and resume later with the same command.
cryptoradar review cbom.json -o review.json --reviewer "Olamiji Gabriel"

# 3. Generate the actual client document. This step reads cbom.json +
#    review.json and INCLUDES ONLY findings that have a review record —
#    anything you skipped or haven't reached yet is silently left out,
#    and the command refuses to run at all against an empty review file.
cryptoradar roadmap cbom.json review.json \
  -o "ClientName_Crypto_Agility_Roadmap.docx" \
  --client "Client Bank Plc" \
  --consultant "Olamiji Gabriel" \
  --firm "Bennybriel Technologies" \
  --shelf-life 15 --migration-time 4
```

The resulting `.docx` has a cover page, an executive summary (counts of
confirmed / false-positive / accepted-risk / already-remediated — so the
client sees the review happened, not just the tool's raw output), the
Mosca exposure panel, a phased remediation roadmap table grouped by the
priority you assigned during review, an accepted-risk register, a
detailed appendix per confirmed finding (secrets still redacted here),
and a methodology/limitations section that says plainly this is not a
penetration test, audit, or compliance certification.

**Why the tool is built to make this the only path**, not just documented
as best practice: a report auto-generated straight from `cbom.json` would
be trivial to hand over unreviewed under deadline pressure — and the
biggest real risk this workflow is designed against isn't a missed
signature, it's a client being handed unverified automated output as if
it were consultant-verified. Building the enforcement into `roadmap.py`
(it calls the same merge function whether you remembered to review
carefully or not) means that mistake structurally can't happen, rather
than relying on remembering not to skip a step.

## Using it in someone else's project

**As a CLI, installed from GitHub (works today, no PyPI needed):**

Run these as two separate commands — pasting them as one line will make
`pip` try to parse `scan`/`-o` as install flags and fail:

```bash
pip install "git+https://github.com/bennybriel/cryptoradar.git@v0.2.0"
```
```bash
cryptoradar scan /path/to/a/real/repo-on-your-machine -o report.html
```

Replace the path with an actual folder that exists — pointing it at a
placeholder path (or an empty one) will correctly report `0 files, 0
findings` rather than erroring, which can look like a bug but isn't one.
The fastest way to see real output is to scan the bundled demo fixtures
instead of a repo of your own:

```bash
cd cryptoradar   # the folder this repo was cloned/extracted into
cryptoradar scan-multi \
  "legacy-core:demo_repo/legacy-core-java" \
  "api-layer:demo_repo/api-layer-node" \
  "mobile-adapter:demo_repo/mobile-adapter-python" \
  "pqc-pilot:demo_repo/pqc-pilot-service" \
  --shelf-life 15 --migration-time 4 \
  -o demo_report.html
```
(On Windows `cmd.exe`, replace the trailing `\` line continuations with
`^`, or just put the whole command on one line.)

Then open the report — it's a single static HTML file, no server needed:

```bash
open report.html      # macOS
xdg-open report.html  # Linux
start report.html     # Windows
```

**If `cryptoradar` isn't recognized after installing (common on Windows):**
pip installs the command into a `Scripts` folder that isn't always on your
`PATH` by default. Two fixes, easiest first:

- Skip PATH entirely and call the module directly — works immediately,
  every OS: `python -m cryptoradar.cli scan /path/to/repo -o report.html`
- Or fix PATH properly: run `pip show -f cryptoradar`, find the folder
  containing `cryptoradar.exe` (or `cryptoradar` on macOS/Linux), add it to
  your OS's `PATH` environment variable, then **open a new terminal window**
  (existing windows won't pick up the change) and try `cryptoradar --help` again.

Pin a tag/commit instead of `main` for anything beyond a quick try —
`...cryptoradar.git@v0.2.0` as shown above — so a later change to this
repo's default branch doesn't silently change what gets installed.

**As a GitHub Action, in their own CI pipeline** — this repo ships a
composite action (`action.yml`) so any repo on GitHub can add crypto
scanning to its workflow with no local install step:

```yaml
# .github/workflows/crypto-scan.yml in THEIR repo
on: [pull_request]
jobs:
  crypto-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bennybriel/cryptoradar@v0.2.0   # pin to a tag in production
        with:
          path: '.'
          fail-on: critical      # fails the PR check if a critical finding exists
          shelf-life: '15'
          migration-time: '4'
```

This fails their PR check on critical findings (hardcoded secrets, broken
ciphers) while leaving lower-severity/quantum-relevant findings as a report
artifact to review rather than a hard block — deliberately, since a repo's
first scan usually turns up a backlog that shouldn't block every subsequent PR.

**As a library**, for anyone building on top of it (e.g. a custom dashboard):

```python
from cryptoradar import scanner, risk, report

result = scanner.scan_repo("./some-service", component_name="some-service")
summary = risk.summarize(result["findings"])
print(summary.readiness_grade, summary.readiness_percent)
html = report.render_report(result)
```

**Not yet on PyPI** — `pip install cryptoradar` (without the `git+` URL)
isn't live yet. Publishing there is a five-minute `python -m build && twine
upload` once the name is confirmed available, and is worth doing before
pointing external users at this rather than internal/consulting-client use.

## Architecture

```
cryptoradar/
  detectors.py   - signature catalogue (regex-based, cross-language)
  scanner.py     - repo walker -> CBOM findings
  redact.py      - masks secret/IV values before they reach any output
  risk.py        - severity scoring + Mosca inequality calculator
  review.py      - analyst triage layer (confirm/dismiss/accept-risk per finding)
  roadmap.py     - client-facing .docx generator (reviewed findings only)
  report.py      - self-contained HTML report renderer (for internal/CI use)
  cli.py         - `cryptoradar scan / scan-multi / cbom / cbom-multi / review / roadmap`
tests/           - pytest smoke tests
demo_repo/       - fictional 4-component mixed stack for demos/sales calls
```

Deliberately regex-based rather than full AST parsing: real fintech
estates mix COBOL, old Java, config files, and stored procedures, and a
"good enough, works everywhere, ships this week" scanner beats a
perfect-but-Java-only one for a first assessment pass. AST-based deep
scanning for the highest-value languages (Java/Kotlin first) is the
natural v2 add-on — see roadmap below.

## Why this exists

Adapted from ongoing PhD research on lattice-based post-quantum
cryptography and homomorphic encryption in blockchain/fintech systems,
and from hands-on work migrating a real fintech platform's JWT signing
from HS256 to RS256 and integrating a post-quantum crypto module
(ML-DSA-65 / ML-KEM-1024 via BouncyCastle). The gap this toolkit targets:
almost nobody serving African financial infrastructure has an actual
inventory of where RSA, 3DES, or MD5 are load-bearing in their stack —
which is the prerequisite for any migration plan, PQC or otherwise.
## See also

This scanner diagnoses where a fintech stack relies on quantum-vulnerable
cryptography. For a working example of what the *fix* looks like once
built — quantum-safe identity credentials, ML-KEM channel security, and
privacy-preserving payment analytics via homomorphic encryption, all
running as a real FastAPI service — see
[quantum-safe-fintech-infra](https://github.com/bennybriel/quantum-safe-fintech-infra).

see the [proof-of-concept summary](proof-of-concept-summary.pdf) for engagement options
## Business model

This is designed as **open-core, not open-and-hope**:

- **OSS scanner (MIT, this repo)** — free, self-hostable, CI-friendly.
  Drives adoption and credibility; the free tier is genuinely useful on
  its own, not a crippled demo.
- **Consulting engagements** (the near-term revenue path, sellable
  starting now): a paid "Crypto Agility Assessment" — run the scanner
  across a client's full estate, manually verify the highest-severity
  findings, size the Mosca inputs with their actual data-retention and
  regulatory requirements (CBN/PCI-DSS/NDPR-driven shelf-life), and
  deliver a prioritized migration roadmap + a debrief to their tech and
  risk teams. This is the same motion as the BenPay JWT/PQC migration
  work, packaged as a repeatable offering.
- **Hosted SaaS tier** (medium-term): continuous scanning on every PR via
  a GitHub/GitLab app, a dashboard tracking readiness-grade trend over
  time per component, Slack/email alerts on new high-severity findings,
  and exportable CBOM/compliance reports for regulators or auditors.
  Priced per repo/component per month; the open CLI becomes the
  local-dev/CI companion to the hosted dashboard rather than a competitor
  to it.
- **Compliance/regulator angle**: CBN and peer regulators across the
  region are increasingly asking about cryptographic risk management;
  a standardized CBOM + readiness report is a concrete artifact banks
  and fintechs can hand to examiners, which is a wedge for both the
  consulting and SaaS tracks.

## Project Roadmap

(Not to be confused with the `cryptoradar roadmap` command above, which
generates a client deliverable — this section is the tool's own future work.)

- [ ] AST-based Java detector (reduce false positives on comments/strings)
- [ ] COBOL `CALL 'CSNBENC'`/ICSF-style crypto call detection for real mainframe cores
- [ ] GitHub Action / GitLab CI template (`cryptoradar cbom --fail-on critical`)
- [ ] Hosted dashboard (trend lines, PR diffing, Slack alerts) — SaaS tier
- [ ] PDF export of the HTML report for board/regulator packs
- [ ] Signature packs for HSM/KMS config files (PKCS#11 provider strings, AWS KMS key specs)

## License

MIT for the scanner core. (Nothing here should ever be the bottleneck to
someone improving their crypto posture — the business is the assessment,
the roadmap, and the ongoing monitoring, not gatekeeping the scanner.)
