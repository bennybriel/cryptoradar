"""
risk.py — Turns raw findings into a Crypto Bill of Materials (CBOM) risk
score and a Mosca-inequality quantum exposure timeline.

Mosca's theorem (simplified): an organization is already at risk today if

    X + Y > Z

  X = years the data/system must stay secure ("shelf-life")
  Y = years needed to migrate once you start ("migration time")
  Z = years until a cryptographically relevant quantum computer exists
      ("theft-to-break horizon" — inherently a range/estimate, not a fact)

"Harvest now, decrypt later" means an attacker capturing encrypted traffic
or data-at-rest TODAY only needs Z to arrive before X elapses — Y is
irrelevant to that specific risk, which is why long-shelf-life data
(KYC records, loan histories, national-ID-linked financial records) is
urgent even though a live migration project has years to run.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict

from .detectors import Category


# Default estimate bands for Z, editable per engagement via CLI flags.
# These are deliberately conservative/uncertain — presented as a range,
# never a single confident number, per NIST/NSA guidance on CRQC timing.
Z_ESTIMATE_LOW = 8
Z_ESTIMATE_HIGH = 20


@dataclass
class MoscaResult:
    shelf_life_years: float
    migration_years: float
    z_low: int
    z_high: int
    at_risk_low: bool
    at_risk_high: bool
    verdict: str


def mosca_assessment(shelf_life_years: float, migration_years: float,
                      z_low: int = Z_ESTIMATE_LOW, z_high: int = Z_ESTIMATE_HIGH) -> MoscaResult:
    x_plus_y = shelf_life_years + migration_years
    at_risk_low = x_plus_y > z_low
    at_risk_high = x_plus_y > z_high

    if at_risk_low and at_risk_high:
        verdict = ("URGENT: X+Y exceeds even the optimistic-for-defenders "
                   "(long) horizon estimate for Z. Treat as already exposed "
                   "to harvest-now-decrypt-later risk.")
    elif at_risk_low:
        verdict = ("AT RISK under the conservative (near-term) Z estimate. "
                   "Migration should be scheduled now, not after a firm CRQC "
                   "timeline exists — none will arrive with advance warning.")
    else:
        verdict = ("Currently within margin under both Z estimates — but "
                   "re-run this assessment periodically as shelf-life "
                   "requirements or Z estimates change.")

    return MoscaResult(shelf_life_years, migration_years, z_low, z_high,
                        at_risk_low, at_risk_high, verdict)


# ---------------------------------------------------------------------------
# Finding-level and repo-level scoring
# ---------------------------------------------------------------------------

# Weight applied on top of raw signature severity, to bias total score
# toward things that matter most for a mixed legacy-core + API-layer stack.
CATEGORY_WEIGHT = {
    Category.HARDCODED_SECRET: 1.4,
    Category.CIPHER_WEAK: 1.3,
    Category.HASH_WEAK: 1.1,
    Category.ASYMMETRIC_QUANTUM_BREAKABLE: 1.2,
    Category.PROTOCOL_WEAK: 1.1,
    Category.KEY_MGMT: 1.15,
    Category.SYMMETRIC_QUANTUM_WEAKENED: 0.8,
    Category.PQC_PRESENT: 0.0,  # not a penalty
}


def score_finding(severity: int, category: Category) -> float:
    return round(severity * CATEGORY_WEIGHT.get(category, 1.0), 2)


@dataclass
class RepoRiskSummary:
    total_findings: int
    findings_by_category: dict
    findings_by_primitive: dict
    total_weighted_score: float
    quantum_relevant_findings: int
    positive_pqc_findings: int
    readiness_grade: str
    readiness_percent: float


def grade_from_score(weighted_score: float, total_findings_excl_positive: int) -> tuple[str, float]:
    """Cruder-is-better here on purpose: a small, well-understood legacy
    core with 5 findings is a very different risk profile from a sprawling
    monorepo with 500 — so we normalize per-finding, then bucket."""
    if total_findings_excl_positive == 0:
        return "A (no crypto-agility findings detected)", 100.0

    avg = weighted_score / total_findings_excl_positive
    # avg weighted severity roughly in [0, 7]
    pct = max(0.0, 100.0 - (avg / 7.0) * 100.0)

    if pct >= 85:
        grade = "A"
    elif pct >= 70:
        grade = "B"
    elif pct >= 50:
        grade = "C"
    elif pct >= 30:
        grade = "D"
    else:
        grade = "F"
    return grade, round(pct, 1)


def summarize(findings: list[dict]) -> RepoRiskSummary:
    by_cat = Counter()
    by_prim = Counter()
    weighted_total = 0.0
    quantum_count = 0
    positive_count = 0

    for f in findings:
        cat = f["category"]
        by_cat[cat] += 1
        by_prim[f["primitive"]] += 1
        if cat == Category.PQC_PRESENT.value:
            positive_count += 1
            continue
        weighted_total += f["weighted_score"]
        if f["quantum_relevant"]:
            quantum_count += 1

    total_excl_positive = sum(v for k, v in by_cat.items() if k != Category.PQC_PRESENT.value)
    grade, pct = grade_from_score(weighted_total, total_excl_positive)

    return RepoRiskSummary(
        total_findings=len(findings),
        findings_by_category=dict(by_cat),
        findings_by_primitive=dict(by_prim),
        total_weighted_score=round(weighted_total, 2),
        quantum_relevant_findings=quantum_count,
        positive_pqc_findings=positive_count,
        readiness_grade=grade,
        readiness_percent=pct,
    )
