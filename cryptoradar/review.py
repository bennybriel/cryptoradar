"""
review.py — The human-in-the-loop layer between a raw scan and a client
deliverable. A CBOM is a list of pattern matches; it is not, by itself,
a verified finding. This module makes an analyst explicitly confirm,
dismiss, or accept-risk-on every item before it can appear in a roadmap
document, and records who did it and when.

Design intent: it should be *impossible* to generate a client roadmap
from unreviewed findings. `roadmap.py` enforces this by refusing to
include anything without a review record.
"""

from __future__ import annotations
import hashlib
import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum


class Status(str, Enum):
    CONFIRMED = "confirmed"                # real issue, goes in the roadmap
    FALSE_POSITIVE = "false_positive"       # pattern matched, not actually exploitable/relevant
    ACCEPTED_RISK = "accepted_risk"         # real, but client/business has chosen not to remediate (yet)
    REMEDIATED = "remediated"               # was real, already fixed since the scan


class Priority(str, Enum):
    IMMEDIATE = "immediate"        # 0-30 days — hardcoded secrets, active exploitation risk
    SHORT_TERM = "short_term"      # 1-3 months
    MEDIUM_TERM = "medium_term"    # 3-9 months
    LONG_TERM = "long_term"        # 9-18 months — larger migrations (e.g. RSA/ECDSA -> PQC)
    MONITOR = "monitor"            # no action now, revisit on next assessment cycle


PRIORITY_LABEL = {
    Priority.IMMEDIATE: "Immediate (0-30 days)",
    Priority.SHORT_TERM: "Short-term (1-3 months)",
    Priority.MEDIUM_TERM: "Medium-term (3-9 months)",
    Priority.LONG_TERM: "Long-term (9-18 months)",
    Priority.MONITOR: "Monitor / next cycle",
}


def finding_key(finding: dict) -> str:
    """Stable identifier for a finding across re-scans, as long as the
    file/line/signature don't change. Used to key review records and to
    let `review --resume` skip items already triaged."""
    basis = f"{finding['file']}::{finding['line']}::{finding['signature_id']}"
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


@dataclass
class ReviewRecord:
    status: str
    note: str
    priority: str | None
    reviewer: str
    reviewed_at: str


def load_review(path: str) -> dict:
    if not os.path.exists(path):
        return {"reviewer_log": [], "records": {}}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_review(path: str, review: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(review, fh, indent=2)


def _all_findings(cbom: dict) -> list[dict]:
    if "components" in cbom:
        out = []
        for c in cbom["components"]:
            for f in c["findings"]:
                out.append({**f, "_component": c["component"]})
        return out
    return [{**f, "_component": cbom.get("component", "unknown")} for f in cbom["findings"]]


def _prompt_choice(prompt: str, choices: dict[str, str]) -> str:
    opts = "  ".join(f"[{k}] {v}" for k, v in choices.items())
    while True:
        ans = input(f"{prompt}\n  {opts}\n> ").strip().lower()
        if ans in choices:
            return ans
        print("  (not a valid option, try again)")


STATUS_KEYS = {"c": Status.CONFIRMED, "f": Status.FALSE_POSITIVE,
               "a": Status.ACCEPTED_RISK, "r": Status.REMEDIATED}
PRIORITY_KEYS = {"1": Priority.IMMEDIATE, "2": Priority.SHORT_TERM,
                 "3": Priority.MEDIUM_TERM, "4": Priority.LONG_TERM, "5": Priority.MONITOR}


def run_interactive_review(cbom: dict, review_path: str, reviewer: str,
                            resume: bool = True, skip_positive: bool = True) -> dict:
    from .detectors import Category  # local import avoids a cycle at module load

    review = load_review(review_path) if resume else {"reviewer_log": [], "records": {}}
    findings = _all_findings(cbom)
    if skip_positive:
        findings = [f for f in findings if f["category"] != Category.PQC_PRESENT.value]
    findings.sort(key=lambda f: -f["severity"])

    pending = [f for f in findings if finding_key(f) not in review["records"]]
    already = len(findings) - len(pending)
    print(f"\n[cryptoradar review] {len(findings)} findings loaded "
          f"({already} already reviewed, {len(pending)} to go). Reviewer: {reviewer}\n")

    i = 0
    for i, f in enumerate(pending, 1):
        print("-" * 72)
        print(f"[{i}/{len(pending)}] {f['_component']} · {f['file']}:{f['line']} "
              f"· severity={f['severity']} · {f['primitive']}")
        print(f"  snippet : {f['snippet']}")
        print(f"  why     : {f['note']}")
        print(f"  hint    : {f['migration_hint']}")

        status_key = _prompt_choice(
            "Status?", {"c": "confirmed", "f": "false positive", "a": "accepted risk",
                        "r": "already remediated", "s": "skip for now", "q": "quit & save"})
        if status_key == "q":
            break
        if status_key == "s":
            continue

        note = input("  Note (optional, press Enter to skip): ").strip()
        priority = None
        if STATUS_KEYS[status_key] == Status.CONFIRMED:
            pkey = _prompt_choice("Priority?", {k: PRIORITY_LABEL[v] for k, v in PRIORITY_KEYS.items()})
            priority = PRIORITY_KEYS[pkey].value

        record = ReviewRecord(
            status=STATUS_KEYS[status_key].value,
            note=note,
            priority=priority,
            reviewer=reviewer,
            reviewed_at=datetime.now(timezone.utc).isoformat(),
        )
        review["records"][finding_key(f)] = asdict(record)
        save_review(review_path, review)  # persist after every item — never lose progress

    review["reviewer_log"].append({
        "reviewer": reviewer,
        "session_ended_at": datetime.now(timezone.utc).isoformat(),
        "findings_reviewed_this_session": min(i, len(pending)) if pending else 0,
    })
    save_review(review_path, review)
    print(f"\n[cryptoradar review] Saved -> {review_path}")
    return review


def merge_reviewed_findings(cbom: dict, review: dict) -> list[dict]:
    """Returns findings enriched with their review record, EXCLUDING any
    finding that has no review record at all. This is the enforcement
    point: roadmap.py only ever sees what a human has actually looked at."""
    findings = _all_findings(cbom)
    out = []
    for f in findings:
        key = finding_key(f)
        record = review["records"].get(key)
        if record is None:
            continue
        out.append({**f, "review": record})
    return out
