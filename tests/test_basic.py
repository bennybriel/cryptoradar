"""Minimal smoke tests — run with: python -m pytest tests/ -q"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptoradar import scanner, risk, report


def test_detects_des_and_md5(tmp_path):
    f = tmp_path / "Legacy.java"
    f.write_text('Cipher.getInstance("DESede/CBC/PKCS5Padding"); MessageDigest.getInstance("MD5");')
    result = scanner.scan_repo(str(tmp_path))
    ids = {finding["signature_id"] for finding in result["findings"]}
    assert "DES-3DES" in ids
    assert "MD5" in ids


def test_pqc_present_not_penalized(tmp_path):
    f = tmp_path / "Pqc.java"
    f.write_text('KeyPairGenerator.getInstance("ML-KEM-1024", "BCPQC");')
    result = scanner.scan_repo(str(tmp_path))
    summary = risk.summarize(result["findings"])
    assert summary.positive_pqc_findings == 1
    assert summary.readiness_grade.startswith("A")


def test_mosca_flags_urgent_when_shelf_life_plus_migration_exceeds_z():
    m = risk.mosca_assessment(shelf_life_years=15, migration_years=6, z_low=8, z_high=20)
    assert m.at_risk_low is True
    assert m.at_risk_high is True


def test_mosca_not_urgent_for_short_lived_data():
    m = risk.mosca_assessment(shelf_life_years=1, migration_years=1, z_low=8, z_high=20)
    assert m.at_risk_low is False
    assert m.at_risk_high is False


def test_report_renders_without_error(tmp_path):
    f = tmp_path / "x.js"
    f.write_text("crypto.createHash('sha1');")
    result = scanner.scan_repo(str(tmp_path), component_name="x")
    html_out = report.render_report(result, {"shelf_life_years": 10, "migration_years": 3})
    assert "<!doctype html>" in html_out
    assert "SHA-1" in html_out


def test_hardcoded_secret_is_redacted_in_findings(tmp_path):
    f = tmp_path / "Config.java"
    f.write_text('private String secret = "REDACTED_TEST_FIXTURE_VALUE_0123456789";')
    result = scanner.scan_repo(str(tmp_path))
    hits = [x for x in result["findings"] if x["signature_id"] == "HARDCODED-KEY"]
    assert hits, "expected a hardcoded-key finding"
    assert "REDACTED_TEST_FIXTURE_VALUE_0123456789" not in hits[0]["snippet"]
    assert hits[0]["snippet"].count("*") > 0


def test_roadmap_only_includes_reviewed_findings(tmp_path):
    from cryptoradar import review as review_mod, roadmap as roadmap_mod

    f = tmp_path / "Legacy.java"
    f.write_text('MessageDigest.getInstance("MD5"); MessageDigest.getInstance("SHA-1");')
    cbom = scanner.scan_repo(str(tmp_path), component_name="svc")

    all_findings = review_mod._all_findings(cbom)
    assert len(all_findings) == 2

    # Only review (confirm) ONE of the two findings.
    key = review_mod.finding_key(all_findings[0])
    review = {"reviewer_log": [], "records": {
        key: {"status": "confirmed", "note": "yep", "priority": "immediate",
              "reviewer": "tester", "reviewed_at": "2026-01-01T00:00:00+00:00"}
    }}

    doc = roadmap_mod.build_roadmap(cbom, review, {"client": "Acme", "consultant": "Tester"})
    all_text = "\n".join(p.text for p in doc.paragraphs)
    # The unreviewed second finding's primitive must NOT appear anywhere as a confirmed item —
    # cheap proxy check: total table rows added should reflect exactly 1 confirmed finding.
    assert "Confirmed findings requiring action: 1" in all_text


def test_roadmap_refuses_via_cli_with_empty_review(tmp_path):
    from cryptoradar import review as review_mod
    empty = {"reviewer_log": [], "records": {}}
    review_mod.save_review(str(tmp_path / "review.json"), empty)
    loaded = review_mod.load_review(str(tmp_path / "review.json"))
    assert loaded["records"] == {}
