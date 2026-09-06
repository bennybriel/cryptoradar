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
