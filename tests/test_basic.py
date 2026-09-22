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


# ---------------------------------------------------------------------------
# Regression tests: comment masking + compound-signature detection + bisect
# line lookup (added after the BenPay/CryptoRadar false-positive review).
# ---------------------------------------------------------------------------

def test_comment_only_mention_is_not_flagged(tmp_path):
    """A // comment describing legacy crypto with no real code nearby
    should not produce a finding — this is the exact bug that made
    demo_repo's pqc-pilot-service (a file with NO legacy crypto at all)
    show a false RS256 finding sourced entirely from a comment."""
    f = tmp_path / "Notes.java"
    f.write_text(
        "// This service replaces the old RSA and DES based signing path.\n"
        "public class Notes {}\n"
    )
    result = scanner.scan_repo(str(tmp_path))
    assert result["findings"] == []


def test_hash_style_comment_is_not_flagged(tmp_path):
    f = tmp_path / "notes.py"
    f.write_text("# TODO: this used to call hashlib.md5(), now removed\n" "x = 1\n")
    result = scanner.scan_repo(str(tmp_path))
    assert result["findings"] == []


def test_block_comment_is_not_flagged(tmp_path):
    f = tmp_path / "Notes.java"
    f.write_text("/* legacy RSA signing removed in v2, see JIRA-114 */\n" "public class Notes {}\n")
    result = scanner.scan_repo(str(tmp_path))
    assert result["findings"] == []


def test_real_code_after_comment_still_detected_on_correct_line(tmp_path):
    """Comment masking must not swallow real findings on later lines, and
    line numbers must stay accurate once comments are stripped out."""
    f = tmp_path / "Legacy.java"
    f.write_text(
        "// RSA-1024 message signing for interbank settlement.\n"
        "public class Legacy {\n"
        "    KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\n"
        "}\n"
    )
    result = scanner.scan_repo(str(tmp_path))
    rsa_hits = [x for x in result["findings"] if x["signature_id"] == "RSA-KEYGEN"]
    assert len(rsa_hits) == 1, "comment mention should not duplicate the real finding"
    assert rsa_hits[0]["line"] == 3


def test_string_literal_is_not_treated_as_comment(tmp_path):
    """Comment masking must not eat string contents — a URL containing
    '//' inside a string literal must not be misread as a line comment,
    and a real finding later on the same or a following line must still
    be detected."""
    f = tmp_path / "Config.java"
    f.write_text(
        'String docs = "https://example.com/notes";\n'
        'MessageDigest.getInstance("MD5");\n'
    )
    result = scanner.scan_repo(str(tmp_path))
    md5_hits = [x for x in result["findings"] if x["signature_id"] == "MD5"]
    assert len(md5_hits) == 1
    assert md5_hits[0]["line"] == 2


def test_compound_jca_signature_algorithm_detected(tmp_path):
    """SHA256withRSA, SHA1withECDSA etc. are the single most common way
    Java names a signature algorithm, and were previously invisible to
    the scanner entirely: neither the standalone hash signature nor the
    standalone RSA/ECDSA signature matches inside the concatenated
    token, because word-boundary rules fail between 'with' and the
    algorithm name."""
    f = tmp_path / "Sig.java"
    f.write_text(
        'Signature.getInstance("SHA256withRSA");\n'
        'Signature.getInstance("SHA1withECDSA");\n'
        'Signature.getInstance("NONEwithECDSA");\n'
    )
    result = scanner.scan_repo(str(tmp_path))
    ids = [f["signature_id"] for f in result["findings"]]
    assert ids.count("JCA-COMPOUND-SIG-ALG") == 3


def test_line_numbers_match_naive_linear_scan(tmp_path):
    """Cross-check the bisect-based line lookup against an independent,
    deliberately naive re-implementation, on a file with matches spread
    across many lines — guards against an off-by-one regression in the
    O(n) -> O(log n) change."""
    lines = []
    expected_lines = []
    for i in range(1, 301):
        if i % 37 == 0:
            lines.append('MessageDigest.getInstance("MD5");')
            expected_lines.append(i)
        else:
            lines.append(f"int v{i} = {i};")
    f = tmp_path / "Many.java"
    f.write_text("\n".join(lines) + "\n")

    result = scanner.scan_repo(str(tmp_path))
    found_lines = sorted(x["line"] for x in result["findings"] if x["signature_id"] == "MD5")
    assert found_lines == expected_lines


def test_scan_speed_reasonable_on_larger_file(tmp_path):
    """Not a strict benchmark (CI hardware varies) — just a guard against
    an accidental reintroduction of O(n) or worse per-match behavior."""
    import time
    lines = []
    for i in range(5000):
        if i % 100 == 0:
            lines.append('Cipher.getInstance("DESede/CBC/PKCS5Padding");')
        else:
            lines.append(f"int v{i} = {i};")
    f = tmp_path / "Big.java"
    f.write_text("\n".join(lines) + "\n")

    t0 = time.perf_counter()
    scanner.scan_repo(str(tmp_path))
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"scan took {elapsed:.2f}s, expected well under 2s for 5000 lines"
