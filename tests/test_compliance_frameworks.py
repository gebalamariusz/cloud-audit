"""Tests for BSI C5:2020, ISO 27001:2022, HIPAA Security Rule, and NIS2 Directive compliance frameworks."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cloud_audit.compliance import list_frameworks, load_framework
from cloud_audit.compliance.engine import build_compliance_report
from cloud_audit.models import ScanReport

FRAMEWORKS_DIR = Path(__file__).parent.parent / "src" / "cloud_audit" / "compliance" / "frameworks"

VALID_CHECKS = {
    "aws-account-001",
    "aws-iam-001",
    "aws-iam-002",
    "aws-iam-003",
    "aws-iam-004",
    "aws-iam-005",
    "aws-iam-006",
    "aws-iam-007",
    "aws-iam-008",
    "aws-iam-009",
    "aws-iam-010",
    "aws-iam-011",
    "aws-iam-012",
    "aws-iam-013",
    "aws-iam-014",
    "aws-iam-015",
    "aws-iam-016",
    "aws-s3-001",
    "aws-s3-002",
    "aws-s3-003",
    "aws-s3-004",
    "aws-s3-005",
    "aws-s3-006",
    "aws-s3-007",
    "aws-ec2-001",
    "aws-ec2-002",
    "aws-ec2-003",
    "aws-ec2-004",
    "aws-ec2-005",
    "aws-ec2-006",
    "aws-vpc-001",
    "aws-vpc-002",
    "aws-vpc-003",
    "aws-vpc-004",
    "aws-vpc-005",
    "aws-rds-001",
    "aws-rds-002",
    "aws-rds-003",
    "aws-rds-004",
    "aws-ct-001",
    "aws-ct-002",
    "aws-ct-003",
    "aws-ct-004",
    "aws-ct-005",
    "aws-ct-006",
    "aws-ct-007",
    "aws-cw-001",
    "aws-cw-002",
    "aws-cw-003",
    "aws-cw-004",
    "aws-cw-005",
    "aws-cw-006",
    "aws-cw-007",
    "aws-cw-008",
    "aws-cw-009",
    "aws-cw-010",
    "aws-cw-011",
    "aws-cw-012",
    "aws-cw-013",
    "aws-cw-014",
    "aws-cw-015",
    "aws-cfg-001",
    "aws-cfg-002",
    "aws-cfg-003",
    "aws-cfg-004",
    "aws-ddb-001",
    "aws-ddb-002",
    "aws-ddb-003",
    "aws-ecs-001",
    "aws-ecs-002",
    "aws-ecs-003",
    "aws-efs-001",
    "aws-eip-001",
    "aws-gd-001",
    "aws-gd-002",
    "aws-kms-001",
    "aws-kms-002",
    "aws-lambda-001",
    "aws-lambda-002",
    "aws-lambda-003",
    "aws-sm-001",
    "aws-sm-002",
    "aws-sh-001",
    "aws-ssm-001",
    "aws-ssm-002",
    "aws-ssm-003",
    "aws-backup-001",
    "aws-inspector-001",
    "aws-waf-001",
    "aws-cw-016",
    "aws-vpc-006",
    "aws-iam-017",
    "aws-ct-008",
}

VALID_CHAINS = {
    "AC-01",
    "AC-02",
    "AC-05",
    "AC-07",
    "AC-09",
    "AC-10",
    "AC-11",
    "AC-12",
    "AC-13",
    "AC-14",
    "AC-17",
    "AC-19",
    "AC-20",
    "AC-21",
    "AC-23",
    "AC-24",
    "AC-25",
    "AC-26",
    "AC-27",
    "AC-28",
    "AC-29",
    "AC-30",
    "AC-31",
    "AC-32",
    "AC-33",
}

REQUIRED_FIELDS = [
    "title",
    "section",
    "level",
    "assessment",
    "description",
    "checks",
    "manual_steps",
    "evidence_template",
]


def _make_empty_scan() -> ScanReport:
    scan = ScanReport(
        provider="aws",
        account_id="123456789012",
        regions=["eu-central-1"],
        results=[],
        duration_seconds=1.0,
        timestamp="2026-04-03T00:00:00Z",
    )
    scan.compute_summary()
    return scan


# ── BSI C5:2020 ──────────────────────────────────────────────────────


class TestBSIC5Loading:
    def test_discoverable(self) -> None:
        ids = [fw["id"] for fw in list_frameworks()]
        assert "bsi_c5_2020" in ids

    def test_loads(self) -> None:
        fw = load_framework("bsi_c5_2020")
        assert fw["framework_id"] == "bsi_c5_2020"
        assert "BSI" in fw["framework_name"]
        assert fw["version"] == "2020"

    def test_disclaimer(self) -> None:
        fw = load_framework("bsi_c5_2020")
        assert "does not constitute" in fw["disclaimer"]


class TestBSIC5Structure:
    def test_control_count(self) -> None:
        fw = load_framework("bsi_c5_2020")
        assert len(fw["controls"]) >= 100, "BSI C5 should have 100+ criteria"

    def test_required_fields(self) -> None:
        fw = load_framework("bsi_c5_2020")
        for cid, ctrl in fw["controls"].items():
            for field in REQUIRED_FIELDS:
                assert field in ctrl, f"BSI {cid} missing field: {field}"

    def test_assessment_values(self) -> None:
        fw = load_framework("bsi_c5_2020")
        for cid, ctrl in fw["controls"].items():
            assert ctrl["assessment"] in ("Automated", "Manual", "Partial"), f"BSI {cid}: {ctrl['assessment']}"

    def test_check_ids_valid(self) -> None:
        fw = load_framework("bsi_c5_2020")
        for cid, ctrl in fw["controls"].items():
            for check_id in ctrl.get("checks", []):
                assert check_id in VALID_CHECKS, f"BSI {cid}: invalid check {check_id}"

    def test_automated_have_checks(self) -> None:
        fw = load_framework("bsi_c5_2020")
        for cid, ctrl in fw["controls"].items():
            if ctrl["assessment"] == "Automated":
                assert ctrl["checks"], f"BSI {cid} is Automated but has no checks"

    def test_manual_no_checks(self) -> None:
        fw = load_framework("bsi_c5_2020")
        for cid, ctrl in fw["controls"].items():
            if ctrl["assessment"] == "Manual":
                assert not ctrl["checks"], f"BSI {cid} is Manual but has checks"

    def test_bsi_domains_present(self) -> None:
        fw = load_framework("bsi_c5_2020")
        sections = {ctrl["section"] for ctrl in fw["controls"].values()}
        for expected in ["IDM", "CRY", "OPS", "COM", "LOG"]:
            assert any(expected in s for s in sections), f"BSI domain {expected} not found"


class TestBSIC5Chains:
    def test_all_chains_mapped(self) -> None:
        fw = load_framework("bsi_c5_2020")
        assert set(fw["attack_chain_mappings"].keys()) == VALID_CHAINS

    def test_chain_refs_valid(self) -> None:
        fw = load_framework("bsi_c5_2020")
        ctrl_ids = set(fw["controls"].keys())
        for chain_id, refs in fw["attack_chain_mappings"].items():
            for ref in refs:
                assert ref in ctrl_ids, f"BSI chain {chain_id} -> invalid control {ref}"


class TestBSIC5Engine:
    def test_empty_scan(self) -> None:
        report = build_compliance_report("bsi_c5_2020", _make_empty_scan())
        assert report.total_controls >= 100
        assert report.framework_id == "bsi_c5_2020"


# ── ISO 27001:2022 ──────────────────────────────────────────────────


class TestISO27001Loading:
    def test_discoverable(self) -> None:
        ids = [fw["id"] for fw in list_frameworks()]
        assert "iso27001_2022" in ids

    def test_loads(self) -> None:
        fw = load_framework("iso27001_2022")
        assert fw["framework_id"] == "iso27001_2022"
        assert "27001" in fw["framework_name"]
        assert fw["version"] == "2022"


class TestISO27001Structure:
    def test_exactly_93_controls(self) -> None:
        fw = load_framework("iso27001_2022")
        assert len(fw["controls"]) == 93

    def test_annex_a_id_format(self) -> None:
        fw = load_framework("iso27001_2022")
        pattern = re.compile(r"^A\.[5-8]\.\d{1,2}$")
        for cid in fw["controls"]:
            assert pattern.match(cid), f"ISO invalid control ID: {cid}"

    def test_four_themes(self) -> None:
        fw = load_framework("iso27001_2022")
        sections = {ctrl["section"] for ctrl in fw["controls"].values()}
        assert any("Organizational" in s for s in sections)
        assert any("People" in s for s in sections)
        assert any("Physical" in s for s in sections)
        assert any("Technological" in s for s in sections)

    def test_theme_counts(self) -> None:
        fw = load_framework("iso27001_2022")
        counts = {"A.5": 0, "A.6": 0, "A.7": 0, "A.8": 0}
        for cid in fw["controls"]:
            prefix = cid[:3]
            if prefix in counts:
                counts[prefix] += 1
        assert counts["A.5"] == 37
        assert counts["A.6"] == 8
        assert counts["A.7"] == 14
        assert counts["A.8"] == 34

    def test_required_fields(self) -> None:
        fw = load_framework("iso27001_2022")
        for cid, ctrl in fw["controls"].items():
            for field in REQUIRED_FIELDS:
                assert field in ctrl, f"ISO {cid} missing: {field}"

    def test_check_ids_valid(self) -> None:
        fw = load_framework("iso27001_2022")
        for cid, ctrl in fw["controls"].items():
            for check_id in ctrl.get("checks", []):
                assert check_id in VALID_CHECKS, f"ISO {cid}: invalid check {check_id}"

    def test_a8_has_most_automation(self) -> None:
        fw = load_framework("iso27001_2022")
        a8_checks = set()
        for cid, ctrl in fw["controls"].items():
            if cid.startswith("A.8"):
                a8_checks.update(ctrl.get("checks", []))
        assert len(a8_checks) >= 50, f"A.8 only maps {len(a8_checks)} checks"


class TestISO27001Chains:
    def test_all_chains_mapped(self) -> None:
        fw = load_framework("iso27001_2022")
        assert set(fw["attack_chain_mappings"].keys()) == VALID_CHAINS

    def test_chain_refs_valid(self) -> None:
        fw = load_framework("iso27001_2022")
        ctrl_ids = set(fw["controls"].keys())
        for chain_id, refs in fw["attack_chain_mappings"].items():
            for ref in refs:
                assert ref in ctrl_ids, f"ISO chain {chain_id} -> invalid {ref}"


class TestISO27001Engine:
    def test_empty_scan(self) -> None:
        report = build_compliance_report("iso27001_2022", _make_empty_scan())
        assert report.total_controls == 93


# ── HIPAA Security Rule ──────────────────────────────────────────────


class TestHIPAALoading:
    def test_discoverable(self) -> None:
        ids = [fw["id"] for fw in list_frameworks()]
        assert "hipaa_security" in ids

    def test_loads(self) -> None:
        fw = load_framework("hipaa_security")
        assert fw["framework_id"] == "hipaa_security"
        assert "HIPAA" in fw["framework_name"]
        assert "164" in fw["version"]


class TestHIPAAStructure:
    def test_control_count(self) -> None:
        fw = load_framework("hipaa_security")
        assert len(fw["controls"]) >= 36, "HIPAA should have 36+ specs"

    def test_three_safeguard_categories(self) -> None:
        fw = load_framework("hipaa_security")
        sections = {ctrl["section"] for ctrl in fw["controls"].values()}
        assert any("Administrative" in s for s in sections)
        assert any("Physical" in s for s in sections)
        assert any("Technical" in s for s in sections)

    def test_level_required_or_addressable(self) -> None:
        fw = load_framework("hipaa_security")
        valid = {"Required", "Addressable", ""}
        for cid, ctrl in fw["controls"].items():
            assert ctrl["level"] in valid, f"HIPAA {cid}: invalid level '{ctrl['level']}'"

    def test_required_fields(self) -> None:
        fw = load_framework("hipaa_security")
        for cid, ctrl in fw["controls"].items():
            for field in REQUIRED_FIELDS:
                assert field in ctrl, f"HIPAA {cid} missing: {field}"

    def test_check_ids_valid(self) -> None:
        fw = load_framework("hipaa_security")
        for cid, ctrl in fw["controls"].items():
            for check_id in ctrl.get("checks", []):
                assert check_id in VALID_CHECKS, f"HIPAA {cid}: invalid check {check_id}"

    def test_technical_safeguards_have_checks(self) -> None:
        fw = load_framework("hipaa_security")
        tech_checks = set()
        for _cid, ctrl in fw["controls"].items():
            if "Technical" in ctrl.get("section", ""):
                tech_checks.update(ctrl.get("checks", []))
        assert len(tech_checks) >= 30, f"Technical safeguards only map {len(tech_checks)} checks"


class TestHIPAAChains:
    def test_all_chains_mapped(self) -> None:
        fw = load_framework("hipaa_security")
        assert set(fw["attack_chain_mappings"].keys()) == VALID_CHAINS

    def test_chain_refs_valid(self) -> None:
        fw = load_framework("hipaa_security")
        ctrl_ids = set(fw["controls"].keys())
        for chain_id, refs in fw["attack_chain_mappings"].items():
            for ref in refs:
                assert ref in ctrl_ids, f"HIPAA chain {chain_id} -> invalid {ref}"


class TestHIPAAEngine:
    def test_empty_scan(self) -> None:
        report = build_compliance_report("hipaa_security", _make_empty_scan())
        assert report.total_controls >= 36
        assert "HIPAA" in report.framework_name


# ── NIS2 Directive ───────────────────────────────────────────────────


class TestNIS2Loading:
    def test_discoverable(self) -> None:
        ids = [fw["id"] for fw in list_frameworks()]
        assert "nis2_directive" in ids

    def test_loads(self) -> None:
        fw = load_framework("nis2_directive")
        assert fw["framework_id"] == "nis2_directive"
        assert "NIS2" in fw["framework_name"]
        assert "2022/2555" in fw["version"]


class TestNIS2Structure:
    def test_control_count(self) -> None:
        fw = load_framework("nis2_directive")
        assert len(fw["controls"]) >= 40, "NIS2 should have 40+ measures"

    def test_article_21_coverage(self) -> None:
        fw = load_framework("nis2_directive")
        sections = {ctrl["section"] for ctrl in fw["controls"].values()}
        # Should cover Article 21(2)(a) through (j)
        assert any("21(2)" in s or "Risk" in s for s in sections)

    def test_required_fields(self) -> None:
        fw = load_framework("nis2_directive")
        for cid, ctrl in fw["controls"].items():
            for field in REQUIRED_FIELDS:
                assert field in ctrl, f"NIS2 {cid} missing: {field}"

    def test_check_ids_valid(self) -> None:
        fw = load_framework("nis2_directive")
        for cid, ctrl in fw["controls"].items():
            for check_id in ctrl.get("checks", []):
                assert check_id in VALID_CHECKS, f"NIS2 {cid}: invalid check {check_id}"

    def test_encryption_controls_mapped(self) -> None:
        fw = load_framework("nis2_directive")
        crypto_checks = set()
        for cid, ctrl in fw["controls"].items():
            if "crypt" in cid.lower() or "08" in cid:
                crypto_checks.update(ctrl.get("checks", []))
        assert len(crypto_checks) >= 5, f"Crypto controls only map {len(crypto_checks)} checks"


class TestNIS2Chains:
    def test_all_chains_mapped(self) -> None:
        fw = load_framework("nis2_directive")
        assert set(fw["attack_chain_mappings"].keys()) == VALID_CHAINS

    def test_chain_refs_valid(self) -> None:
        fw = load_framework("nis2_directive")
        ctrl_ids = set(fw["controls"].keys())
        for chain_id, refs in fw["attack_chain_mappings"].items():
            for ref in refs:
                assert ref in ctrl_ids, f"NIS2 chain {chain_id} -> invalid {ref}"


class TestNIS2Engine:
    def test_empty_scan(self) -> None:
        report = build_compliance_report("nis2_directive", _make_empty_scan())
        assert report.total_controls >= 40
        assert "NIS2" in report.framework_name


# ── Cross-framework tests ───────────────────────────────────────────


class TestAllFrameworksConsistency:
    @pytest.mark.parametrize("fw_id", ["bsi_c5_2020", "iso27001_2022", "hipaa_security", "nis2_directive"])
    def test_no_duplicate_checks_per_control(self, fw_id: str) -> None:
        fw = load_framework(fw_id)
        for cid, ctrl in fw["controls"].items():
            checks = ctrl.get("checks", [])
            assert len(checks) == len(set(checks)), f"{fw_id}/{cid} has duplicate checks"

    @pytest.mark.parametrize("fw_id", ["bsi_c5_2020", "iso27001_2022", "hipaa_security", "nis2_directive"])
    def test_no_empty_titles(self, fw_id: str) -> None:
        fw = load_framework(fw_id)
        for cid, ctrl in fw["controls"].items():
            assert ctrl["title"].strip(), f"{fw_id}/{cid} empty title"

    @pytest.mark.parametrize("fw_id", ["bsi_c5_2020", "iso27001_2022", "hipaa_security", "nis2_directive"])
    def test_no_empty_descriptions(self, fw_id: str) -> None:
        fw = load_framework(fw_id)
        for cid, ctrl in fw["controls"].items():
            assert ctrl["description"].strip(), f"{fw_id}/{cid} empty description"

    @pytest.mark.parametrize("fw_id", ["bsi_c5_2020", "iso27001_2022", "hipaa_security", "nis2_directive"])
    def test_evidence_templates_for_automated(self, fw_id: str) -> None:
        fw = load_framework(fw_id)
        for cid, ctrl in fw["controls"].items():
            if ctrl["checks"]:
                tpl = ctrl["evidence_template"]
                has_placeholders = "{pass_count}" in tpl or "requires manual" in tpl.lower()
                assert has_placeholders, f"{fw_id}/{cid} evidence template missing placeholders"

    @pytest.mark.parametrize("fw_id", ["bsi_c5_2020", "iso27001_2022", "hipaa_security", "nis2_directive"])
    def test_manual_controls_have_steps(self, fw_id: str) -> None:
        fw = load_framework(fw_id)
        for cid, ctrl in fw["controls"].items():
            if ctrl["assessment"] == "Manual":
                assert ctrl["manual_steps"].strip(), f"{fw_id}/{cid} Manual but no manual_steps"

    def test_six_frameworks_total(self) -> None:
        fws = list_frameworks()
        assert len(fws) == 6
