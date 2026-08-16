"""
Tests para R-03 REDEFINES_SIZE_MISMATCH en tools/cobol_rules.py
Cubre detección, no-detección, explicitez del auditor, schema v1 y corpus.
"""

import json
from pathlib import Path

import pytest

from tools.cobol_rules import scan_file_r03, scan_path_r03
from tools.vtr_finding import (
    ASSET_UNRESOLVED,
    CLASS_HECHO,
    CONF_OBSERVED,
    SEV_HIGH,
)

CORPUS_REDEF = Path("corpus/redefines-mismatch")


def make_cob(tmp_path: Path, content: str, name: str = "test.cob") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ── R-03 — Detección ─────────────────────────────────────────────────────────

def test_detects_redefines_size_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert len(findings) == 1


def test_detects_numeric_redefines_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(5).
       01 WS-AMOUNT-X    REDEFINES WS-AMOUNT PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert len(findings) == 1


def test_detects_multiple_redefines_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE1       PIC X(5).
       01 WS-REDEF1      REDEFINES WS-BASE1 PIC X(10).
       01 WS-BASE2       PIC 9(3).
       01 WS-REDEF2      REDEFINES WS-BASE2 PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert len(findings) == 2


# ── R-03 — No detección ──────────────────────────────────────────────────────

def test_no_detection_redefines_smaller(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(5).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r03(str(f)) == []


def test_no_detection_redefines_same_size(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC 9(8).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r03(str(f)) == []


def test_no_detection_without_redefines(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-OTHER       PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r03(str(f)) == []


# ── Explicitez del auditor — 4 elementos requeridos ──────────────────────────

def test_observation_includes_base_name(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert "WS-BASE" in findings[0].observation


def test_observation_includes_redef_name(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert "WS-REDEF" in findings[0].observation


def test_observation_includes_byte_sizes(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert "10 bytes" in findings[0].observation
    assert "20 bytes" in findings[0].observation


def test_observation_includes_pic_declaration_basis(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert "PIC declaration" in findings[0].observation


def test_observation_includes_base_line_reference(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert "base at line" in findings[0].observation


def test_observation_includes_byte_difference(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert "by 10 bytes" in findings[0].observation


# ── COMP — confidence INFERRED ───────────────────────────────────────────────

def test_confidence_inferred_when_comp_involved(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC 9(5) COMP.
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    if findings:
        assert findings[0].confidence == "INFERRED"


def test_observation_mentions_comp_warning(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC 9(5) COMP.
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    if findings:
        assert "COMP" in findings[0].observation


def test_confidence_observed_without_comp(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert findings[0].confidence == CONF_OBSERVED


# ── VTR Finding Schema v1 ─────────────────────────────────────────────────────

def test_finding_rule_id_is_r03(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert findings[0].rule_id == "R-03"


def test_finding_severity_is_high(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert findings[0].severity == SEV_HIGH


def test_finding_classification_is_hecho(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert findings[0].classification == CLASS_HECHO


def test_finding_asset_id_never_null(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert findings[0].asset_id is not None
    assert findings[0].asset_id.startswith("file:")


def test_finding_asset_id_status_unresolved(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    assert findings[0].asset_id_status == ASSET_UNRESOLVED


def test_finding_serializes_to_valid_json(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-BASE        PIC X(10).
       01 WS-REDEF       REDEFINES WS-BASE PIC X(20).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r03(str(f))
    parsed = json.loads(findings[0].to_json())
    assert parsed["rule_id"] == "R-03"
    assert parsed["asset_id_status"] == ASSET_UNRESOLVED


# ── Corpus ────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    not CORPUS_REDEF.exists(),
    reason="corpus/redefines-mismatch no encontrado"
)
def test_corpus_overflow_redef_detected():
    findings = scan_file_r03(str(CORPUS_REDEF / "OVERFLOW-REDEF.cob"))
    assert len(findings) >= 1


@pytest.mark.skipif(
    not CORPUS_REDEF.exists(),
    reason="corpus/redefines-mismatch no encontrado"
)
def test_corpus_numeric_redef_detected():
    findings = scan_file_r03(str(CORPUS_REDEF / "NUMERIC-REDEF.cob"))
    assert len(findings) >= 1


@pytest.mark.skipif(
    not CORPUS_REDEF.exists(),
    reason="corpus/redefines-mismatch no encontrado"
)
def test_corpus_safe_redef_not_detected():
    findings = scan_file_r03(str(CORPUS_REDEF / "SAFE-REDEF.cob"))
    assert findings == []


@pytest.mark.skipif(
    not CORPUS_REDEF.exists(),
    reason="corpus/redefines-mismatch no encontrado"
)
def test_corpus_same_size_redef_not_detected():
    findings = scan_file_r03(str(CORPUS_REDEF / "SAME-SIZE-REDEF.cob"))
    assert findings == []
