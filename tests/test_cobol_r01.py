"""
Tests para R-01 UNINITIALIZED_WS en tools/cobol_rules.py
Cubre detección, mitigaciones FP, schema v1 y corpus.
"""

import json
from pathlib import Path

import pytest

from tools.cobol_rules import scan_file_r01, scan_path_r01
from tools.vtr_finding import (
    ASSET_UNRESOLVED,
    CLASS_HECHO,
    CONF_OBSERVED,
    SEV_HIGH,
    TOOL_NAME,
    SCHEMA_VERSION,
)

CORPUS_UNINIT = Path("corpus/uninitialized-ws")


def make_cob(tmp_path: Path, content: str, name: str = "test.cob") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ── R-01 — Detección ─────────────────────────────────────────────────────────

def test_detects_pic_without_value(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert len(findings) >= 1
    assert "WS-AMOUNT" in findings[0].observation


def test_detects_multiple_uninitialized(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       01 WS-COUNTER     PIC 9(4) COMP.
       01 WS-NAME        PIC X(30).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert len(findings) == 3


def test_detects_pic77(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       77 WS-TEMP        PIC X(10).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert len(findings) == 1


# ── Mitigación 1 — Solo WORKING-STORAGE ──────────────────────────────────────

def test_ignores_linkage_section(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       LINKAGE SECTION.
       01 LS-INPUT       PIC X(50).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


def test_ignores_file_section(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       FILE SECTION.
       01 FS-RECORD      PIC X(80).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


# ── Mitigación 2 — VALUE clause ───────────────────────────────────────────────

def test_no_detection_with_value_zeros(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8) VALUE ZEROS.
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


def test_no_detection_with_value_spaces(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-NAME        PIC X(30) VALUE SPACES.
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


def test_no_detection_with_value_literal(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-FLAG        PIC X VALUE 'N'.
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


def test_no_detection_with_value_numeric(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-COUNTER     PIC 9(4) VALUE 0.
       PROCEDURE DIVISION.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


# ── Mitigación 2 — INITIALIZE / MOVE en PROCEDURE ────────────────────────────

def test_no_detection_with_initialize(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           INITIALIZE WS-AMOUNT.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


def test_no_detection_with_move(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-TOTAL       PIC 9(8).
       PROCEDURE DIVISION.
           MOVE ZEROS TO WS-TOTAL.
           STOP RUN.
""")
    assert scan_file_r01(str(f)) == []


def test_no_detection_with_move_in_perform(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           PERFORM INIT-RTN.
           STOP RUN.
       INIT-RTN.
           MOVE ZEROS TO WS-AMOUNT.
""")
    assert scan_file_r01(str(f)) == []


# ── Mitigación 3 — COPY nearby → INFERRED ────────────────────────────────────

def test_confidence_inferred_near_copy(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       COPY 'WS-DEFS'.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert len(findings) >= 1
    assert findings[0].confidence == "INFERRED"


def test_confidence_observed_without_copy(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert findings[0].confidence == CONF_OBSERVED


# ── VTR Finding Schema v1 ─────────────────────────────────────────────────────

def test_finding_rule_id_is_r01(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert findings[0].rule_id == "R-01"


def test_finding_severity_is_high(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert findings[0].severity == SEV_HIGH


def test_finding_classification_is_hecho(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert findings[0].classification == CLASS_HECHO


def test_finding_asset_id_never_null(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert findings[0].asset_id is not None
    assert findings[0].asset_id.startswith("file:")


def test_finding_asset_id_status_unresolved(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert findings[0].asset_id_status == ASSET_UNRESOLVED


def test_finding_observation_mentions_static_analysis_limit(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    assert "static analysis" in findings[0].observation


def test_finding_serializes_to_valid_json(tmp_path):
    f = make_cob(tmp_path, """\
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-AMOUNT      PIC 9(8).
       PROCEDURE DIVISION.
           STOP RUN.
""")
    findings = scan_file_r01(str(f))
    parsed = json.loads(findings[0].to_json())
    assert parsed["rule_id"] == "R-01"
    assert parsed["asset_id_status"] == ASSET_UNRESOLVED


# ── Corpus ────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    not CORPUS_UNINIT.exists(),
    reason="corpus/uninitialized-ws no encontrado"
)
def test_corpus_batch_payroll_detected():
    findings = scan_file_r01(str(CORPUS_UNINIT / "BATCH-PAYROLL.cob"))
    assert len(findings) >= 1


@pytest.mark.skipif(
    not CORPUS_UNINIT.exists(),
    reason="corpus/uninitialized-ws no encontrado"
)
def test_corpus_safe_value_not_detected():
    findings = scan_file_r01(str(CORPUS_UNINIT / "SAFE-VALUE.cob"))
    assert findings == []


@pytest.mark.skipif(
    not CORPUS_UNINIT.exists(),
    reason="corpus/uninitialized-ws no encontrado"
)
def test_corpus_safe_initialize_not_detected():
    findings = scan_file_r01(str(CORPUS_UNINIT / "SAFE-INITIALIZE.cob"))
    assert findings == []


@pytest.mark.skipif(
    not CORPUS_UNINIT.exists(),
    reason="corpus/uninitialized-ws no encontrado"
)
def test_corpus_safe_move_not_detected():
    findings = scan_file_r01(str(CORPUS_UNINIT / "SAFE-MOVE.cob"))
    assert findings == []
