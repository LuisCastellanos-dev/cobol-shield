"""
Tests para tools/cobol_rules.py — R-02 UNSTRING_NO_OVERFLOW
Valida detección, no-detección, schema v1 y corpus.
"""

import json
import tempfile
from pathlib import Path

import pytest

from tools.cobol_rules import scan_file_r02, scan_path_r02
from tools.vtr_finding import (
    ASSET_UNRESOLVED,
    CLASS_HECHO,
    CONF_OBSERVED,
    CTX_OBSERVED,
    SEV_HIGH,
    TOOL_NAME,
    TOOL_VERSION,
    SCHEMA_VERSION,
)


CORPUS_OVERFLOW = Path("corpus/unstring-overflow")
CORPUS_CLEAN = Path("corpus/clean")


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_cob(tmp_path: Path, content: str, name: str = "test.cob") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ── R-02 — Detección ─────────────────────────────────────────────────────────

def test_detects_unstring_without_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       PROCEDURE DIVISION.
           UNSTRING WS-INPUT
               DELIMITED BY SPACE
               INTO WS-A WS-B.
""")
    findings = scan_file_r02(str(f))
    assert len(findings) == 1
    assert "UNSTRING" in findings[0].observation
    assert "ON OVERFLOW" in findings[0].observation


def test_detects_string_without_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       PROCEDURE DIVISION.
           STRING WS-A DELIMITED SPACE
                  INTO WS-RESULT.
""")
    findings = scan_file_r02(str(f))
    assert len(findings) == 1
    assert "STRING" in findings[0].observation


def test_detects_multiline_unstring_without_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       PROCEDURE DIVISION.
           UNSTRING WS-DATA
               DELIMITED BY ','
               INTO WS-PART1
                    WS-PART2
                    WS-PART3
               TALLYING IN WS-COUNT.
""")
    findings = scan_file_r02(str(f))
    assert len(findings) == 1


def test_detects_multiple_violations(tmp_path):
    f = make_cob(tmp_path, """\
       PROCEDURE DIVISION.
           UNSTRING WS-A DELIMITED BY SPACE INTO WS-B WS-C.
           STRING WS-X DELIMITED SPACE INTO WS-Y.
""")
    findings = scan_file_r02(str(f))
    assert len(findings) == 2


# ── R-02 — No detección ──────────────────────────────────────────────────────

def test_no_detection_unstring_with_on_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       PROCEDURE DIVISION.
           UNSTRING WS-INPUT
               DELIMITED BY SPACE
               INTO WS-A WS-B
               ON OVERFLOW
                   MOVE 'Y' TO WS-FLAG.
""")
    assert scan_file_r02(str(f)) == []


def test_no_detection_string_with_not_on_overflow(tmp_path):
    f = make_cob(tmp_path, """\
       PROCEDURE DIVISION.
           STRING WS-A DELIMITED SPACE
                  INTO WS-RESULT
               NOT ON OVERFLOW
                   MOVE 'Y' TO WS-OK.
""")
    assert scan_file_r02(str(f)) == []


def test_no_detection_clean_file(tmp_path):
    f = make_cob(tmp_path, """\
       IDENTIFICATION DIVISION.
       PROGRAM-ID. HELLO.
       PROCEDURE DIVISION.
           MOVE 'HELLO' TO WS-FIELD.
           STOP RUN.
""")
    assert scan_file_r02(str(f)) == []


def test_no_detection_non_cobol_extension(tmp_path):
    p = tmp_path / "test.py"
    p.write_text("UNSTRING WS-A INTO WS-B.\n", encoding="utf-8")
    findings = scan_path_r02(str(tmp_path))
    assert findings == []


# ── VTR Finding Schema v1 — campos requeridos ────────────────────────────────

def test_finding_has_schema_version(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].schema_version == SCHEMA_VERSION


def test_finding_has_source_tool(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].source_tool == TOOL_NAME


def test_finding_has_tool_version(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].tool_version == TOOL_VERSION


def test_finding_severity_is_high(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].severity == SEV_HIGH


def test_finding_classification_is_hecho(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].classification == CLASS_HECHO


def test_finding_confidence_is_observed(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].confidence == CONF_OBSERVED


def test_finding_context_status_is_observed(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].context_status == CTX_OBSERVED


# ── asset_id — Opción C: nunca null ──────────────────────────────────────────

def test_asset_id_never_null(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].asset_id is not None
    assert findings[0].asset_id != ""


def test_asset_id_uses_file_proxy_when_unresolved(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].asset_id.startswith("file:")


def test_asset_id_status_is_unresolved_without_inventory(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].asset_id_status == ASSET_UNRESOLVED


# ── Provenance — cadena de custodia ──────────────────────────────────────────

def test_provenance_has_file_sha256(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert len(findings[0].provenance.file_sha256) == 64


def test_provenance_has_line_number(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    assert findings[0].provenance.line == 1


def test_evidence_ref_format(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    ref = findings[0].evidence_ref
    assert "sha256:" in ref
    assert f.name in ref


def test_finding_id_is_uuid(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    import uuid
    uuid.UUID(findings[0].finding_id)  # lanza si no es UUID válido


# ── JSON serializable ─────────────────────────────────────────────────────────

def test_finding_serializes_to_valid_json(tmp_path):
    f = make_cob(tmp_path, "           UNSTRING WS-A INTO WS-B.\n")
    findings = scan_file_r02(str(f))
    json_str = findings[0].to_json()
    parsed = json.loads(json_str)
    assert parsed["schema_version"] == SCHEMA_VERSION
    assert parsed["asset_id_status"] == ASSET_UNRESOLVED
    assert parsed["classification"] == CLASS_HECHO


# ── Corpus — validación de archivos reales ────────────────────────────────────

@pytest.mark.skipif(
    not CORPUS_OVERFLOW.exists(),
    reason="corpus/unstring-overflow no encontrado"
)
def test_corpus_overflow_payroll_detected():
    findings = scan_file_r02(str(CORPUS_OVERFLOW / "PAYROLL.cob"))
    assert len(findings) >= 1


@pytest.mark.skipif(
    not CORPUS_OVERFLOW.exists(),
    reason="corpus/unstring-overflow no encontrado"
)
def test_corpus_overflow_buildname_detected():
    findings = scan_file_r02(str(CORPUS_OVERFLOW / "BUILDNAME.cob"))
    assert len(findings) >= 1


@pytest.mark.skipif(
    not CORPUS_OVERFLOW.exists(),
    reason="corpus/unstring-overflow no encontrado"
)
def test_corpus_overflow_multiline_detected():
    findings = scan_file_r02(str(CORPUS_OVERFLOW / "MULTILINE.cob"))
    assert len(findings) >= 1


@pytest.mark.skipif(
    not CORPUS_CLEAN.exists(),
    reason="corpus/clean no encontrado"
)
def test_corpus_clean_safe_unstring_not_detected():
    findings = scan_file_r02(str(CORPUS_CLEAN / "SAFE-UNSTRING.cob"))
    assert findings == []


@pytest.mark.skipif(
    not CORPUS_CLEAN.exists(),
    reason="corpus/clean no encontrado"
)
def test_corpus_clean_safe_string_not_detected():
    findings = scan_file_r02(str(CORPUS_CLEAN / "SAFE-STRING.cob"))
    assert findings == []
