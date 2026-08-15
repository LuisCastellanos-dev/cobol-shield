"""
Tests para tools/check-invisibles.py
Cubre todos los rangos Unicode peligrosos declarados en README.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

CHECKER = Path(__file__).parent.parent / "tools" / "check-invisibles.py"


def run_checker(path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CHECKER), path],
        capture_output=True,
        text=True,
    )


def make_cob(tmp_path: Path, content: str, name: str = "test.cob") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ── Exit codes ───────────────────────────────────────────────────────────────

def test_exits_0_on_clean_file(tmp_path):
    f = make_cob(tmp_path, "IDENTIFICATION DIVISION.\nPROGRAM-ID. HELLO.\n")
    result = run_checker(str(f))
    assert result.returncode == 0


def test_exits_1_on_detection(tmp_path):
    # U+200B Zero-Width Space
    f = make_cob(tmp_path, "MOVE \u200B TO WS-FIELD.\n")
    result = run_checker(str(f))
    assert result.returncode == 1


def test_exits_0_on_empty_dir(tmp_path):
    result = run_checker(str(tmp_path))
    assert result.returncode == 0


# ── Rangos peligrosos — cada uno debe disparar exit 1 ────────────────────────

def test_detects_zero_width_space(tmp_path):
    f = make_cob(tmp_path, "DATA\u200BDIVISION.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_zero_width_non_joiner(tmp_path):
    f = make_cob(tmp_path, "DATA\u200CDIVISION.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_zero_width_joiner(tmp_path):
    f = make_cob(tmp_path, "DATA\u200DDIVISION.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_bidi_override_202e(tmp_path):
    """U+202E — Trojan Source CVE-2021-42574"""
    f = make_cob(tmp_path, "MOVE \u202E TO WS-FIELD.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_bidi_override_202a(tmp_path):
    f = make_cob(tmp_path, "MOVE \u202A TO WS-FIELD.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_bidi_isolate_2066(tmp_path):
    f = make_cob(tmp_path, "MOVE \u2066 TO WS-FIELD.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_bidi_isolate_2069(tmp_path):
    f = make_cob(tmp_path, "MOVE \u2069 TO WS-FIELD.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_variation_selector_fe00(tmp_path):
    """U+FE00 — Glassworm vector"""
    f = make_cob(tmp_path, "MOVE A\uFE00 TO B.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_variation_selector_fe0f(tmp_path):
    f = make_cob(tmp_path, "MOVE A\uFE0F TO B.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_bom_feff(tmp_path):
    """U+FEFF — BOM silencioso"""
    f = make_cob(tmp_path, "\uFEFF IDENTIFICATION DIVISION.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_c0_control(tmp_path):
    """U+0001 — C0 control no permitido"""
    f = make_cob(tmp_path, "MOVE \x01 TO WS.\n")
    assert run_checker(str(f)).returncode == 1


def test_detects_private_use_area(tmp_path):
    """U+E000 — Private Use Area"""
    f = make_cob(tmp_path, "MOVE \uE000 TO WS.\n")
    assert run_checker(str(f)).returncode == 1


# ── Caracteres permitidos — NO deben disparar ────────────────────────────────

def test_allows_tab(tmp_path):
    f = make_cob(tmp_path, "MOVE\tA\tTO\tB.\n")
    assert run_checker(str(f)).returncode == 0


def test_allows_lf(tmp_path):
    f = make_cob(tmp_path, "LINE1\nLINE2\n")
    assert run_checker(str(f)).returncode == 0


def test_allows_cr_lf(tmp_path):
    p = tmp_path / "test.cob"
    p.write_bytes(b"LINE1\r\nLINE2\r\n")
    assert run_checker(str(p)).returncode == 0


def test_allows_standard_ascii(tmp_path):
    content = (
        "IDENTIFICATION DIVISION.\n"
        "PROGRAM-ID. SHIELD.\n"
        "DATA DIVISION.\n"
        "WORKING-STORAGE SECTION.\n"
        "01 WS-FIELD PIC X(10).\n"
    )
    f = make_cob(tmp_path, content)
    assert run_checker(str(f)).returncode == 0


# ── Exclusión de test_utf8 ───────────────────────────────────────────────────

def test_skips_file_named_test_utf8(tmp_path):
    """Archivos con test_utf8 en el nombre son excluidos explícitamente."""
    f = tmp_path / "test_utf8_fixtures.cob"
    f.write_text("MOVE \u200B TO WS.\n", encoding="utf-8")
    result = run_checker(str(tmp_path))
    assert result.returncode == 0


# ── Extensiones de archivo ───────────────────────────────────────────────────

def test_scans_cbl_extension(tmp_path):
    p = tmp_path / "prog.cbl"
    p.write_text("MOVE \u200B TO WS.\n", encoding="utf-8")
    assert run_checker(str(tmp_path)).returncode == 1


def test_scans_py_extension(tmp_path):
    p = tmp_path / "script.py"
    p.write_text("x = '\u202E'\n", encoding="utf-8")
    assert run_checker(str(tmp_path)).returncode == 1


def test_ignores_unknown_extension(tmp_path):
    p = tmp_path / "data.xyz"
    p.write_text("MOVE \u200B TO WS.\n", encoding="utf-8")
    assert run_checker(str(tmp_path)).returncode == 0


# ── Output ───────────────────────────────────────────────────────────────────

def test_output_mentions_cve_on_detection(tmp_path):
    f = make_cob(tmp_path, "MOVE \u202E TO WS.\n")
    result = run_checker(str(f))
    assert "CVE-2021-42574" in result.stdout


def test_output_ok_on_clean(tmp_path):
    f = make_cob(tmp_path, "IDENTIFICATION DIVISION.\n")
    result = run_checker(str(f))
    assert "[OK]" in result.stdout


def test_output_fail_on_detection(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    result = run_checker(str(f))
    assert "[FAIL]" in result.stdout
