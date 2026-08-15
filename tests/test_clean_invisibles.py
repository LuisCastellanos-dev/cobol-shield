"""
Tests para tools/clean-invisibles.py
Cubre: dry-run, backup, audit log, limpieza de rangos peligrosos.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

CLEANER = Path(__file__).parent.parent / "tools" / "clean-invisibles.py"


def run_cleaner(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLEANER)] + args,
        capture_output=True,
        text=True,
    )


def make_cob(tmp_path: Path, content: str, name: str = "test.cob") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ── dry-run — no modifica archivos ───────────────────────────────────────────

def test_dry_run_does_not_modify_file(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    original = f.read_text(encoding="utf-8")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--dry-run", "--report", str(log)])
    assert f.read_text(encoding="utf-8") == original


def test_dry_run_does_not_create_backup(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--dry-run", "--report", str(log)])
    backup = f.with_suffix(".cob.bak")
    assert not backup.exists()


def test_dry_run_output_mentions_dry_run(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    result = run_cleaner([str(f), "--dry-run", "--report", str(log)])
    assert "DRY-RUN" in result.stdout


# ── Limpieza real — modifica y crea backup ───────────────────────────────────

def test_clean_removes_zero_width_space(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    cleaned = f.read_text(encoding="utf-8")
    assert "\u200B" not in cleaned


def test_clean_creates_backup(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    backup = tmp_path / "test.cob.bak"
    assert backup.exists()


def test_backup_contains_original_content(tmp_path):
    original = "MOVE \u200B TO WS.\n"
    f = make_cob(tmp_path, original)
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    backup = tmp_path / "test.cob.bak"
    assert backup.read_text(encoding="utf-8") == original


def test_clean_removes_bom(tmp_path):
    f = make_cob(tmp_path, "\uFEFF IDENTIFICATION DIVISION.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    assert "\uFEFF" not in f.read_text(encoding="utf-8")


def test_clean_removes_variation_selector(tmp_path):
    f = make_cob(tmp_path, "MOVE A\uFE00 TO B.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    assert "\uFE00" not in f.read_text(encoding="utf-8")


def test_clean_removes_bidi_critical(tmp_path):
    """Bidi override U+202E — Trojan Source — debe ser removido."""
    f = make_cob(tmp_path, "MOVE \u202E TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    assert "\u202E" not in f.read_text(encoding="utf-8")


def test_clean_preserves_clean_content(tmp_path):
    content = "IDENTIFICATION DIVISION.\nPROGRAM-ID. SHIELD.\n"
    f = make_cob(tmp_path, content)
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    assert f.read_text(encoding="utf-8") == content


def test_clean_does_not_create_backup_for_clean_file(tmp_path):
    f = make_cob(tmp_path, "IDENTIFICATION DIVISION.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    backup = tmp_path / "test.cob.bak"
    assert not backup.exists()


# ── Audit log ────────────────────────────────────────────────────────────────

def test_audit_log_created(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    assert log.exists()


def test_audit_log_mentions_cve(tmp_path):
    f = make_cob(tmp_path, "MOVE \u202E TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    content = log.read_text(encoding="utf-8")
    assert "CVE-2021-42574" in content


def test_audit_log_mentions_trojan_source_for_bidi(tmp_path):
    f = make_cob(tmp_path, "MOVE \u202E TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    content = log.read_text(encoding="utf-8")
    assert "Trojan Source" in content


def test_audit_log_includes_hex_sample(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    content = log.read_text(encoding="utf-8")
    assert "Hex sample" in content


def test_audit_log_empty_for_clean_file(tmp_path):
    f = make_cob(tmp_path, "IDENTIFICATION DIVISION.\n")
    log = tmp_path / "audit.log"
    run_cleaner([str(f), "--report", str(log)])
    content = log.read_text(encoding="utf-8")
    # Log existe pero no tiene entradas de archivos
    assert str(f.name) not in content


# ── Output ───────────────────────────────────────────────────────────────────

def test_output_mentions_cleaned(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    result = run_cleaner([str(f), "--report", str(log)])
    assert "CLEANED" in result.stdout


def test_output_done_summary(tmp_path):
    f = make_cob(tmp_path, "MOVE \u200B TO WS.\n")
    log = tmp_path / "audit.log"
    result = run_cleaner([str(f), "--report", str(log)])
    assert "Done." in result.stdout
