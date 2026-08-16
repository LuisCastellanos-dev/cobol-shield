"""
Tests para R-04 FORMAT_BOUNDARY_ANALYSIS — cobol-shield

Fase 1: Format Boundary Analysis.
Produce observaciones de condición posicional en COBOL fixed-format.
No produce findings de vulnerabilidad — severity=info, classification=PROYECCION.

Tres condiciones cubiertas:
  R-04a COL73_NONEMPTY  — contenido no-espacio en identification area (cols 73-80)
  R-04b COL7_VERB       — verbo COBOL ejecutable en línea comentada (col7 = * / D)
  R-04c SOURCE_BOUNDARY — contenido más allá de col 80 (caso extremo)

Limitaciones documentadas en cada test donde aplican.
"""

import os
import tempfile

import pytest

from tools.cobol_rules import scan_file_r04
from tools.vtr_finding import CLASS_PROYECCION, SEV_INFO

# ── helpers ───────────────────────────────────────────────────────────────────

def fixed_line(seq: str, indicator: str, code: str, id_area: str = '        ') -> str:
    """Construye línea COBOL fixed-format de 80 chars exactos."""
    line = seq[:6].ljust(6) + indicator[0] + code[:65].ljust(65) + id_area[:8].ljust(8)
    assert len(line) == 80, f'fixed_line produjo {len(line)} chars'
    return line


def write_cbl(lines: list[str]) -> str:
    """Escribe líneas en archivo temporal .cbl, retorna path."""
    fd, path = tempfile.mkstemp(suffix='.cbl')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    return path


# ── corpus paths ─────────────────────────────────────────────────────────────

CORPUS_DIR = os.path.join(os.path.dirname(__file__), '..', 'corpus', 'fixed-format')

def corpus(name: str) -> str:
    return os.path.join(CORPUS_DIR, name)


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 1 — Corpus estático
# ══════════════════════════════════════════════════════════════════════════════

class TestR04Corpus:
    """Tests contra el corpus en disco — fuente de verdad fija."""

    def test_clean_zero_observations(self):
        """clean.cbl no tiene contenido en identification area ni verbos en comentarios."""
        findings = scan_file_r04(corpus('clean.cbl'))
        assert findings == []

    def test_col73_nonempty_one_finding(self):
        """col73-nonempty.cbl tiene 'SMITH01' en identification area de línea 5."""
        findings = scan_file_r04(corpus('col73-nonempty.cbl'))
        assert len(findings) == 1
        assert 'COL73_NONEMPTY' in findings[0].observation
        assert 'SMITH01' in findings[0].observation

    def test_col7_verb_one_finding(self):
        """col7-verb.cbl tiene MOVE en línea comentada con col7='*'."""
        findings = scan_file_r04(corpus('col7-verb.cbl'))
        assert len(findings) == 1
        assert 'COL7_VERB' in findings[0].observation
        assert 'MOVE' in findings[0].observation

    def test_boundary_exceeded_one_finding(self):
        """boundary-exceeded.cbl tiene 'PROG0042' en identification area."""
        findings = scan_file_r04(corpus('boundary-exceeded.cbl'))
        assert len(findings) == 1
        assert 'COL73_NONEMPTY' in findings[0].observation
        assert 'PROG0042' in findings[0].observation


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 2 — Clasificación y severidad
# ══════════════════════════════════════════════════════════════════════════════

class TestR04Classification:
    """R-04 produce observaciones, no findings de vulnerabilidad."""

    def test_severity_is_info(self):
        """Cualquier finding R-04 debe tener severity=info."""
        findings = scan_file_r04(corpus('col73-nonempty.cbl'))
        assert all(f.severity == SEV_INFO for f in findings)

    def test_classification_is_proyeccion(self):
        """Clasificación debe ser PROYECCION — impacto no demostrado sin PoC."""
        findings = scan_file_r04(corpus('col73-nonempty.cbl'))
        assert all(f.classification == CLASS_PROYECCION for f in findings)

    def test_rule_id_r04(self):
        findings = scan_file_r04(corpus('col7-verb.cbl'))
        assert all(f.rule_id == 'R-04' for f in findings)

    def test_observation_not_vulnerability(self):
        """El texto del finding debe dejar claro que no es finding de vulnerabilidad."""
        findings = scan_file_r04(corpus('col73-nonempty.cbl'))
        assert any('Not a vulnerability finding' in f.observation for f in findings)


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 3 — COL73_NONEMPTY
# ══════════════════════════════════════════════════════════════════════════════

class TestR04Col73:
    """Detección de contenido no-espacio en identification area (cols 73-80)."""

    def test_spaces_only_no_finding(self):
        """Identificación area con solo espacios — sin observación."""
        lines = [
            fixed_line('000100', ' ', 'IDENTIFICATION DIVISION.'),
            fixed_line('000200', ' ', 'PROGRAM-ID. TEST.'),
            fixed_line('000300', ' ', 'PROCEDURE DIVISION.'),
            fixed_line('000400', ' ', '    STOP RUN.'),
        ]
        path = write_cbl(lines)
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_programmer_id_triggers(self):
        """ID de programador en cols 73-80 genera observación COL73_NONEMPTY."""
        lines = [
            fixed_line('000100', ' ', 'IDENTIFICATION DIVISION.', 'JSMITH01'),
            fixed_line('000200', ' ', 'PROGRAM-ID. TEST.'),
            fixed_line('000300', ' ', 'PROCEDURE DIVISION.'),
            fixed_line('000400', ' ', '    STOP RUN.'),
        ]
        path = write_cbl(lines)
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
            assert 'COL73_NONEMPTY' in findings[0].observation
            assert 'JSMITH01' in findings[0].observation
        finally:
            os.unlink(path)

    def test_multiple_lines_with_id_area(self):
        """Varias líneas con ID area generan una observación por línea."""
        lines = [
            fixed_line('000100', ' ', 'IDENTIFICATION DIVISION.', 'PROG0001'),
            fixed_line('000200', ' ', 'PROGRAM-ID. TEST.',         'PROG0002'),
            fixed_line('000300', ' ', 'PROCEDURE DIVISION.'),
            fixed_line('000400', ' ', '    STOP RUN.'),
        ]
        path = write_cbl(lines)
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 2
        finally:
            os.unlink(path)

    def test_line_shorter_than_73_no_finding(self):
        """Línea más corta que 73 chars — sin observación R-04a."""
        short_line = '000100 IDENTIFICATION DIVISION.'  # < 73 chars
        path = write_cbl([short_line])
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_tab_in_id_area_triggers(self):
        """Tab en identification area es contenido no-espacio — genera observación."""
        line = fixed_line('000100', ' ', 'IDENTIFICATION DIVISION.')
        # Reemplazar último char de id_area con tab
        line_with_tab = line[:79] + '\t'
        path = write_cbl([line_with_tab])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
            assert 'COL73_NONEMPTY' in findings[0].observation
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 4 — COL7_VERB
# ══════════════════════════════════════════════════════════════════════════════

class TestR04Col7Verb:
    """Detección de verbos COBOL ejecutables en líneas comentadas."""

    def _make_commented(self, verb_content: str) -> str:
        return fixed_line('000100', '*', verb_content)

    def test_move_in_comment_triggers(self):
        path = write_cbl([self._make_commented('MOVE 999 TO WS-X')])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
            assert 'COL7_VERB' in findings[0].observation
        finally:
            os.unlink(path)

    def test_perform_in_comment_triggers(self):
        path = write_cbl([self._make_commented('PERFORM VALIDATE-ROUTINE')])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
        finally:
            os.unlink(path)

    def test_exec_in_comment_triggers(self):
        path = write_cbl([self._make_commented('EXEC CICS LINK PROGRAM BACKDOOR')])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
        finally:
            os.unlink(path)

    def test_call_in_comment_triggers(self):
        path = write_cbl([self._make_commented("CALL 'SUBPROG' USING WS-DATA")])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
        finally:
            os.unlink(path)

    def test_plain_text_comment_no_finding(self):
        """Comentario de texto sin verbos no genera observación."""
        path = write_cbl([self._make_commented('Actualizado por JSmith 2024-01-15')])
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_date_comment_no_finding(self):
        """Comentario con fecha — no genera observación."""
        path = write_cbl([self._make_commented('2024-08-15 Fix saldo negativo')])
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_slash_indicator_with_verb_triggers(self):
        """Col7='/' (page eject) con verbo también es condición observable."""
        line = fixed_line('000100', '/', 'CALL BYPASS-AUDIT USING WS-KEY')
        path = write_cbl([line])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
            assert 'COL7_VERB' in findings[0].observation
        finally:
            os.unlink(path)

    def test_d_indicator_with_verb_triggers(self):
        """Col7='D' (debugging line) con verbo es condición observable."""
        line = fixed_line('000100', 'D', 'PERFORM BYPASS-VALIDATION')
        path = write_cbl([line])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
        finally:
            os.unlink(path)

    def test_normal_code_line_no_finding(self):
        """Línea de código normal (col7=' ') con MOVE — no es observación R-04b."""
        line = fixed_line('000100', ' ', 'MOVE 1000 TO WS-BALANCE')
        path = write_cbl([line])
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_case_insensitive_verb(self):
        """Detección de verbo es case-insensitive."""
        path = write_cbl([self._make_commented('move 0 to ws-balance')])
        try:
            findings = scan_file_r04(path)
            assert len(findings) == 1
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 5 — FREE format excluido
# ══════════════════════════════════════════════════════════════════════════════

class TestR04FreeFormat:
    """Archivos con >>SOURCE FORMAT FREE no deben ser analizados."""

    def test_free_format_directive_excludes_file(self):
        """>>SOURCE FORMAT FREE al inicio del archivo — R-04 retorna vacío."""
        lines = [
            '      >>SOURCE FORMAT FREE',
            'IDENTIFICATION DIVISION.',
            'PROGRAM-ID. FREE-TEST.',
            '* MOVE 999 TO WS-X',   # en free-format, * en col 1 no es col7
            'PROCEDURE DIVISION.',
            '    STOP RUN.',
        ]
        path = write_cbl(lines)
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_free_format_is_directive_variant(self):
        """>>SOURCE FORMAT IS FREE también excluye."""
        lines = [
            '      >>SOURCE FORMAT IS FREE',
            'IDENTIFICATION DIVISION.',
            'PROGRAM-ID. FREE-TEST.',
        ]
        path = write_cbl(lines)
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 6 — SOURCE_BOUNDARY (>80 chars)
# ══════════════════════════════════════════════════════════════════════════════

class TestR04SourceBoundary:
    """Detección de contenido más allá de col 80."""

    def test_line_beyond_80_with_content_triggers(self):
        """Línea de 81+ chars con contenido no-espacio después de col 80."""
        line = fixed_line('000100', ' ', 'IDENTIFICATION DIVISION.') + 'X'
        assert len(line) == 81
        path = write_cbl([line])
        try:
            findings = scan_file_r04(path)
            # Puede disparar COL73_NONEMPTY (por id_area='       X') o SOURCE_BOUNDARY
            assert len(findings) >= 1
        finally:
            os.unlink(path)

    def test_line_exactly_80_no_boundary_finding(self):
        """Línea de exactamente 80 chars — sin SOURCE_BOUNDARY."""
        line = fixed_line('000100', ' ', 'IDENTIFICATION DIVISION.')
        assert len(line) == 80
        path = write_cbl([line])
        try:
            findings = scan_file_r04(path)
            boundary = [f for f in findings if 'SOURCE_BOUNDARY' in f.observation]
            assert boundary == []
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 7 — Provenance y schema
# ══════════════════════════════════════════════════════════════════════════════

class TestR04Schema:
    """Findings R-04 cumplen el VTR Finding Schema v1."""

    def test_finding_has_evidence_ref(self):
        findings = scan_file_r04(corpus('col73-nonempty.cbl'))
        assert all(f.evidence_ref for f in findings)

    def test_finding_has_sha256_in_evidence_ref(self):
        findings = scan_file_r04(corpus('col73-nonempty.cbl'))
        assert all('sha256' in f.evidence_ref for f in findings)

    def test_finding_has_provenance(self):
        findings = scan_file_r04(corpus('col7-verb.cbl'))
        assert all(f.provenance is not None for f in findings)

    def test_finding_line_number_correct(self):
        """COL7_VERB debe apuntar a la línea 6 del corpus col7-verb.cbl."""
        findings = scan_file_r04(corpus('col7-verb.cbl'))
        verb_findings = [f for f in findings if 'COL7_VERB' in f.observation]
        assert len(verb_findings) == 1
        assert verb_findings[0].provenance.line == 6

    def test_finding_id_unique(self):
        """Cada finding debe tener finding_id único."""
        lines_a = [
            fixed_line('000100', '*', 'MOVE 1 TO X', 'PROG0001'),
            fixed_line('000200', '*', 'PERFORM Y',   'PROG0002'),
        ]
        path = write_cbl(lines_a)
        try:
            findings = scan_file_r04(path)
            ids = [f.finding_id for f in findings]
            assert len(ids) == len(set(ids))
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Grupo 8 — Edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestR04EdgeCases:
    """Casos límite que el detector debe manejar sin error."""

    def test_empty_file(self):
        path = write_cbl([])
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_single_empty_line(self):
        path = write_cbl([''])
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_empty(self):
        assert scan_file_r04('/tmp/no-existe-cobol-shield.cbl') == []

    def test_file_with_only_comments(self):
        """Archivo con solo comentarios de texto — sin observaciones."""
        lines = [
            fixed_line('000100', '*', 'Programa de nomina v2.1'),
            fixed_line('000200', '*', 'Autor: Juan Perez'),
            fixed_line('000300', '*', 'Fecha: 2024-01-15'),
        ]
        path = write_cbl(lines)
        try:
            assert scan_file_r04(path) == []
        finally:
            os.unlink(path)

    def test_mixed_conditions_multiple_findings(self):
        """Archivo con COL73_NONEMPTY y COL7_VERB en distintas líneas."""
        lines = [
            fixed_line('000100', ' ', 'IDENTIFICATION DIVISION.', 'PROG0001'),
            fixed_line('000200', '*', 'MOVE 999 TO WS-BAD'),
            fixed_line('000300', ' ', 'PROCEDURE DIVISION.'),
            fixed_line('000400', ' ', '    STOP RUN.'),
        ]
        path = write_cbl(lines)
        try:
            findings = scan_file_r04(path)
            conditions = {f.observation.split(']')[0].split('[R-04 ')[1] for f in findings}
            assert 'COL73_NONEMPTY' in conditions
            assert 'COL7_VERB' in conditions
        finally:
            os.unlink(path)
