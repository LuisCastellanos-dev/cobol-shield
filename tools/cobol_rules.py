"""
cobol-shield v0.3.0 — Reglas de auditoría COBOL
Detectores de riesgo operacional por falta de soporte y adaptabilidad.

Reglas implementadas:
  R-02: UNSTRING_NO_OVERFLOW — STRING/UNSTRING sin ON OVERFLOW
  (R-01, R-03, R-04, M-01, M-02 — próximas iteraciones)

Cada regla produce un VTR Finding Schema v1.
asset_id nunca es null — ver vtr_finding.py para política de UNRESOLVED.

Copyright (C) 2026 Luis Fidel Castellanos Diaz
Vector Telemetry Research (VTR) — SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from tools.vtr_finding import (
    CLASS_HECHO,
    CONF_OBSERVED,
    SEV_HIGH,
    Finding,
    make_finding,
)

# ── R-02 — UNSTRING_NO_OVERFLOW ──────────────────────────────────────────────

RULE_R02 = "R-02"
RULE_R02_DESC = "UNSTRING_NO_OVERFLOW"

# Detecta STRING o UNSTRING como inicio de sentencia COBOL
_RE_STRING_START = re.compile(
    r"^\s*(UNSTRING|STRING)\s+", re.IGNORECASE
)

# Detecta ON OVERFLOW o NOT ON OVERFLOW como parte de la sentencia
_RE_OVERFLOW_CLAUSE = re.compile(
    r"\bON\s+OVERFLOW\b|\bNOT\s+ON\s+OVERFLOW\b", re.IGNORECASE
)

# Detecta el fin de una sentencia COBOL (punto al final de línea)
_RE_STATEMENT_END = re.compile(r"\.\s*$")

# Detecta END-STRING o END-UNSTRING explícito
_RE_END_VERB = re.compile(r"\bEND-(STRING|UNSTRING)\b", re.IGNORECASE)


@dataclass
class R02Match:
    """Resultado de detección de R-02 en un archivo."""
    line_number: int
    verb: str        # STRING o UNSTRING
    line_content: str


def _scan_r02(lines: List[str]) -> List[R02Match]:
    """
    Analiza líneas de código COBOL buscando STRING/UNSTRING sin ON OVERFLOW.

    Estrategia:
      1. Detecta inicio de sentencia STRING/UNSTRING
      2. Acumula líneas hasta encontrar fin de sentencia (punto o END-verb)
      3. Verifica si la sentencia completa contiene ON OVERFLOW
      4. Si no contiene — es un hallazgo R-02
    """
    matches = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _RE_STRING_START.match(line)
        if m:
            verb = m.group(1).upper()
            start_line = i + 1  # 1-indexed para evidencia
            # Acumula la sentencia completa
            statement_lines = [line]
            j = i + 1
            found_end = _RE_STATEMENT_END.search(line) or _RE_END_VERB.search(line)
            while not found_end and j < len(lines):
                next_line = lines[j]
                statement_lines.append(next_line)
                found_end = (
                    _RE_STATEMENT_END.search(next_line)
                    or _RE_END_VERB.search(next_line)
                )
                j += 1
            statement = "\n".join(statement_lines)
            if not _RE_OVERFLOW_CLAUSE.search(statement):
                matches.append(R02Match(
                    line_number=start_line,
                    verb=verb,
                    line_content=line.rstrip(),
                ))
            i = j
        else:
            i += 1
    return matches


def scan_file_r02(file_path: str) -> List[Finding]:
    """
    Escanea un archivo COBOL para R-02.
    Retorna lista de VTR Findings — vacía si no hay hallazgos.
    """
    p = Path(file_path)
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    raw_matches = _scan_r02(lines)
    findings = []
    for match in raw_matches:
        observation = (
            f"{match.verb} without ON OVERFLOW at "
            f"{p.name}:{match.line_number} — "
            f"silent truncation risk"
        )
        f = make_finding(
            observation=observation,
            file_path=file_path,
            line=match.line_number,
            severity=SEV_HIGH,
            classification=CLASS_HECHO,
            confidence=CONF_OBSERVED,
            rule_id=RULE_R02,
        )
        findings.append(f)
    return findings


def scan_path_r02(root: str) -> List[Finding]:
    """
    Escanea un path (archivo o directorio) para R-02.
    Solo archivos con extensión COBOL.
    """
    COBOL_EXTS = {'.cob', '.cbl', '.cpy'}
    p = Path(root)
    targets = (
        [p] if p.is_file()
        else [f for f in p.rglob("*")
              if f.is_file() and f.suffix.lower() in COBOL_EXTS]
    )
    findings = []
    for t in targets:
        findings.extend(scan_file_r02(str(t)))
    return findings


# ── R-01 — UNINITIALIZED_WS ──────────────────────────────────────────────────

RULE_R01 = "R-01"
RULE_R01_DESC = "UNINITIALIZED_WS"

# Detecta inicio de WORKING-STORAGE SECTION
_RE_WS_START = re.compile(
    r"^\s*WORKING-STORAGE\s+SECTION", re.IGNORECASE
)

# Detecta inicio de otra sección — fin de WORKING-STORAGE
_RE_SECTION_END = re.compile(
    r"^\s*(LINKAGE|FILE|COMMUNICATION|LOCAL-STORAGE|"
    r"PROCEDURE|REPORT|SCREEN)\s+SECTION",
    re.IGNORECASE,
)

# Detecta declaración de nivel 01/77 con PIC
_RE_PIC_DECL = re.compile(
    r"^\s*(01|77)\s+(\S+)\s+.*\bPIC\b", re.IGNORECASE
)

# Detecta VALUE clause — cualquier forma
_RE_VALUE_CLAUSE = re.compile(
    r"\bVALUE\s+(ZEROS?|SPACES?|LOW-VALUES?|HIGH-VALUES?|ALL\b|NULLS?|"
    r"['\"].*?['\"]|\d+)",
    re.IGNORECASE,
)

# Detecta INITIALIZE <var> o MOVE ... TO <var>
def _re_init_for(varname: str) -> re.Pattern:
    escaped = re.escape(varname)
    return re.compile(
        rf"\bINITIALIZE\s+{escaped}\b|\bMOVE\b.*\bTO\s+{escaped}\b",
        re.IGNORECASE,
    )

# Detecta COPY en la misma zona — posible init externa
_RE_COPY = re.compile(r"^\s*COPY\s+", re.IGNORECASE)


@dataclass
class R01Match:
    line_number: int
    varname: str
    line_content: str
    confidence: str  # OBSERVED o INFERRED


def _extract_ws_vars(lines: List[str]) -> List[tuple]:
    """
    Extrae variables PIC de WORKING-STORAGE SECTION.
    Retorna lista de (lineno, varname, has_value, near_copy).
    Ignora LINKAGE, FILE, y otras secciones.
    """
    in_ws = False
    vars_found = []
    has_copy_nearby = False

    for i, line in enumerate(lines):
        if _RE_WS_START.match(line):
            in_ws = True
            has_copy_nearby = False
            continue
        if in_ws and _RE_SECTION_END.match(line):
            in_ws = False
            continue
        if not in_ws:
            continue

        if _RE_COPY.match(line):
            has_copy_nearby = True

        m = _RE_PIC_DECL.match(line)
        if m:
            varname = m.group(2)
            has_value = bool(_RE_VALUE_CLAUSE.search(line))
            vars_found.append((i + 1, varname, has_value, has_copy_nearby))

    return vars_found


def _scan_r01(lines: List[str]) -> List[R01Match]:
    """
    Detecta variables WORKING-STORAGE sin inicialización.

    Mitigación 1: solo WORKING-STORAGE — ignora LINKAGE y FILE SECTION.
    Mitigación 2: busca MOVE/INITIALIZE en todo PROCEDURE DIVISION.
    Mitigación 3: confidence INFERRED si hay COPY cercano.
    """
    ws_vars = _extract_ws_vars(lines)
    if not ws_vars:
        return []

    # Extraer texto completo del PROCEDURE DIVISION para búsqueda
    procedure_text = ""
    in_procedure = False
    for line in lines:
        if re.match(r"^\s*PROCEDURE\s+DIVISION", line, re.IGNORECASE):
            in_procedure = True
        if in_procedure:
            procedure_text += line + "\n"

    matches = []
    for lineno, varname, has_value, near_copy in ws_vars:
        # Mitigación 2 — tiene VALUE clause
        if has_value:
            continue

        # Mitigación 2 — tiene MOVE/INITIALIZE en PROCEDURE DIVISION
        init_pattern = _re_init_for(varname)
        if init_pattern.search(procedure_text):
            continue

        # Mitigación 3 — COPY cercano → INFERRED
        confidence = CONF_OBSERVED
        if near_copy:
            confidence = "INFERRED"

        matches.append(R01Match(
            line_number=lineno,
            varname=varname,
            line_content=lines[lineno - 1].rstrip(),
            confidence=confidence,
        ))

    return matches


def scan_file_r01(file_path: str) -> List[Finding]:
    """
    Escanea un archivo COBOL para R-01 UNINITIALIZED_WS.
    Retorna lista de VTR Findings.
    """
    p = Path(file_path)
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    raw_matches = _scan_r01(lines)
    findings = []
    for match in raw_matches:
        observation = (
            f"{match.varname} PIC — no VALUE clause, no INITIALIZE/MOVE "
            f"found in PROCEDURE DIVISION at {p.name}:{match.line_number}. "
            f"Note: initialization via COPY or PERFORM subprogram cannot "
            f"be verified by static analysis."
        )
        f = make_finding(
            observation=observation,
            file_path=file_path,
            line=match.line_number,
            severity=SEV_HIGH,
            classification=CLASS_HECHO,
            confidence=match.confidence,
            rule_id=RULE_R01,
        )
        findings.append(f)
    return findings


def scan_path_r01(root: str) -> List[Finding]:
    """Escanea un path para R-01."""
    COBOL_EXTS = {'.cob', '.cbl', '.cpy'}
    p = Path(root)
    targets = (
        [p] if p.is_file()
        else [f for f in p.rglob("*")
              if f.is_file() and f.suffix.lower() in COBOL_EXTS]
    )
    findings = []
    for t in targets:
        findings.extend(scan_file_r01(str(t)))
    return findings
