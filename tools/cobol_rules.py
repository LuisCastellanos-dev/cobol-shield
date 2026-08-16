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
