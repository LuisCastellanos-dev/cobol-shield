"""
transform_renumber.py — Fase 2: Transformation Differential

Simula una renumeración de secuencia que desplaza el contenido
de la columna 7 (indicator area) hacia la columna 6 (sequence area),
activando código que estaba comentado.

Esta transformación es análoga a la que realizan herramientas como
IBM Z Open Editor (renumber/denumber) o scripts de migración OCR
que recalculan los números de secuencia sin preservar el indicator area.

MECANISMO:
  SOURCE A (fixed-format original):
    cols 1-6:  número de secuencia original (ej. "000600")
    col  7:    indicator ('*' = comentario)
    cols 8-72: código COBOL
    cols 73-80: identification area

  SOURCE B (tras renumeración incorrecta):
    cols 1-6:  nuevo número de secuencia (ej. "000060")
    col  7:    primer char del código — que era '*' pero ahora
               el contenido se desplazó: el '*' pasó a col 6,
               y col 7 ahora es ' ' (espacio) → código ACTIVO

IMPORTANTE:
  Este script produce SOURCE B como evidencia del PoC.
  No es un ataque — es demostración de divergencia semántica
  para clasificar el vector como PROBABLE o CONFIRMADO
  según el resultado de compilación de A vs B.

Copyright (C) 2026 Luis Fidel Castellanos Diaz
Vector Telemetry Research (VTR)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def renumber_shift(source_a: str, source_b: str) -> dict:
    """
    Transforma SOURCE A en SOURCE B simulando una renumeración que introduce
    un off-by-one en la identification area (cols 1-6), desplazando el número
    de secuencia hacia col 7.

    MECANISMO REAL:
    Herramientas de renumeración como IBM SCU o scripts OCR a veces insertan
    el nuevo número de secuencia en cols 1-7 en lugar de 1-6, empujando el
    indicator area (col 7) un carácter hacia la derecha. El resultado:

      SOURCE A: "000600*   MOVE 999999 TO WS-BALANCE."
                 ^^^^^^ ^-- col7='*' (comentario)
      SOURCE B: "0006000   MOVE 999999 TO WS-BALANCE."
                 ^^^^^^^ ^-- col7=' ' (código activo)

    La identificación area se amplía en 1 char, el indicator se absorbe
    en el número de secuencia, y col 7 pasa a ser el primer char del
    contenido original — usualmente un espacio.

    Este es el off-by-one que convierte código dormido en código ejecutable.
    """
    lines_a = Path(source_a).read_text(encoding='utf-8', errors='replace').splitlines()
    lines_b = []
    divergences = []

    for i, line in enumerate(lines_a):
        raw = line.rstrip('\r\n')
        line_num = i + 1

        if len(raw) < 8:
            lines_b.append(raw)
            continue

        seq_a   = raw[0:6]    # sequence number original
        col7_a  = raw[6]      # indicator original
        code_a  = raw[7:72]   # código cols 8-72
        id_area = raw[72:] if len(raw) > 72 else '        '

        # Off-by-one: nuevo seq ocupa cols 1-7 (7 chars en lugar de 6)
        # col7_b = primer char de code_a (usualmente espacio)
        # El código se desplaza 1 char a la derecha (pierde último char)
        new_seq7 = f"{line_num * 10:07d}"   # 7 dígitos — ocupa hasta col 7
        col7_b   = code_a[0] if code_a else ' '
        code_b   = code_a[1:].ljust(65)[:65]

        line_b = new_seq7 + col7_b + code_b + id_area
        line_b = line_b[:80].ljust(80)
        lines_b.append(line_b)

        # Detectar divergencia semántica en col7
        if col7_a in ('*', '/', 'D') and col7_b not in ('*', '/', 'D'):
            divergences.append({
                'line': line_num,
                'col7_a': col7_a,
                'col7_b': col7_b,
                'code_a': code_a.strip(),
                'code_b': code_b.strip(),
                'effect': 'COMMENT→ACTIVE: dormant code became executable',
            })
        elif col7_a not in ('*', '/', 'D') and col7_b in ('*', '/', 'D'):
            divergences.append({
                'line': line_num,
                'col7_a': col7_a,
                'col7_b': col7_b,
                'code_a': code_a.strip(),
                'code_b': code_b.strip(),
                'effect': 'ACTIVE→COMMENT: executable code became dormant',
            })

    Path(source_b).write_text('\n'.join(lines_b) + '\n', encoding='utf-8')

    return {
        'source_a': source_a,
        'source_b': source_b,
        'total_lines': len(lines_a),
        'divergences': divergences,
    }


def main():
    parser = argparse.ArgumentParser(
        description='Transformation Differential — renumber shift simulation'
    )
    parser.add_argument('source_a', help='Input COBOL fixed-format file (SOURCE A)')
    parser.add_argument('source_b', help='Output transformed file (SOURCE B)')
    args = parser.parse_args()

    result = renumber_shift(args.source_a, args.source_b)

    print(f"SOURCE A: {result['source_a']}")
    print(f"SOURCE B: {result['source_b']}")
    print(f"Total lines: {result['total_lines']}")
    print(f"Divergences found: {len(result['divergences'])}")

    for d in result['divergences']:
        print(f"\n  Line {d['line']}:")
        print(f"    col7 A={repr(d['col7_a'])} → B={repr(d['col7_b'])}")
        print(f"    Effect: {d['effect']}")
        print(f"    Code A: {d['code_a'][:60]}")
        print(f"    Code B: {d['code_b'][:60]}")

    return 0 if result['divergences'] else 1


if __name__ == '__main__':
    sys.exit(main())
