#!/usr/bin/env bash
# poc_differential.sh — Fase 2: Transformation Differential PoC
#
# Demuestra divergencia semántica entre COBOL fixed-format y free-format.
#
# SOURCE A: fixed-format original
#   col7='*' en L06 → MOVE 999999 es comentario (código dormido)
#   Output esperado: 0000001000
#
# SOURCE B: resultado de migración fixed→free incorrecta
#   La herramienta elimina el indicator area (col7)
#   El MOVE 999999 que era comentario queda como código activo
#   Output esperado: 0000999999
#
# Si OUTPUT_A ≠ OUTPUT_B → CONFIRMADO: divergencia semántica demostrada.
#
# Prerequisitos: GnuCOBOL (cobc), Python 3
# Uso:
#   cd ~/cobol-shield
#   bash tools/poc_differential.sh
#
# Copyright (C) 2026 Luis Fidel Castellanos Diaz — Vector Telemetry Research

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="$REPO_DIR/corpus/fixed-format"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SOURCE_A="$CORPUS/poc-source-a.cbl"
SOURCE_B="$CORPUS/poc-source-b.cbl"

echo "═══════════════════════════════════════════════════════════════"
echo " VTR cobol-shield — Fase 2: Transformation Differential PoC   "
echo " Vector: fixed-format → free-format semantic divergence        "
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── Paso 1: Prerequisitos ────────────────────────────────────────────────────
echo "[1/5] Verificando prerequisitos..."
if ! command -v cobc &>/dev/null; then
    echo "ERROR: GnuCOBOL no encontrado. Instala: sudo apt install gnucobol"
    exit 1
fi
echo "      $(cobc --version 2>&1 | head -1)"
echo ""

# ── Paso 2: Verificar corpus ─────────────────────────────────────────────────
echo "[2/5] Verificando corpus..."
echo ""
echo "  SOURCE A (fixed-format original):"
python3 -c "
with open('$SOURCE_A') as f:
    for i,l in enumerate(f,1):
        raw=l.rstrip()
        col7=raw[6] if len(raw)>6 else '?'
        code=raw[7:55].rstrip() if len(raw)>7 else ''
        marker=' ← DORMANT (col7=*)' if col7=='*' else ''
        print(f'    L{i:02d} col7={repr(col7)} | {code}{marker}')
"
echo ""
echo "  SOURCE B (tras migración fixed→free — código dormido activado):"
python3 -c "
with open('$SOURCE_B') as f:
    for i,l in enumerate(f,1):
        raw=l.rstrip()
        marker=' ← WAS DORMANT IN A, NOW ACTIVE' if 'MOVE 999999' in raw else ''
        print(f'    L{i:02d} {raw[:55]}{marker}')
"
echo ""

# ── Paso 3: R-04 en SOURCE A ─────────────────────────────────────────────────
echo "[3/5] R-04 FORMAT_BOUNDARY_ANALYSIS en SOURCE A..."
python3 -c "
import sys
sys.path.insert(0, '$REPO_DIR')
from tools.cobol_rules import scan_file_r04
findings = scan_file_r04('$SOURCE_A')
if findings:
    for f in findings:
        print(f'  [{f.rule_id}] {f.severity.upper()} {f.classification}')
        print(f'  {f.observation[:110]}...')
else:
    print('  Sin observaciones R-04')
"
echo ""

# ── Paso 4: Compilar A y B ───────────────────────────────────────────────────
echo "[4/5] Compilando SOURCE A (-fixed) y SOURCE B (-free)..."

COMPILE_A_OK=false
COMPILE_B_OK=false

echo "  Compilando SOURCE A con -fixed..."
if cobc -x -fixed "$SOURCE_A" -o "$TMP/poc-a" 2>"$TMP/err-a.log"; then
    COMPILE_A_OK=true
    echo "  ✓ SOURCE A compilado"
else
    echo "  ✗ SOURCE A falló:"
    cat "$TMP/err-a.log"
fi

echo "  Compilando SOURCE B con -free..."
if cobc -x -free "$SOURCE_B" -o "$TMP/poc-b" 2>"$TMP/err-b.log"; then
    COMPILE_B_OK=true
    echo "  ✓ SOURCE B compilado"
else
    echo "  ✗ SOURCE B falló:"
    cat "$TMP/err-b.log"
fi
echo ""

# ── Paso 5: Comparar output observable ──────────────────────────────────────
echo "[5/5] Comparando output observable..."
echo ""

OUTPUT_A="[no compiló]"
OUTPUT_B="[no compiló]"

[[ "$COMPILE_A_OK" == true ]] && \
    OUTPUT_A=$(cd "$TMP" && ./poc-a 2>/dev/null || echo "RUNTIME_ERROR")
[[ "$COMPILE_B_OK" == true ]] && \
    OUTPUT_B=$(cd "$TMP" && ./poc-b 2>/dev/null || echo "RUNTIME_ERROR")

echo "  OUTPUT A (fixed — MOVE 999999 dormido):  '$OUTPUT_A'"
echo "  OUTPUT B (free  — MOVE 999999 activo):   '$OUTPUT_B'"
echo ""

if [[ "$COMPILE_A_OK" == true && "$COMPILE_B_OK" == true ]]; then
    if [[ "$OUTPUT_A" != "$OUTPUT_B" ]]; then
        echo "  ╔══════════════════════════════════════════════════════╗"
        echo "  ║  DIVERGENCIA SEMÁNTICA CONFIRMADA                    ║"
        echo "  ║  CLASIFICACIÓN VTR: CONFIRMADO                       ║"
        echo "  ╚══════════════════════════════════════════════════════╝"
        echo ""
        echo "  La migración fixed→free activó código que estaba dormido."
        echo "  El mismo WS-BALANCE produce valores distintos:"
        echo "    SOURCE A (fixed): $OUTPUT_A"
        echo "    SOURCE B (free):  $OUTPUT_B"
        echo ""
        SHA_A=$(sha256sum "$SOURCE_A" | cut -d' ' -f1)
        SHA_B=$(sha256sum "$SOURCE_B" | cut -d' ' -f1)
        echo "  Evidencia forense:"
        echo "    SHA-256 A: $SHA_A"
        echo "    SHA-256 B: $SHA_B"
        echo "    Compiler:  $(cobc --version 2>&1 | head -1)"
        echo ""
        echo "  R-04b COL7_VERB se eleva de PROYECCION a CONFIRMADO."
    else
        echo "  Outputs idénticos."
        echo "  CLASIFICACIÓN VTR: PROBABLE"
    fi
elif [[ "$COMPILE_A_OK" == true && "$COMPILE_B_OK" == false ]]; then
    echo "  SOURCE B no compila — error de sintaxis en migración."
    echo "  CLASIFICACIÓN VTR: PROBABLE"
    echo "  Evidencia: el mismo contenido es inválido en free-format,"
    echo "  confirmando que la interpretación posicional es format-dependent."
else
    echo "  CLASIFICACIÓN VTR: HIPÓTESIS — compilación incompleta."
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
