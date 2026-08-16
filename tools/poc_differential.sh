#!/usr/bin/env bash
# poc_differential.sh — Fase 2: Transformation Differential PoC
#
# Demuestra divergencia semántica entre COBOL fixed-format y free-format.
# SOURCE A: fixed-format — línea con col7='*' es comentario (código dormido)
# SOURCE B: free-format  — la misma línea pierde significado posicional
#
# El vector: migración fixed→free sin validación de integridad semántica.
# Compilar A con -fixed y B con -free — comparar output observable.
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
echo "  SOURCE A (fixed-format) — col7 por línea:"
python3 -c "
with open('$SOURCE_A') as f:
    for i,l in enumerate(f,1):
        raw=l.rstrip()
        col7=raw[6] if len(raw)>6 else '?'
        code=raw[7:50].rstrip() if len(raw)>7 else ''
        marker=' ← DORMANT (col7=*)' if col7=='*' else ''
        print(f'    L{i:02d} col7={repr(col7)} | {code[:40]}{marker}')
"
echo ""
echo "  SOURCE B (free-format) — mismas sentencias sin posición fija:"
python3 -c "
with open('$SOURCE_B') as f:
    for i,l in enumerate(f,1):
        raw=l.rstrip()
        marker=' ← SAME LINE, NO col7 SEMANTICS' if 'DORMANT' in raw else ''
        print(f'    L{i:02d} {raw[:55]}{marker}')
"
echo ""

# ── Paso 3: Análisis R-04 de SOURCE A ───────────────────────────────────────
echo "[3/5] Ejecutando R-04 FORMAT_BOUNDARY_ANALYSIS en SOURCE A..."
python3 -c "
import sys
sys.path.insert(0, '$REPO_DIR')
from tools.cobol_rules import scan_file_r04
findings = scan_file_r04('$SOURCE_A')
if findings:
    for f in findings:
        print(f'  FINDING [{f.rule_id}] {f.severity.upper()} {f.classification}')
        print(f'  {f.observation[:100]}...')
else:
    print('  No R-04 observations (expected for clean fixed-format)')
"
echo ""

# ── Paso 4: Compilar A (fixed) y B (free) ───────────────────────────────────
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
    echo "  ✗ SOURCE B falló (esperado si '*' no es comentario en free-format):"
    cat "$TMP/err-b.log"
fi
echo ""

# ── Paso 5: Comparar output observable ──────────────────────────────────────
echo "[5/5] Comparando output observable..."
echo ""

OUTPUT_A="[no compiló]"
OUTPUT_B="[no compiló]"

[[ "$COMPILE_A_OK" == true ]] && OUTPUT_A=$(cd "$TMP" && ./poc-a 2>/dev/null || echo "RUNTIME_ERROR")
[[ "$COMPILE_B_OK" == true ]] && OUTPUT_B=$(cd "$TMP" && ./poc-b 2>/dev/null || echo "RUNTIME_ERROR")

echo "  OUTPUT SOURCE A (fixed, col7='*' es comentario): '$OUTPUT_A'"
echo "  OUTPUT SOURCE B (free, sin semántica posicional): '$OUTPUT_B'"
echo ""

# Clasificación VTR
if [[ "$COMPILE_A_OK" == true && "$COMPILE_B_OK" == false ]]; then
    echo "  RESULTADO: SOURCE B no compila — la línea con '*' no es comentario"
    echo "  en free-format sin la directiva correcta, o produce error de sintaxis."
    echo "  CLASIFICACIÓN VTR: PROBABLE"
    echo "  Evidencia: compilación diferencial demuestra que el mismo archivo"
    echo "  se interpreta de forma distinta según el formato declarado."
elif [[ "$COMPILE_A_OK" == true && "$COMPILE_B_OK" == true ]]; then
    if [[ "$OUTPUT_A" != "$OUTPUT_B" ]]; then
        echo "  *** DIVERGENCIA SEMÁNTICA CONFIRMADA ***"
        echo "  CLASIFICACIÓN VTR: CONFIRMADO"
        echo ""
        echo "  La misma lógica produce outputs diferentes según el formato:"
        echo "    fixed → $OUTPUT_A"
        echo "    free  → $OUTPUT_B"
        echo ""
        SHA_A=$(sha256sum "$SOURCE_A" | cut -d' ' -f1)
        SHA_B=$(sha256sum "$SOURCE_B" | cut -d' ' -f1)
        echo "  Evidencia forense:"
        echo "    SHA-256 A: $SHA_A"
        echo "    SHA-256 B: $SHA_B"
        echo "    Compiler:  $(cobc --version 2>&1 | head -1)"
    else
        echo "  Outputs idénticos — divergencia posicional sin efecto semántico observable."
        echo "  CLASIFICACIÓN VTR: PROBABLE (condición detectada, output no diverge)"
    fi
else
    echo "  Compilación incompleta — revisar errores arriba."
    echo "  CLASIFICACIÓN VTR: HIPÓTESIS"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
