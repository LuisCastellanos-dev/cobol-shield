#!/usr/bin/env bash
# poc_compiler_flag.sh — PoC definitivo: mismo archivo, -fixed vs -free
#
# Demuestra que un archivo COBOL fixed-format es semánticamente válido
# bajo -fixed y sintácticamente inválido bajo -free con el mismo compilador.
#
# Este es el PoC más limpio del paper porque:
#   - Un solo artefacto sin modificación
#   - Un solo compilador (GnuCOBOL documentado)
#   - Dos flags documentados: -fixed y -free
#   - La transformación ES el flag — no una herramienta externa
#   - Reproducible en 3 comandos
#
# Uso:
#   cd ~/cobol-shield
#   bash tools/poc_compiler_flag.sh
#
# Copyright (C) 2026 Luis Fidel Castellanos Diaz — Vector Telemetry Research

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$REPO_DIR/corpus/fixed-format/poc-same-file.cbl"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "═══════════════════════════════════════════════════════════════"
echo " VTR cobol-shield — PoC: Compiler Flag Semantic Divergence     "
echo " Same file. Same compiler. Two flags. Different semantics.     "
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Prerequisitos
if ! command -v cobc &>/dev/null; then
    echo "ERROR: GnuCOBOL no encontrado. Instala: sudo apt install gnucobol"
    exit 1
fi
COMPILER="$(cobc --version 2>&1 | head -1)"
SHA256="$(sha256sum "$SOURCE" | cut -d' ' -f1)"

echo "Compiler : $COMPILER"
echo "File     : $(basename "$SOURCE")"
echo "SHA-256  : $SHA256"
echo ""

# Mostrar el archivo — especialmente L06 con col7='*'
echo "[Source] col7 analysis:"
python3 -c "
with open('$SOURCE') as f:
    for i,l in enumerate(f,1):
        raw=l.rstrip()
        col7=raw[6] if len(raw)>6 else '?'
        marker=' ← col7=* COMMENT INDICATOR (dormant code)' if col7=='*' else ''
        print(f'  L{i:02d} col7={repr(col7)} | {raw[:50]}{marker}')
"
echo ""

# Compilar con -fixed
echo "[1/2] cobc -x -fixed ..."
FIXED_OK=false
OUTPUT_FIXED=""
if cobc -x -fixed "$SOURCE" -o "$TMP/poc-fixed" 2>"$TMP/err-fixed.log"; then
    FIXED_OK=true
    OUTPUT_FIXED=$(cd "$TMP" && ./poc-fixed 2>/dev/null || echo "RUNTIME_ERROR")
    echo "  ✓ Compiles"
    echo "  Output: $OUTPUT_FIXED"
else
    echo "  ✗ Compilation failed:"
    cat "$TMP/err-fixed.log" | head -5
fi
echo ""

# Compilar con -free
echo "[2/2] cobc -x -free ..."
FREE_OK=false
if cobc -x -free "$SOURCE" -o "$TMP/poc-free" 2>"$TMP/err-free.log"; then
    FREE_OK=true
    OUTPUT_FREE=$(cd "$TMP" && ./poc-free 2>/dev/null || echo "RUNTIME_ERROR")
    echo "  ✓ Compiles"
    echo "  Output: $OUTPUT_FREE"
else
    ERRORS=$(wc -l < "$TMP/err-free.log")
    echo "  ✗ $ERRORS compilation errors"
    cat "$TMP/err-free.log"
fi
echo ""

# Clasificación VTR
echo "═══════════════════════════════════════════════════════════════"
if [[ "$FIXED_OK" == true && "$FREE_OK" == false ]]; then
    echo " CLASIFICACIÓN VTR: CONFIRMADO"
    echo ""
    echo " Same file. Same compiler ($COMPILER)."
    echo " -fixed : compiles → output $OUTPUT_FIXED"
    echo " -free  : compilation rejected (positional semantics lost)"
    echo ""
    echo " The compiler flag — which lives outside the source file —"
    echo " determines whether the program is valid and what it does."
    echo " This is the minimal demonstration of Source Transformation"
    echo " Integrity failure in COBOL fixed-format systems."
    echo ""
    echo " Evidence:"
    echo "   SHA-256 : $SHA256"
    echo "   Compiler: $COMPILER"
elif [[ "$FIXED_OK" == true && "$FREE_OK" == true ]]; then
    echo " CLASIFICACIÓN VTR: PROBABLE"
    echo " Both compile — check output differential above."
else
    echo " CLASIFICACIÓN VTR: HIPÓTESIS — revisar errores"
fi
echo "═══════════════════════════════════════════════════════════════"
