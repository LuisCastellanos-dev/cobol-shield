# PoC Differential — Resultado CONFIRMADO

**Fecha:** 2026-08-16  
**Compilador:** cobc (GnuCOBOL) 3.1.2.0  
**Clasificación VTR:** CONFIRMADO  

## Vector demostrado

Transformación fixed-format → free-format activa código dormido (col7='*').

## Evidencia observable

| Archivo   | Formato | Output      | SHA-256 (primeros 16)  |
|-----------|---------|-------------|------------------------|
| SOURCE A  | fixed   | 0000001000  | b70a948a0df5e8f6...    |
| SOURCE B  | free    | 0000999999  | f5fd80f79ed3e5be...    |

## Cadena de ataque demostrada

1. SOURCE A contiene `MOVE 999999 TO WS-BALANCE` en línea con `col7='*'`
2. R-04 detecta condición: `COL7_VERB` — verbo ejecutable en línea comentada
3. Herramienta de migración convierte fixed→free eliminando semántica posicional
4. SOURCE B compila con `-free` — el MOVE 999999 es ahora código activo
5. Output diverge: 1000 → 999999

## Clasificación por columna (VTR Audit Master Prompt v3.5)

| Condición | Clasificación |
|-----------|---------------|
| col7='*' suprime código en fixed-format | CONFIRMADO |
| Migración fixed→free elimina semántica de col7 | CONFIRMADO |
| Código dormido se activa tras transformación | CONFIRMADO |
| Output observable diverge entre A y B | CONFIRMADO |

## Limitaciones del PoC

- GnuCOBOL 3.1.2 — comportamiento de IBM Enterprise COBOL puede diferir
- SOURCE B es representación manual de migración incorrecta, no output real de IBM Z Open Editor
- Impacto en producción depende de si la herramienta de migración real reproduce este patrón
