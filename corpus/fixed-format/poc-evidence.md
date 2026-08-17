# PoC Evidence — Compiler Flag Semantic Divergence

**Date:** 2026-08-16  
**Compiler:** cobc (GnuCOBOL) 3.1.2.0  
**File:** `poc-same-file.cbl` — single artifact, no modification between compilations  
**SHA-256:** `$(sha256sum corpus/fixed-format/poc-same-file.cbl | cut -d' ' -f1)`

## Setup

One file. Same compiler. Two flags.

```bash
cobc -x -fixed corpus/fixed-format/poc-same-file.cbl -o /tmp/poc-fixed
cobc -x -free  corpus/fixed-format/poc-same-file.cbl -o /tmp/poc-free
```

## Results (observed 2026-08-16, GnuCOBOL 3.1.2)

| Flag | Outcome | Output |
|------|---------|--------|
| `-fixed` | Compiles and executes | `0000001000` |
| `-free` | 10 compilation errors | — |

**Under `-fixed`:**  
Line 6 (`000600*   MOVE 999999 TO WS-BALANCE.`) — col7=`*` is the
comment indicator. `MOVE 999999` is dormant. Sequence numbers cols 1-6
are ignored. Program executes and displays `WS-BALANCE = 1000`.

**Under `-free`:**  
Sequence numbers `000100`...`001000` are parsed as numeric literals.
`PROGRAM-ID` header is reported missing. All 10 lines produce errors.
The file is syntactically invalid.

```
poc-same-file.cbl:1: error: PROGRAM-ID header missing
poc-same-file.cbl:1: error: PROCEDURE DIVISION header missing
poc-same-file.cbl:1: error: syntax error, unexpected Literal
poc-same-file.cbl:2: error: unknown statement «000200»
poc-same-file.cbl:3: error: unknown statement «000300»
poc-same-file.cbl:4: error: unknown statement «000400»
poc-same-file.cbl:5: error: unknown statement «000500»
poc-same-file.cbl:6: error: unknown statement «000600»
poc-same-file.cbl:6: error: WS-BALANCE undefined
poc-same-file.cbl:7: error: unknown statement «000700»
```

## Classification (VTR Audit Master Prompt v3.5)

| Condition | Classification |
|---|---|
| File valid under `-fixed` | CONFIRMADO |
| File invalid under `-free` | CONFIRMADO |
| Positional semantics are compiler-flag-dependent | CONFIRMADO |
| Flag is not visible inside the source file | CONFIRMADO |
| Changing the flag changes program validity | CONFIRMADO |

## Why this is stronger than SOURCE A → SOURCE B

The previous PoC (Phase 2) used a manually constructed SOURCE B to
demonstrate divergence. This PoC uses:

- **Single artifact** — no manual construction
- **Single compiler** — GnuCOBOL 3.1.2, documented behavior
- **Documented flags** — `-fixed` and `-free` are specified in GnuCOBOL
  Programmer's Guide
- **Reproducible** — three commands, any machine with GnuCOBOL installed

The transformation is the compiler flag itself, not a migration tool.
This is the minimal, cleanest demonstration of the thesis:
*the same source artifact has different semantics depending on the
compilation context, and that context lives outside the file.*

## Limitation

GnuCOBOL 3.1.2 behavior documented and observed.  
IBM Enterprise COBOL equivalent flags (`-SRCFORMAT(FIXED)` vs
`-SRCFORMAT(FREE)`) not verified — requires mainframe access.
Behavior may differ from GnuCOBOL.
