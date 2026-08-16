# cobol-shield

**Security auditing toolkit for COBOL legacy systems**

Detects invisible Unicode attacks, unsafe COBOL patterns, and format
transformation integrity issues in GnuCOBOL sources and Zowe API→COBOL pipelines.

`PIC X` accepts everything. Your batch shouldn't.

---

## Scope

cobol-shield covers two distinct threat surfaces:

**1. Unicode Invisible Characters** — CVE-2021-42574 and Glassworm-class vectors
that bypass visual code review and corrupt PIC X fields silently.

**2. COBOL Static Analysis** — unsafe patterns in legacy sources: uninitialized
working-storage, unchecked STRING/UNSTRING overflow, REDEFINES size mismatches,
and fixed-format positional conditions that change meaning under transformation.

---

## Tools

| File | Purpose |
|------|---------|
| `tools/check-invisibles.py` | CI checker — exits 1 on invisible Unicode detection |
| `tools/clean-invisibles.py` | Sanitizer with forensic audit log |
| `src/AUDITOR-INVISIBLE.cob` | In-COBOL byte validator using `HEX-OF` |
| `tools/cobol_rules.py` | Static analysis rules R-01 through R-04 |
| `tools/transform_renumber.py` | Fixed-format renumber shift simulator (Phase 2) |
| `tools/poc_differential.sh` | Transformation differential PoC (GnuCOBOL required) |

---

## Static Analysis Rules

Each rule produces a **VTR Finding Schema v1** output compatible with
`cryptofault` and `vtr-forensic-img` via `context_loader`.

| Rule | Name | Severity | Classification |
|------|------|----------|----------------|
| R-01 | `UNINITIALIZED_WS` | High | HECHO |
| R-02 | `UNSTRING_NO_OVERFLOW` | High | HECHO |
| R-03 | `REDEFINES_SIZE_MISMATCH` | High | HECHO |
| R-04 | `FORMAT_BOUNDARY_ANALYSIS` | Info | PROYECCION |

**R-01 — UNINITIALIZED_WS**
Detects Working-Storage variables declared without a VALUE clause and without
INITIALIZE or MOVE in the PROCEDURE DIVISION. Silent undefined behavior risk
in batch and CICS environments.

**R-02 — UNSTRING_NO_OVERFLOW**
Detects STRING/UNSTRING statements without ON OVERFLOW handling. Silent
truncation when input exceeds target field length.

**R-03 — REDEFINES_SIZE_MISMATCH**
Detects REDEFINES where the redefined field declares more bytes than its base.
Memory boundary violation risk — compiler-dependent behavior.

**R-04 — FORMAT_BOUNDARY_ANALYSIS** *(Phase 1 — observations only)*
Detects positional conditions in fixed-format COBOL sources:
- `COL73_NONEMPTY` — non-space content in identification area (cols 73–80)
- `COL7_VERB` — COBOL executable verb in a commented line (col7 = `*` / `/` / `D`)
- `SOURCE_BOUNDARY` — content beyond col 80

R-04 produces `severity=info`, `classification=PROYECCION`. It documents
format conditions — not vulnerabilities. Impact requires transformation
differential analysis (Phase 2).

---

## Transformation Differential — Phase 2

R-04b `COL7_VERB` findings are **CONFIRMADO** when a transformation
(fixed→free-format migration) demonstrably activates dormant code.

**Demonstrated with GnuCOBOL 3.1.2:**

```
SOURCE A (fixed-format, col7='*' dormant):   output → 0000001000
SOURCE B (free-format,  code active):         output → 0000999999
```

SHA-256 A: `b70a948a0df5e8f685e82f5bffc9c4710f2c0a7a23b6294e7ca20092c2d25d37`
SHA-256 B: `f5fd80f79ed3e5be97628f89790256d6fba80605dce2b7985b729b5fef6f26d5`

**Run the PoC** (requires GnuCOBOL):

```bash
bash tools/poc_differential.sh
```

**Limitation:** SOURCE B is a manual representation of an incorrect
fixed→free migration. Behavior of IBM Z Open Editor or IBM SCU
under real renumbering conditions is not yet verified.

---

## Unicode Detection

Detected ranges:

| Codepoint | Name | Risk |
|-----------|------|------|
| U+0001–U+001F | C0 Controls | Batch abends |
| U+200B–U+200F | Zero-Width | Data corruption, VSAM truncation |
| U+202A–U+202E | Bidi Override | Trojan Source — CVE-2021-42574 |
| U+2066–U+2069 | Bidi Isolate | Direction spoofing |
| U+FE00–U+FE0F | Variation Selectors | Glassworm-class steganography |
| U+E000–U+F8FF | Private Use Area | Payload hiding |
| U+FEFF | BOM | Silent prepended byte |

```bash
# Byte-level inspection
hexdump -C source.cob | grep -E "e2 80 (8b|ae)"
```

---

## Usage

```bash
# Unicode CI check — exits 1 on detection
python3 tools/check-invisibles.py .

# Sanitize with forensic audit log
python3 tools/clean-invisibles.py . --report audit-$(date +%Y%m%d).log

# Run static analysis rules
python3 -c "
from tools.cobol_rules import scan_path_r01, scan_path_r02, scan_path_r03, scan_path_r04
import json
for f in scan_path_r02('your-source.cbl'):
    print(f.to_json())
"

# Transformation differential PoC
bash tools/poc_differential.sh
```

---

## GitHub Action

```yaml
- name: Check for invisible Unicode
  run: python3 tools/check-invisibles.py .
```

---

## Why COBOL

`PIC X(n)` is a raw byte buffer. It accepts any byte sequence without
validation. When a Zowe API layer passes JSON to a COBOL copybook via
`MOVE`, invisible Unicode enters the record silently.

Fixed-format COBOL adds a second surface: positional column semantics
(col 7 as indicator area, cols 73–80 as identification area) are
format-dependent. A migration tool that does not preserve these semantics
can activate dormant code or silently corrupt program structure.

The shared mechanism with CVE-2021-42574 is the detection gap — content
that bypasses visual inspection. The data-field truncation vector and
the format transformation vector are distinct from the source-code
semantic flip described in CVE-2021-42574.

---

## Test Suite

```bash
pip install pytest
python -m pytest tests/ -q
# 159 tests, 0 failures
```

---

## References

- [CVE-2021-42574 — Trojan Source](https://trojansource.codes/)
- [Glassworm — Aikido Security, March 2026](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode)
- [IBM Enterprise COBOL Programming Guide — Source Format](https://www.ibm.com/docs/en/cobol-zos)
- [GnuCOBOL Programmer's Guide](https://gnucobol.sourceforge.io/)
- [Open Mainframe Project — Zowe](https://github.com/zowe)
- [VTR Finding Schema v1 — tools/vtr_finding.py](tools/vtr_finding.py)

---

## License

MIT

---

*Luis F. Castellanos — Applied Cryptography & Systems Engineering ·
FreeBSD / Rust · COBOL Legacy Auditing · Founder @ Vector Telemetry Research*
