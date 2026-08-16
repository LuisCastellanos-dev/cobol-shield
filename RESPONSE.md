# cobol-shield — Response Playbook

How to act on findings produced by cobol-shield.

Each finding carries a `context_status` field that tracks where it stands
in the response lifecycle:

```
OBSERVED → CORROBORATED → VERIFIED → CLOSED
```

This document describes what moves a finding through each stage,
and what remediation looks like per rule.

---

## context_status lifecycle

| Status | Meaning | What it takes to reach it |
|--------|---------|---------------------------|
| `OBSERVED` | Condition detected by static analysis | cobol-shield produces this automatically |
| `CORROBORATED` | A second independent method confirms the condition | Manual review, second tool, or compiler behavior |
| `VERIFIED` | Condition confirmed to produce observable impact | Runtime test, compilation differential, or production trace |
| `CLOSED` | Remediation applied and re-scan is clean | Re-run cobol-shield on patched source, 0 findings |

A finding should never be closed without a clean re-scan.

---

## R-01 — UNINITIALIZED_WS

**What it means:**
A Working-Storage variable has no VALUE clause and no INITIALIZE or MOVE
found in the PROCEDURE DIVISION. Its initial content is undefined —
compiler-dependent, environment-dependent, or leftover from a prior run.

**To corroborate:**
Trace the variable through the PROCEDURE DIVISION manually.
Confirm no COPY or subprogram initializes it before first use.
If a COPY is present and R-01 confidence is `INFERRED`, check the copybook.

**To remediate:**
Add a VALUE clause at declaration:
```cobol
01 WS-BALANCE    PIC 9(10) VALUE ZEROS.
01 WS-NAME       PIC X(30) VALUE SPACES.
```
Or add INITIALIZE at the start of PROCEDURE DIVISION:
```cobol
PROCEDURE DIVISION.
    INITIALIZE WS-BALANCE WS-NAME.
```

**To verify closure:**
Re-run `scan_path_r01` on the patched file. Expect 0 findings.

---

## R-02 — UNSTRING_NO_OVERFLOW

**What it means:**
A STRING or UNSTRING statement has no ON OVERFLOW handler. If the input
exceeds the target field length, truncation occurs silently — no abend,
no return code, no log entry.

**To corroborate:**
Review the target field's PIC clause. If input can realistically exceed
that length (API data, user input, external files), the risk is active.

**To remediate:**
Add explicit overflow handling:
```cobol
UNSTRING WS-INPUT
    DELIMITED BY SPACE
    INTO WS-FIELD-1 WS-FIELD-2
    ON OVERFLOW
        MOVE 'Y' TO WS-OVERFLOW-FLAG
        PERFORM HANDLE-OVERFLOW
END-UNSTRING.
```

**To verify closure:**
Re-run `scan_path_r02`. Confirm the statement now has ON OVERFLOW.
If possible, test with input that exceeds the target field length.

---

## R-03 — REDEFINES_SIZE_MISMATCH

**What it means:**
A REDEFINES field declares more bytes (by PIC) than its base field.
Writing through the redefined view writes beyond the base field boundary.
Behavior is compiler-dependent — IBM Enterprise COBOL and GnuCOBOL
may handle this differently.

**Note:** If COMP or COMP-3 types are involved, confidence is `INFERRED`
because actual byte size differs from PIC declaration. Verify with your
compiler's size calculation before acting.

**To corroborate:**
Calculate actual byte sizes for both fields under your target compiler.
For COMP fields, consult IBM Enterprise COBOL Programming Guide §Storage.

**To remediate:**
Align the REDEFINES field size to match the base:
```cobol
* Before — mismatch
01 WS-BASE       PIC X(10).
01 WS-REDEF REDEFINES WS-BASE PIC X(15).  ← R-03 finding

* After — aligned
01 WS-BASE       PIC X(15).
01 WS-REDEF REDEFINES WS-BASE PIC X(15).  ← clean
```
Or reduce the REDEFINES field to fit within the base.

**To verify closure:**
Re-run `scan_path_r03`. Expect 0 findings for this variable pair.

---

## R-04 — FORMAT_BOUNDARY_ANALYSIS

R-04 findings are `severity=info`, `classification=PROYECCION`.
They document format conditions — not confirmed vulnerabilities.
Each sub-condition has its own response path.

### R-04a — COL73_NONEMPTY

**What it means:**
The identification area (cols 73–80) contains non-space content.
Historically this held programmer IDs or job names. Under fixed-format
IBM compilation it is ignored. Under free-format or modern tooling it
may be interpreted as code.

**To corroborate:**
Inspect the content. Determine whether it is:
- Historical metadata (programmer ID, job name) → document, low risk
- Executable-looking content → escalate, run Phase 2

**To remediate (if needed):**
Clear the identification area:
```python
# Strip cols 73-80 from each line
line = line[:72].ljust(72) + '        '
```
Or migrate to free-format and remove positional constraints.

**To verify closure:**
Re-run `scan_path_r04`. Expect 0 COL73_NONEMPTY findings.

---

### R-04b — COL7_VERB

**What it means:**
A line with col7=`*` (comment indicator) contains a COBOL executable verb.
The code is dormant under fixed-format compilation. It can become active if:
- A renumbering tool shifts the indicator area by one position
- The source is migrated to free-format without preserving col7 semantics

**This condition is CONFIRMADO when:**
Transformation differential (Phase 2) produces divergent output between
SOURCE A (fixed) and SOURCE B (free/transformed). See Phase 2 below.

**To corroborate:**
Run Phase 2 PoC:
```bash
bash tools/poc_differential.sh
```
If OUTPUT A ≠ OUTPUT B → CONFIRMADO.

**To remediate:**
Option 1 — remove the dormant code if it serves no purpose:
```cobol
* Before
000600*   MOVE 999999 TO WS-BALANCE.   ← R-04b finding

* After — line removed
```

Option 2 — convert to a format-independent comment:
```cobol
*> MOVE 999999 TO WS-BALANCE.   ← free-format comment, safe in both modes
```

Option 3 — if the code is intentional debugging, use a compiler directive:
```cobol
>>D MOVE 999999 TO WS-BALANCE.   ← only compiles with DEBUGGING MODE
```

**To verify closure:**
Re-run `scan_path_r04`. Expect 0 COL7_VERB findings on patched lines.
Re-run Phase 2 PoC on the patched source. OUTPUT A should equal OUTPUT B.

---

### R-04c — SOURCE_BOUNDARY

**What it means:**
A line contains non-space content beyond column 80. In fixed-format this
is outside the standard COBOL source record. Content there is
compiler-dependent — some toolchains ignore it, others may process it.

**To corroborate:**
Determine the origin of the line (manual edit, OCR import, Git migration).
Check whether your target compiler truncates or processes beyond col 80.

**To remediate:**
Trim lines to 80 characters:
```python
line = line[:80]
```

---

## Phase 2 — Transformation Differential

When R-04b produces a finding, Phase 2 determines its classification.

**Run:**
```bash
bash tools/poc_differential.sh
```

**Classification logic:**

| Result | Classification |
|--------|----------------|
| SOURCE B does not compile | PROBABLE — format-dependent interpretation confirmed |
| OUTPUT A ≠ OUTPUT B | CONFIRMADO — semantic divergence demonstrated |
| OUTPUT A = OUTPUT B | PROBABLE — condition present, no observable effect |

**What CONFIRMADO means for remediation:**
The dormant code in SOURCE A will produce different behavior if the source
is migrated to free-format without explicit review of col7 indicators.
Remediate per R-04b above before any format migration.

---

## Unicode Findings (check-invisibles.py)

**What it means:**
Invisible Unicode characters are present in the source or data.
These bypass visual code review and pass `PIC X` validation silently.

**To corroborate:**
```bash
hexdump -C affected-file.cob | grep -E "e2 80 (8b|ae|8c|8d|8e|8f)"
```
The byte sequence confirms the character is present, not a rendering artifact.

**To remediate:**
```bash
# Dry run first — review what will be changed
python3 tools/clean-invisibles.py . --dry-run --report audit.log

# Apply sanitization with forensic log
python3 tools/clean-invisibles.py . --report audit-$(date +%Y%m%d).log
```

**To verify closure:**
```bash
python3 tools/check-invisibles.py .
# Must exit 0
```

---

## Re-scan after remediation

For any finding, the closure criterion is a clean re-scan:

```bash
# Full re-scan — all rules
python3 -c "
from tools.cobol_rules import scan_path_r01, scan_path_r02, scan_path_r03, scan_path_r04
import sys
findings = (
    scan_path_r01('.') +
    scan_path_r02('.') +
    scan_path_r03('.') +
    scan_path_r04('.')
)
if findings:
    for f in findings:
        print(f'[{f.rule_id}] {f.severity.upper()} {f.observation[:80]}')
    sys.exit(1)
else:
    print('Clean — 0 findings')
    sys.exit(0)
"
```

Exit 0 on all rules is the closure criterion.

---

*cobol-shield — Vector Telemetry Research (VTR)*
