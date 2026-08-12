# COBOL Shield

**Security hardening toolkit for COBOL legacy systems**

Detects and cleans invisible Unicode attacks in GnuCOBOL sources and
Zowe API→COBOL pipelines.

`PIC X` accepts everything. Your batch shouldn't.

---

## The Problem

Modern APIs send JSON with UTF-8. Legacy COBOL core expects ASCII/EBCDIC
`PIC X(n)`. A single `U+200B` (Zero-Width Space) or `U+202E` (Bidi
Override) bypasses visual code review, passes `PIC X` validation silently,
and can corrupt nightly batches, DB2 loads, and CICS transactions.

Standard linters don't catch it. GitHub diff renders it as blank space.
Only byte-level inspection reveals it.

```
hexdump -C source.cob | grep -E "e2 80 (8b|ae)"
```

---

## Tools

| File | Purpose |
|------|---------|
| `tools/check-invisibles.py` | CI checker — exits 1 on detection |
| `tools/clean-invisibles.py` | Sanitizer with forensic audit log |
| `src/AUDITOR-INVISIBLE.cob` | In-COBOL byte validator using `HEX-OF` |

---

## Detected Ranges

| Codepoint | Name | Risk |
|-----------|------|------|
| U+0001–U+001F | C0 Controls | Batch abends |
| U+200B–U+200F | Zero-Width | Data corruption, VSAM truncation |
| U+202A–U+202E | Bidi Override | **Trojan Source CVE-2021-42574** |
| U+2066–U+2069 | Bidi Isolate | Direction spoofing |
| U+FE00–U+FE0F | Variation Selectors | Glassworm steganography |
| U+E000–U+F8FF | Private Use Area | Payload hiding |
| U+FEFF | BOM | Silent prepended byte |

---

## Usage

```bash
# CI — fail on detection
python3 tools/check-invisibles.py .

# Audit only (no changes)
python3 tools/clean-invisibles.py --dry-run --report audit.log

# Clean + backup + audit trail
python3 tools/clean-invisibles.py . --report audit-$(date +%Y%m%d).log

# COBOL internal validation (requires GnuCOBOL)
cobc -x src/AUDITOR-INVISIBLE.cob && ./AUDITOR-INVISIBLE
```

---

## GitHub Action

Add to `.github/workflows/unicode-check.yml` — included in this repo.

```yaml
- name: Check for invisible Unicode
  run: python3 tools/check-invisibles.py .
```

---

## Why COBOL

`PIC X(n)` is a raw byte buffer. It accepts any byte sequence without
validation. When a Zowe API layer passes JSON to a COBOL copybook via
`MOVE`, invisible Unicode enters the record silently. The COBOL program
processes it as data. Downstream systems — DB2, VSAM, CICS — receive
corrupted records.

This is CVE-2021-42574 (Trojan Source) applied to mainframe pipelines.
The same technique was used in the Glassworm campaign (March 2026) to
compromise 433+ software components across GitHub, npm, and VS Code.

The defense: validate at the boundary, in raw bytes, before any `MOVE`.
`FUNCTION HEX-OF` is the COBOL equivalent of `hexdump -C`.

---

## References

- [CVE-2021-42574 — Trojan Source](https://trojansource.codes/)
- [Glassworm — Aikido Security, March 2026](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode)
- [curl malicious unicode check — Daniel Stenberg](https://github.com/curl/curl)
- [Open Mainframe Project — Zowe](https://github.com/zowe)

---

## License

MIT

---

*Luis F. Castellanos — FreeBSD Security / COBOL Legacy Auditing / VTR Shield*
