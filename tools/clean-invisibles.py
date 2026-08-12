#!/usr/bin/env python3
"""
COBOL Shield - Invisible Unicode Sanitizer
Cleans dangerous Unicode and generates forensic audit log.

Usage:
  python3 tools/clean-invisibles.py [path] [--dry-run] [--report FILE]

  --dry-run   Report only, do not modify files
  --report    Audit log path (default: audit-invisibles.log)
"""

import argparse
import shutil
from pathlib import Path

# Characters to remove silently
CLEAN_MAP = {
    0x200B: "",  # Zero-Width Space
    0x200C: "",  # Zero-Width Non-Joiner
    0x200D: "",  # Zero-Width Joiner
    0xFEFF: "",  # BOM / Zero Width No-Break Space
    **{cp: "" for cp in range(0xFE00, 0xFE10)},  # Variation Selectors
}

# Bidi overrides — critical, log separately
BIDI_CRITICAL = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))

ALLOWED_CONTROLS = {0x09, 0x0A, 0x0D}  # TAB, LF, CR

SCAN_EXTS = {'.cob', '.cbl', '.cpy', '.jcl', '.txt', '.dat'}


def clean_file(path, dry_run=False, report=None):
    try:
        data = path.read_bytes()
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        if report:
            report.write(f"{path}: BINARY or invalid UTF-8 — manual review needed\n")
        return False

    cleaned = []
    issues = []
    changed = False

    for idx, ch in enumerate(text):
        cp = ord(ch)
        if cp in BIDI_CRITICAL:
            issues.append(
                f"  CRITICAL Bidi U+{cp:04X} at offset {idx} "
                f"[{ch.encode('utf-8').hex().upper()}] — possible Trojan Source"
            )
            changed = True
            # Remove — do not substitute
        elif cp in CLEAN_MAP:
            issues.append(
                f"  CLEANED  U+{cp:04X} [{ch.encode('utf-8').hex().upper()}] "
                f"at offset {idx}"
            )
            cleaned.append(CLEAN_MAP[cp])
            changed = True
        elif cp < 0x20 and cp not in ALLOWED_CONTROLS:
            issues.append(
                f"  C0 ctrl  U+{cp:04X} at offset {idx}"
            )
            cleaned.append("")
            changed = True
        else:
            cleaned.append(ch)

    if changed and issues:
        if report:
            report.write(f"\n== {path} ==\n")
            for i in issues:
                report.write(f"{i}\n")
            report.write(
                f"  Hex sample (first 100 bytes): "
                f"{data[:100].hex().upper()}\n"
            )

        if not dry_run:
            backup = path.with_suffix(path.suffix + ".bak")
            shutil.copy2(path, backup)
            path.write_text("".join(cleaned), encoding='utf-8')
            print(f"[CLEANED] {path} — {len(issues)} issue(s), backup: {backup.name}")
        else:
            print(f"[DRY-RUN] {path} — would clean {len(issues)} issue(s)")
        return True

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Clean invisible Unicode from COBOL legacy files"
    )
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report only, do not modify files"
    )
    parser.add_argument(
        "--report", default="audit-invisibles.log",
        help="Audit log output path"
    )
    args = parser.parse_args()

    root = Path(args.path)
    report = open(args.report, "w", encoding="utf-8")
    report.write("COBOL Shield — Invisible Unicode Audit Log\n")
    report.write("==========================================\n")
    report.write(
        "Ref: CVE-2021-42574 (Trojan Source), Glassworm March 2026\n\n"
    )

    files = (
        [root] if root.is_file()
        else [p for p in root.rglob("*")
              if p.is_file() and p.suffix.lower() in SCAN_EXTS]
    )

    count = sum(
        clean_file(f, dry_run=args.dry_run, report=report)
        for f in files
    )

    report.close()
    print(f"\nDone. {count} file(s) affected. Audit log: {args.report}")
    if not args.dry_run:
        print("Recompile with GnuCOBOL and validate with FUNCTION HEX-OF.")


if __name__ == "__main__":
    main()
