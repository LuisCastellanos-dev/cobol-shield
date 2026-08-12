#!/usr/bin/env python3
"""
COBOL Shield - Invisible Unicode Security Checker
Mitigates CVE-2021-42574 (Trojan Source) and Glassworm (March 2026)

References:
  - CVE-2021-42574: https://trojansource.codes/
  - Glassworm: https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode
  - curl unicode check: https://github.com/curl/curl/blob/master/scripts/badwords.pl

Usage:
  python3 tools/check-invisibles.py [path]
  Exits 1 if invisible Unicode is found (CI-safe).
"""

import sys
from pathlib import Path

# Dangerous ranges — invisible or direction-altering Unicode
DANGEROUS_RANGES = [
    (0x0001, 0x001F, "C0 Control"),
    (0x200B, 0x200F, "Zero-Width / Bidi control"),
    (0x202A, 0x202E, "Bidi Override — Trojan Source CVE-2021-42574"),
    (0x2066, 0x2069, "Isolate Bidi"),
    (0xFE00, 0xFE0F, "Variation Selectors — Glassworm vector"),
    (0xE000, 0xF8FF, "Private Use Area — steganography"),
    (0xFEFF, 0xFEFF, "Zero Width No-Break Space / BOM"),
]

# Permitted control characters in COBOL source
ALLOWED_CONTROLS = {0x09, 0x0A, 0x0D}  # TAB, LF, CR

# Extensions to scan
SCAN_EXTS = {'.cob', '.cbl', '.cpy', '.jcl', '.c', '.h', '.py', '.sh'}


def is_dangerous(codepoint):
    if codepoint < 0x20 and codepoint not in ALLOWED_CONTROLS:
        return f"C0 Control U+{codepoint:04X}"
    for start, end, name in DANGEROUS_RANGES:
        if start <= codepoint <= end and codepoint not in ALLOWED_CONTROLS:
            return f"{name} U+{codepoint:04X}"
    return None


def scan_file(path):
    issues = []
    try:
        data = path.read_bytes()
        text = data.decode('utf-8')
    except UnicodeDecodeError as e:
        return [f"{path}:{e.start}: Invalid UTF-8 sequence — possible binary injection"]

    for lineno, line in enumerate(text.splitlines(), 1):
        for col, ch in enumerate(line, 1):
            reason = is_dangerous(ord(ch))
            if reason:
                hex_bytes = ch.encode('utf-8').hex().upper()
                issues.append(
                    f"{path}:{lineno}:{col}: {reason} "
                    f"[bytes {hex_bytes}] -> {repr(line[:80])}"
                )
    return issues


def main(root="."):
    root = Path(root)
    all_issues = []
    files_scanned = 0

    targets = [root] if root.is_file() else [
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in SCAN_EXTS
    ]

    for p in targets:
        # Allow explicit UTF-8 test fixtures
        if "test_utf8" in p.name.lower():
            continue
        files_scanned += 1
        all_issues.extend(scan_file(p))

    print(f"Scanned {files_scanned} file(s).")

    if all_issues:
        print("\n[FAIL] Invisible Unicode detected:\n")
        for issue in all_issues:
            print(f"  {issue}")
        print("\nFix: run tools/clean-invisibles.py or add HEX-OF validation in COBOL.")
        print("Ref: CVE-2021-42574 (Trojan Source), Glassworm March 2026")
        sys.exit(1)
    else:
        print("[OK] No invisible Unicode found.")
        sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
