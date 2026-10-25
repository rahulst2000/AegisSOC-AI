#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

# Patterns to detect potential secrets
SECRET_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "API Key"),
    (r"(?i)secret[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "Secret Key"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password"),
    (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
]

EXCLUDE_DIRS = {
    ".git",
    ".pytest_cache",
    "node_modules",
    "dist",
    ".ruff_cache",
    "__pycache__",
    ".venv",
}
EXCLUDE_FILES = {".env", "package-lock.json", ".git"}

# Allowed placeholders and false-positive test values
ALLOWED_STRINGS = [
    "DEMO_PASSWORD=<configure locally>",
    "change-this-in-production-generate-with-openssl-rand-hex-32",
    "ci-environment-testing-secret-key-32-chars-long",
    "test-jwt-secret-key-at-least-32-chars-long-secure!",
    "ci_test_password_not_for_prod",
    "your_gemini_api_key_here",
    "SuperSecurePassword123!",
    "CorrectHorseBatteryStaple99!",
    "OriginalPassword123!",
    "test-mock-fake-gemini-key-for-testing-only-12345",
    "test-live-synthetic-mock-key-12345",
    'password_hash="dummy"',
]


def scan_file(filepath: Path) -> list:
    issues = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return issues

    for line_num, line in enumerate(content.splitlines(), start=1):
        if any(allowed in line for allowed in ALLOWED_STRINGS):
            continue
        for pattern, name in SECRET_PATTERNS:
            if re.search(pattern, line):
                # Check if it's documentation or example
                if (
                    "your_" in line.lower()
                    or "example" in line.lower()
                    or "<configure" in line
                ):
                    continue
                issues.append((line_num, name, line.strip()))
    return issues


def main():
    root = Path(".")
    total_files = 0
    total_issues = 0

    print("[*] Running comprehensive repository secret scan...")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for f in filenames:
            if f in EXCLUDE_FILES:
                continue
            path = Path(dirpath) / f
            total_files += 1
            issues = scan_file(path)
            if issues:
                for line_num, name, line in issues:
                    print(f"[-] {path}:{line_num} Potential {name}: {line[:80]}")
                    total_issues += 1

    print(f"[*] Scanned {total_files} files.")
    if total_issues == 0:
        print("[+] Secret Scan: PASS — 0 secrets or real credentials found.")
        sys.exit(0)
    else:
        print(f"[-] Secret Scan: FAIL — {total_issues} issues identified.")
        sys.exit(1)


if __name__ == "__main__":
    main()
