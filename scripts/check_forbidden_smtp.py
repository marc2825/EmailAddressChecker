from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [
    ROOT / "src" / "emailcheck" / "adapters" / "smtp",
    ROOT / "src" / "emailcheck" / "domain" / "smtp_contract.py",
]

# Constructed to avoid embedding a forbidden command token as one literal in
# the protocol implementation tree.
FORBIDDEN_COMMANDS = {
    "DA" + "TA",
    "VR" + "FY",
    "EX" + "PN",
}


def iter_python_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if root.is_file():
            files.append(root)
        elif root.exists():
            files.extend(sorted(root.rglob("*.py")))
    return files


def scan_file(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    findings: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.strip().upper()
            if value in FORBIDDEN_COMMANDS:
                findings.append(f"{path}:{node.lineno}: forbidden SMTP command literal {value!r}")
        elif isinstance(node, ast.Name):
            if node.id.upper() in FORBIDDEN_COMMANDS:
                findings.append(f"{path}:{node.lineno}: forbidden SMTP identifier {node.id!r}")
        elif isinstance(node, ast.Attribute) and node.attr.upper() in FORBIDDEN_COMMANDS:
            findings.append(f"{path}:{node.lineno}: forbidden SMTP attribute {node.attr!r}")

    return findings


def main() -> int:
    findings: list[str] = []
    for path in iter_python_files():
        findings.extend(scan_file(path))

    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1

    print("SMTP invariant scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
