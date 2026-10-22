"""Inspect the actual wheel/sdist, optionally extract for independent secret scans."""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

DATA = {
    "disposable_domains.toml",
    "free_mail_domains.toml",
    "role_local_parts.toml",
    "provider_mx_patterns.toml",
    "overrides.toml",
}
FORBIDDEN = {
    ".git",
    ".aws",
    ".codex",
    ".agents",
    ".venv",
    "__pycache__",
    ".env",
    "prompts",
    "plans",
}


def inspect_artifacts(directory: Path, extract: Path | None = None) -> None:
    artifacts = sorted([*directory.glob("*.whl"), *directory.glob("*.tar.gz")])
    if len(artifacts) != 2 or sum(p.suffix == ".whl" for p in artifacts) != 1:
        raise ValueError("expected exactly one wheel and one sdist")
    versions = set()
    for artifact in artifacts:
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as wheel:
                content = {
                    name: wheel.read(name) for name in wheel.namelist() if not name.endswith("/")
                }
            metadata = next(
                data for name, data in content.items() if name.endswith(".dist-info/METADATA")
            )
            assert not any(name.endswith((".key", ".crt", ".toml.example")) for name in content)
        else:
            with tarfile.open(artifact) as archive:
                assert all(member.isfile() or member.isdir() for member in archive)
                content = {}
                for member in archive:
                    if member.isfile():
                        handle = archive.extractfile(member)
                        assert handle is not None
                        content[member.name] = handle.read()
            metadata = next(data for name, data in content.items() if name.endswith("/PKG-INFO"))
        for name, data in content.items():
            path = PurePosixPath(name)
            assert not path.is_absolute() and ".." not in path.parts
            assert not FORBIDDEN.intersection(path.parts), name
            assert not name.endswith((".sqlite", ".sqlite3", ".db", ".pyc", ".log")), name
            assert len(data) < 8 * 1024 * 1024, name
            if extract:
                destination = extract / artifact.name / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        assert {PurePosixPath(name).name for name in content if "/data/passive/" in name} >= DATA
        message = email.parser.BytesParser().parsebytes(metadata)
        assert message["Name"] == "email-address-checker"
        assert message["Requires-Python"] == ">=3.12"
        assert message["License-Expression"] == "Apache-2.0"
        versions.add(message["Version"])
        print(
            f"{artifact.name}: {len(content)} files; "
            f"sha256={hashlib.sha256(artifact.read_bytes()).hexdigest()}"
        )
    assert len(versions) == 1
    from emailcheck import __version__

    assert versions == {__version__}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--extract", type=Path)
    args = parser.parse_args()
    inspect_artifacts(args.dist, args.extract)
