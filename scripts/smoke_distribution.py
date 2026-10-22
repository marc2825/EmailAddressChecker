"""Install both actual artifacts into independent fresh environments outside the repo."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
import venv
from pathlib import Path


def run(command: list[str], cwd: Path) -> str:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(  # noqa: S603 - explicit argv, never shell text
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def smoke(dist: Path, extras: str = "") -> None:
    artifacts = sorted([*dist.glob("*.whl"), *dist.glob("*.tar.gz")])
    assert len(artifacts) == 2
    for artifact in artifacts:
        with tempfile.TemporaryDirectory(prefix="emailcheck-install-") as temporary:
            root = Path(temporary)
            environment = root / "venv"
            venv.EnvBuilder(with_pip=True).create(environment)
            bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
            python = str(bin_dir / ("python.exe" if os.name == "nt" else "python"))
            specification = str(artifact.resolve()) + (f"[{extras}]" if extras else "")
            run([python, "-m", "pip", "install", specification], root)
            run([python, "-m", "pip", "check"], root)
            version = run([python, "-m", "emailcheck", "--version"], root).strip()
            assert (
                version
                == run(
                    [
                        str(bin_dir / ("emailcheck.exe" if os.name == "nt" else "emailcheck")),
                        "--version",
                    ],
                    root,
                ).strip()
            )
            run(
                [
                    python,
                    "-c",
                    "from importlib.metadata import version; from emailcheck import __version__; "
                    'assert version("email-address-checker") == __version__',
                ],
                root,
            )
            report = run([python, "-m", "emailcheck", "--report-versions", "--json"], root)
            assert "unavailable-by-declaration" in report
            result = run([python, "-m", "emailcheck", "check", "bad", "also-bad"], root)
            assert "invalid_syntax" in result
            generated = run(
                [python, "-m", "emailcheck", "expand", "m**rc@gmail.com", "--dry-run"], root
            )
            assert "676" in generated
            print(
                f"{artifact.name}: isolated install, metadata, datasets, CLI/module, "
                f"passive syntax and offline generation OK ({extras or 'base'})"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--extras", default="")
    args = parser.parse_args()
    smoke(args.dist, args.extras)
