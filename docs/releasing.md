# Release procedure

Version 0.1.0 is prepared but not published. Publishing needs the explicit owner actions below; nothing in the repository pushes tags, creates Releases, changes repository visibility, or uploads to an index on its own.

## Distribution identity

- PyPI distribution: `email-address-checker`.
- Import name `emailcheck`; CLI `emailcheck` and `python -m emailcheck`.
- One version source: `src/emailcheck/__init__.py`, read by Hatchling.
- On 2026-10-22 the PyPI JSON endpoints for `email-address-checker`, `marc2825-email-address-checker`, and the old name `emailcheck` all returned HTTP 404. That showed no visible project at the time; it does not reserve or guarantee a name. Check the name policy again and register the pending publisher before use.

## Owner configuration

1. Review the source, the release report, dataset limitations, the licence, and the history scan. Internal development material (prompts, plans, agent configuration) was removed from the whole history before publication. A secret scan cannot prove that no confidential prose remains, so review new history too. The test TLS keys are intentional public fixtures.
2. Create the GitHub Environments `pypi` and `testpypi` with required human reviewers, self-review prevented, and administrative bypass disabled. Restrict deployment to protected `v*` tags and restrict who can create them. Check that the account plan supports required reviewers; an environment name in YAML does not enable protection by itself.
3. On PyPI and on TestPyPI, configure a pending GitHub Trusted Publisher: project `email-address-checker`, owner `marc2825`, repository `EmailAddressChecker`, workflow `release.yml`, and the matching environment (`pypi` or `testpypi`). No long-lived API token is used.
4. Only after protection and publishers are verified, set the repository variable `PUBLISH_ENABLED=true`. Without it the publish job is skipped. Do not set it if human approval protection is unavailable.
5. After approval, commit, run CI, and push the tag `v0.1.0`. A tag run targets PyPI; for TestPyPI, dispatch the release workflow on the same tag with target `testpypi`. Every run rebuilds the distributions and requires the tag to equal the package version. Never reuse a published version.
6. Before approving the Environment job, inspect the Linux tests, the Linux and Windows install jobs, the dependency and secret scans, and the `distributions` artifact. The publish job downloads the artifact from its own run, checks out no source, holds OIDC permission only in that job, and creates no GitHub Release.
7. After upload, check the PyPI metadata, install from the index with pip, uv, and pipx, check the module, CLI, and datasets, and mark the changelog entry as released.

## Local commands

```bash
python -m pip install -e '.[dev,release]'
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python scripts/check_forbidden_smtp.py
python -m build
python -m twine check dist/*
python scripts/check_artifacts.py --extract /tmp/emailcheck-artifacts
python scripts/smoke_distribution.py
python -m pip_audit --skip-editable
gitleaks git --log-opts=--all --redact
gitleaks dir /tmp/emailcheck-artifacts --config .gitleaks.toml --redact
```

The smoke test installs the wheel and the sdist separately into fresh environments outside the repository, using the chosen interpreter, and removes them afterwards. Installation may download build and runtime dependencies; the smoke commands themselves use invalid-syntax inputs, offline generation, and version reports, and contact neither DNS nor SMTP. Windows CI tests real installs and commands; the full pytest suite with the guarded SMTP loopback runs on Linux. Python 3.15 and free-threaded builds are not validated yet.

Gitleaks is pinned to 8.30.1 by checksum. Its exceptions are narrow: the public test TLS key paths, the fixed idempotency example in the schema, and one test that passes an idempotency variable. None is a deployment credential. A new finding blocks CI and needs review, not a broader path exclusion.

References: [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/), [GitHub Environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments), [Python packaging metadata](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/).
