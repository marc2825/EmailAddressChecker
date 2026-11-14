# Release procedure

Version 0.1.0 is prepared locally, not published. This procedure requires explicit
owner actions; the implementation task does not push, create a Release, change
repository visibility, execute Actions or upload to either index.

## Distribution identity

- PyPI distribution: `email-address-checker`.
- Import: `emailcheck`; CLI: `emailcheck` and `python -m emailcheck`.
- Single version source: `src/emailcheck/__init__.py`, read by Hatchling.
- Name checks on 2026-10-22: PyPI JSON endpoints for `email-address-checker`,
  `marc2825-email-address-checker`, and the old `emailcheck` all returned HTTP 404.
  This indicates no visible project at that time, not reservation/guaranteed
  availability. Recheck name policy and register the pending publisher before use.

## Required owner configuration

1. Review source, the local report, dataset limitations, license and history scan.
   Internal development material (prompts, plans, agent configuration) was
   removed from the entire history before publication. Secret scans cannot
   establish complete absence of confidential prose, so review new history too.
   Test TLS keys are intentional public fixtures.
2. Create GitHub Environments **pypi** and **testpypi**. Set required human
   reviewers, prevent self-review and disable administrative bypass. Restrict
   deployment to protected `v*` tags; restrict who can create those tags.
   Check that the account/repository plan supports required reviewers. An
   environment name in YAML alone does not enable approval protection.
3. In PyPI and TestPyPI separately, configure a pending GitHub Trusted Publisher:
   project `email-address-checker`, owner `marc2825`, repository
   `EmailAddressChecker`, workflow filename `release.yml`, and matching
   environment name (`pypi` or `testpypi`). No long-lived API token is used.
4. Only after both protection and publisher configuration are verified, set the
   repository variable `PUBLISH_ENABLED=true`. Without it the publish job is
   skipped. Do not enable it if human approval protection is unavailable.
5. Review/commit changes, run CI, and create/push `v0.1.0` **only after approval**.
   Tag runs target PyPI; for TestPyPI, dispatch the release workflow on the same
   matching tag with target `testpypi`. Every run rebuilds and requires its tag to
   equal the package version. Do not reuse an already published version.
6. Inspect all Linux tests and Linux/Windows install jobs, dependency/secret scans,
   and the exact `distributions` artifact before approving the Environment job.
   The publish job downloads the artifact from its own run, checks out no source,
   and has OIDC permission only in that job. It does not create GitHub Releases.
7. After upload, verify PyPI metadata, install using pip/uv/pipx from the index,
   check module/CLI and datasets, then mark the changelog as released.

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

Fresh install environments use the chosen interpreter and are removed afterwards.
The wheel and sdist are installed separately outside the repository. Installation
may download build/runtime dependencies; smoke commands themselves use invalid
syntax inputs or offline generation/version reports and do not contact DNS/SMTP.
Windows CI tests actual installs and command behavior; full guarded SMTP loopback
pytest runs on Linux. Python 3.15/free-threaded builds are not yet validated.

The scanner is checksum-pinned to Gitleaks 8.30.1. Its exceptions are narrow:
public test TLS key paths; the fixed schema idempotency example; and a test passing
an idempotency variable. These are not deployment credentials. New findings block
CI and need review, not broad path exclusions.

Sources: [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[GitHub Environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments),
[Python packaging metadata](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/).
