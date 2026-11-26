# Release procedure

Version 0.1.0 is prepared but not published. Publishing needs the owner actions below. Nothing in the repository pushes tags, creates Releases, changes settings, or uploads to an index on its own.

## Distribution identity

- PyPI distribution: `email-address-checker`. Import name and CLI: `emailcheck` (also `python -m emailcheck`).
- One version source: `src/emailcheck/__init__.py`, read by Hatchling.
- The PyPI page is [docs/pypi.md](pypi.md): absolute links pinned to the version tag and no images, because PyPI cannot resolve repository-relative paths. Update its `v0.1.0` links with each version; `tests/test_pypi_description.py` fails otherwise.
- Name check on 2026-11-26: on both PyPI and TestPyPI, `email-address-checker` and its separator variants (`emailaddresschecker`, `email-addresschecker`, `emailaddress-checker`) and `emailcheck` had no project. The nearest existing name is `emailchecker` on PyPI, an unrelated logging tool. A missing project does not reserve a name. PyPI does not reserve import names either: another distribution could also install a module called `emailcheck`. Check again just before registering the pending publisher.

## How a release reaches each index

| Trigger | Index | Extra gate |
| --- | --- | --- |
| Push of tag `v0.1.0` | TestPyPI only | `testpypi` Environment approval |
| Manual run of **Release distributions** on tag `v0.1.0` with `target=pypi` and `confirm=v0.1.0` | PyPI | the typed tag, then `pypi` Environment approval |

Every run first runs the full CI, rebuilds the distributions, requires the tag to equal the package version, and runs `twine check` and `scripts/check_artifacts.py`. The publish job runs only when the repository variable `PUBLISH_ENABLED` is `true`, downloads the artifact from its own run, checks out no source, and alone holds the OIDC permission. Actions are pinned by commit SHA. `tests/test_release_workflow.py` pins these gates.

## Owner configuration

Observed on 2026-11-26: the repository is public; it has no Environments and no variables; private vulnerability reporting is enabled.

1. **Review** the source, the [release report](release-report.md), dataset limitations, the licence, and the history scan. A secret scan cannot prove that no confidential prose remains, so review new history too. The test TLS keys are intentional public fixtures.
2. **Create the Environments** `testpypi` and `pypi`. For each, allow deployments only from tags matching `v*`, add a required reviewer, and disable administrator bypass. Choose how approval works:
   - **Two people (stronger).** Add a second trusted reviewer and turn on "Prevent self-reviews".
   - **One maintainer.** Make yourself the required reviewer and leave self-review allowed. The human decisions are the manual run with the typed tag and the approval click, both recorded in Actions. This is weaker than two people, because one account decides alone.

   If neither is acceptable, do not set `PUBLISH_ENABLED`.
3. **Protect release tags** with a tag ruleset on `refs/tags/v*` that restricts creation, update, and deletion, with only the repository admin role as a bypass actor.
4. **Register pending Trusted Publishers** on TestPyPI and on PyPI: project `email-address-checker`, owner `marc2825`, repository `EmailAddressChecker`, workflow `release.yml`, and the matching environment (`testpypi` or `pypi`). No long-lived API token is used.
5. **Set** the repository variable `PUBLISH_ENABLED=true`.

## Publishing 0.1.0

1. On `main`, with CI green, mark the changelog entry with its date and push tag `v0.1.0`. Approve the `testpypi` deployment after checking the run's tests, install jobs, scans, and the `distributions` artifact.
2. Check the TestPyPI upload in a fresh environment. Install the dependencies from PyPI first and the package alone from TestPyPI, so no dependency is taken from TestPyPI:

   ```bash
   python -m venv /tmp/ec-test && . /tmp/ec-test/bin/activate
   python -m pip install 'dnspython>=2.9.2,<3' 'idna>=3.10,<4'
   python -m pip install --no-deps --index-url https://test.pypi.org/simple/ email-address-checker==0.1.0
   emailcheck --version && emailcheck explain && emailcheck check 'not an address'
   ```

3. Run **Release distributions** manually on tag `v0.1.0` with `target=pypi` and `confirm=v0.1.0`, then approve the `pypi` deployment.
4. Install from PyPI with `pipx install email-address-checker`, `uv tool install email-address-checker`, and `pip install email-address-checker`, and check the CLI and the datasets (`emailcheck versions`). A GitHub Release is optional and made by hand. Never reuse a published version.

## Repository protection

Observed on 2026-11-26 in the ruleset "main protection": deletion and non-fast-forward pushes are blocked, and the required checks are `check (3.12)`, `check (3.13)`, `check (3.14)`, and `security`. `check (3.12)` is listed twice, once without an app, and that entry accepts a status with the same name from any source. The `distribution` jobs are not required.

Proposed, for the owner to apply:

- Keep each required check once, bound to GitHub Actions, and add the `distribution` jobs, so an install failure on Windows or macOS blocks a merge.
- Do not require a pull-request review while there is one maintainer: GitHub does not let an author approve their own pull request, so every merge would need a bypass.

## Local commands

```bash
python -m pip install -e '.[dev,release]'
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python scripts/check_forbidden_smtp.py
python -m build
python -m twine check --strict dist/*
python scripts/check_artifacts.py --extract /tmp/emailcheck-artifacts
python scripts/smoke_distribution.py
python -m pip_audit --skip-editable
gitleaks git --log-opts=--all --redact
gitleaks dir /tmp/emailcheck-artifacts --config .gitleaks.toml --redact
```

The smoke test installs the wheel and the sdist separately into fresh environments outside the repository and removes them afterwards. Installation may download dependencies; the smoke commands themselves contact neither DNS nor SMTP. CI runs the install and smoke tests on Linux, Windows, and macOS, and the full pytest suite with the guarded SMTP loopback on Linux. Python 3.15 and free-threaded builds are not validated yet.

Gitleaks is pinned to 8.30.1 by checksum. Its exceptions are narrow: the public test TLS key paths, the fixed idempotency example in the schema, and one test that passes an idempotency variable. None is a deployment credential. A new finding blocks CI and needs review, not a broader path exclusion.

References: [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/), [GitHub Environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments), [Python packaging metadata](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/).
