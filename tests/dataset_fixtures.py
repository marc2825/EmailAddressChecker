"""Helpers for building dataset files in tests, without touching disk."""

METADATA_BLOCK = """
[metadata]
name = "test"
source_url = "https://example.invalid/list"
license = "test fixture, not redistributed"
version = "test-1"
retrieved_at = "2026-08-07"
checksum = "sha256:fixture"
normalization = "trim, lower-case, IDNA"
update_frequency = "never; fixture"
maintainer = "tests"
"""


def domain_dataset_text(kind: str, *domains: str, version: str = "test-1") -> str:
    entries = ",\n  ".join(f'"{domain}"' for domain in domains)
    metadata = METADATA_BLOCK.replace('version = "test-1"', f'version = "{version}"')
    return f"""
schema_version = 1
kind = "{kind}"
domains = [
  {entries}
]
{metadata}
"""


def role_dataset_text(*local_parts: str, version: str = "test-1") -> str:
    entries = ",\n  ".join(f'"{part}"' for part in local_parts)
    metadata = METADATA_BLOCK.replace('version = "test-1"', f'version = "{version}"')
    return f"""
schema_version = 1
kind = "role_local_parts"
local_parts = [
  {entries}
]
{metadata}
"""


def provider_dataset_text(*rows: tuple[str, str], version: str = "test-1") -> str:
    # An empty dataset writes the array explicitly; the loader requires the key.
    tables = (
        "\n".join(
            f'[[patterns]]\nfamily = "{family}"\nsuffix = "{suffix}"\nevidence = "fixture"\n'
            for family, suffix in rows
        )
        or "patterns = []"
    )
    metadata = METADATA_BLOCK.replace('version = "test-1"', f'version = "{version}"')
    return f"""
schema_version = 1
kind = "provider_mx_patterns"
{tables}
{metadata}
"""


def override_dataset_text(
    not_disposable: tuple[tuple[str, str], ...] = (),
    disposable: tuple[tuple[str, str], ...] = (),
    target: str = "disposable",
) -> str:
    """Build an override file.

    `not_disposable` forces a domain off the disposable list and `disposable`
    forces it on. Both arrays are always written, empty or not, because the
    loader requires them.
    """
    off_rows = "\n".join(
        f'[[not_disposable]]\ndomain = "{domain}"\nreason = "{reason}"\n'
        for domain, reason in not_disposable
    )
    on_rows = "\n".join(
        f'[[disposable]]\ndomain = "{domain}"\nreason = "{reason}"\n'
        for domain, reason in disposable
    )
    empty_arrays = "\n".join(
        f"{name} = []"
        for name, rows in (("not_disposable", off_rows), ("disposable", on_rows))
        if not rows
    )
    return f"""
schema_version = 1
kind = "overrides"
target = "{target}"
{empty_arrays}
{off_rows}
{on_rows}
{METADATA_BLOCK}
"""
