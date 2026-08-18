"""Loading passive datasets, and refusing the ones that cannot be trusted.

A dataset is remote-authored data that decides what this project publishes about
a domain, so the loader fails closed. A file that is oversized, duplicated,
self-contradictory, or of an unknown schema version is rejected outright rather
than partially applied: half a disposable list is worse than none, because the
misses look like clean answers.

Every domain goes through the same normalization the address layer uses, so a
list written with a trailing dot, in upper case, or in Unicode form matches the
same domain a user typed.
"""

from __future__ import annotations

import hashlib
import tomllib
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import idna

from emailcheck.domain.address import ascii_domain_issue, local_part_issue
from emailcheck.domain.passive import ProviderFamily, ProviderPattern, RoleName

#: The only schema this loader understands. A file declaring anything else is
#: rejected: silently reading unknown fields is how a format change becomes a
#: classification change.
SUPPORTED_SCHEMA_VERSION: Final = 1

#: Bounds that keep a hostile or accidental file from exhausting memory.
MAX_DATASET_BYTES: Final = 8 * 1024 * 1024
MAX_DATASET_ENTRIES: Final = 200_000

#: A metadata value is a URL, a version, an SPDX identifier, a checksum, or a
#: sentence describing a normalization rule. This is generous for all of those
#: and far too small for anything smuggled through provenance into evidence.
MAX_METADATA_VALUE_LENGTH: Final = 512

#: Exactly the fields `docs/data-sources.md` requires.
REQUIRED_METADATA_FIELDS: Final = (
    "name",
    "source_url",
    "license",
    "version",
    "retrieved_at",
    "checksum",
    "normalization",
    "update_frequency",
    "maintainer",
)

#: Fields every dataset document carries, whatever its kind.
COMMON_TOP_LEVEL_FIELDS: Final = frozenset({"schema_version", "kind", "metadata"})

#: Unicode categories a metadata value may not contain. `Cc` is C0/C1 and DEL,
#: `Cf` is the format characters including the bidirectional overrides, and
#: `Zl`/`Zp` are the line and paragraph separators. `Zs` is deliberately absent:
#: an ordinary space is not a control character.
_DISALLOWED_METADATA_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp"})


class DatasetError(ValueError):
    """A dataset file cannot be trusted and was not loaded.

    Its message is written here and names the field at fault. A parser's or a
    library's own wording is never copied into it: that text is not this
    project's vocabulary, and a dataset failure is reported to an operator.
    """


def _metadata_value_problem(value: str) -> str | None:
    """Return why a metadata value is unusable, or None.

    A metadata value travels further than any other part of a dataset: it
    becomes `Evidence.source_version` and can end up in a response or a log
    line. A value that can break a line, terminate a string, or reorder the
    text around it is refused before it can get there.
    """
    if len(value) > MAX_METADATA_VALUE_LENGTH:
        return "is longer than the configured limit"
    for char in value:
        if char in "\r\n\x00":
            return "contains a line break or NUL"
        if unicodedata.category(char) in _DISALLOWED_METADATA_CATEGORIES:
            return "contains a control or format character"
    return None


@dataclass(frozen=True, slots=True)
class DatasetMetadata:
    """Provenance for one dataset snapshot.

    Every field is mandatory. A dataset whose licence or source is unknown must
    not be loaded at all, so there is no way to express "unspecified" here.

    Each value is validated on construction rather than only at load time, so a
    metadata string that could break a log line or a response cannot exist even
    if a future caller builds one directly.
    """

    name: str
    source_url: str
    license: str
    version: str
    retrieved_at: str
    checksum: str
    normalization: str
    update_frequency: str
    maintainer: str

    def __post_init__(self) -> None:
        for field_name in REQUIRED_METADATA_FIELDS:
            problem = _metadata_value_problem(getattr(self, field_name))
            if problem is not None:
                raise DatasetError(f"dataset metadata field {field_name!r} {problem}")


#: How many hex characters of a content digest each dataset publishes.
#:
#: A prefix rather than the whole SHA-256: this value goes into a cache key, a
#: stored row, and an operator's version report, and 32 hex characters is far
#: past the point where two configured snapshots collide.
CONTENT_DIGEST_LENGTH: Final = 32


def content_digest(kind: str, *groups: Iterable[str]) -> str:
    """A deterministic digest of one dataset's effective contents.

    **Length-framed, never concatenated.** Each entry is written as its UTF-8
    byte length, a colon, and the entry, and each group ends with a marker that
    cannot appear in a framed entry. Plain joining with a separator is what
    creates structural collisions: `{"a.b", "c"}` and `{"a", "b.c"}` share a
    naive `.`-joined form, and two datasets whose contents differ would then
    share an identity.

    **Sorted, because these datasets are sets.** `frozenset` has no order and a
    file's line order carries no meaning, so two files listing the same domains
    differently are the same dataset and must digest the same. A dataset whose
    order *did* matter would pass its entries already ordered and must not use
    this helper's sorting for that group.

    `kind` is the semantic dataset name, so two datasets that happen to hold the
    same strings — a domain list and a role list both containing `support` —
    do not share a digest.
    """
    hasher = hashlib.sha256()
    hasher.update(f"{len(kind)}:{kind}\x00".encode())
    for group in groups:
        for entry in sorted(group):
            hasher.update(f"{len(entry.encode())}:".encode())
            hasher.update(entry.encode())
        hasher.update(b"\x01")
    return hasher.hexdigest()[:CONTENT_DIGEST_LENGTH]


@dataclass(frozen=True, slots=True)
class DomainDataset:
    """A set of normalized ASCII domains."""

    metadata: DatasetMetadata
    domains: frozenset[str]

    def contains(self, ascii_domain: str) -> bool:
        return ascii_domain in self.domains

    @property
    def content_fingerprint(self) -> str:
        """This dataset's identity, computed from what it actually holds.

        **Not the declared version, and not the declared checksum.** A version
        is a string an operator types and may forget to change; a checksum is a
        string the file declares and this loader does not verify. Either can say
        "unchanged" about a file that was edited, and the final system audit
        measured exactly that: two role lists with one entry each and the same
        version collided, so a cached verdict computed under the first was
        served under the second with the wrong risk flags.
        """
        return content_digest("domain", self.domains)

    @property
    def size(self) -> int:
        return len(self.domains)


@dataclass(frozen=True, slots=True)
class LocalPartDataset:
    """A set of lower-case role local parts."""

    metadata: DatasetMetadata
    local_parts: frozenset[str]

    def contains(self, comparison_form: str) -> bool:
        return comparison_form in self.local_parts

    @property
    def content_fingerprint(self) -> str:
        """This dataset's identity, from its entries. See `DomainDataset`."""
        return content_digest("local_part", self.local_parts)

    def canonical(self, comparison_form: str) -> RoleName | None:
        """Return the dataset's own entry for this comparison form, or None.

        A `RoleName` can only be obtained this way, so a role match always names
        something the dataset published rather than something a user submitted.
        """
        if comparison_form not in self.local_parts:
            return None
        return RoleName(comparison_form)

    @property
    def size(self) -> int:
        return len(self.local_parts)


@dataclass(frozen=True, slots=True)
class ProviderPatternDataset:
    """MX suffix rules, kept as data so no provider list lives in code."""

    metadata: DatasetMetadata
    patterns: tuple[ProviderPattern, ...]

    @property
    def size(self) -> int:
        return len(self.patterns)

    @property
    def content_fingerprint(self) -> str:
        """Every field of every rule that can change a classification.

        A pattern's family and suffix both decide what it matches and what it
        answers, so both are in the digest. `evidence` is a note for a human and
        is included too: it costs nothing and leaving it out would mean two
        provider files a reviewer can tell apart share one identity.
        """
        return content_digest(
            "provider",
            (
                f"{pattern.family.value}|{pattern.suffix}|{pattern.evidence}"
                for pattern in self.patterns
            ),
        )


class OverrideTarget(StrEnum):
    """Which classification an override file corrects.

    Only the disposable list has one today. A file naming any other target is
    rejected rather than loaded and ignored, so adding free-mail overrides later
    is a deliberate change here and not a silent behavior change in a data file.
    """

    DISPOSABLE = "disposable"


#: The entry arrays an override file must declare, derived from its target. The
#: names say what the override asserts about membership of that list, never
#: whether mail may be delivered: this project also has an allow/deny vocabulary
#: for destination addresses, and the two must not read alike.
OVERRIDE_ENTRY_FIELDS: Final[dict[OverrideTarget, tuple[str, str]]] = {
    OverrideTarget.DISPOSABLE: ("not_disposable", "disposable"),
}

#: The field names an earlier draft used. They are rejected by name rather than
#: as merely unknown, because `allow` and `deny` read as a delivery decision.
LEGACY_OVERRIDE_FIELDS: Final = ("allow", "deny")


@dataclass(frozen=True, slots=True)
class OverrideDataset:
    """Local corrections applied on top of a list.

    An override always wins over the dataset, which is how a false positive is
    fixed without editing a vendored file or the source code.

    `not_disposable` asserts that a domain is not disposable even though the
    upstream list says it is. `disposable` asserts the opposite. Neither says
    anything about whether mail to that domain may be sent or accepted.
    """

    metadata: DatasetMetadata
    not_disposable: dict[str, str]
    disposable: dict[str, str]
    target: OverrideTarget = OverrideTarget.DISPOSABLE

    @property
    def content_fingerprint(self) -> str:
        """Both correction lists and the target they correct.

        Two groups rather than one merged set: a domain moving from
        `not_disposable` to `disposable` inverts the answer, and a digest that
        merged them would not notice.
        """
        return content_digest(
            f"override:{self.target.value}",
            (f"{domain}|{reason}" for domain, reason in self.not_disposable.items()),
            (f"{domain}|{reason}" for domain, reason in self.disposable.items()),
        )

    def override_for(self, ascii_domain: str) -> tuple[bool, str] | None:
        """Return `(matched, reason)` when an override decides this domain."""
        if ascii_domain in self.not_disposable:
            return False, self.not_disposable[ascii_domain]
        if ascii_domain in self.disposable:
            return True, self.disposable[ascii_domain]
        return None


EMPTY_METADATA: Final = DatasetMetadata(
    name="empty",
    source_url="",
    license="",
    version="empty",
    retrieved_at="",
    checksum="",
    normalization="",
    update_frequency="",
    maintainer="",
)

EMPTY_DOMAIN_DATASET: Final = DomainDataset(metadata=EMPTY_METADATA, domains=frozenset())
EMPTY_LOCAL_PART_DATASET: Final = LocalPartDataset(metadata=EMPTY_METADATA, local_parts=frozenset())
EMPTY_PROVIDER_DATASET: Final = ProviderPatternDataset(metadata=EMPTY_METADATA, patterns=())
EMPTY_OVERRIDE_DATASET: Final = OverrideDataset(
    metadata=EMPTY_METADATA, not_disposable={}, disposable={}
)


def normalize_dataset_domain(raw: str) -> str:
    """Return the ASCII form a dataset entry must be compared in.

    The address layer's rules are reused deliberately: a list entry and a user's
    domain have to normalize identically or a match becomes a coin flip.
    """
    candidate = raw.strip().rstrip(".")
    if not candidate:
        raise DatasetError("a dataset domain cannot be empty")
    if candidate.startswith("[") or candidate.endswith("]"):
        raise DatasetError(f"a dataset domain cannot be an address literal: {candidate!r}")
    if any(ord(char) > 0x7F for char in candidate):
        try:
            candidate = idna.encode(candidate, uts46=True, transitional=False).decode("ascii")
        except UnicodeError as error:
            raise DatasetError(f"a dataset domain cannot be encoded: {candidate!r}") from error
    else:
        candidate = candidate.lower()
    if _looks_like_ip_literal(candidate):
        raise DatasetError(f"a dataset domain cannot be an IP address: {candidate!r}")
    issue = ascii_domain_issue(candidate)
    if issue is not None:
        raise DatasetError(f"a dataset domain is not a usable hostname: {candidate!r}")
    return candidate


def _looks_like_ip_literal(candidate: str) -> bool:
    """Reject a bare IPv4 address written where a hostname belongs."""
    labels = candidate.split(".")
    return len(labels) == 4 and all(label.isdigit() for label in labels)


def _unicode_key(value: str) -> str:
    """A key that collapses entries differing only by Unicode normalization."""
    return unicodedata.normalize("NFC", value)


def _read_document(text: str, *, expected_kind: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > MAX_DATASET_BYTES:
        raise DatasetError("dataset file is larger than the configured limit")
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise DatasetError("dataset file is not valid TOML") from error

    schema_version = document.get("schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise DatasetError(f"unsupported dataset schema version: {schema_version!r}")
    kind = document.get("kind")
    if kind != expected_kind:
        raise DatasetError(f"expected a {expected_kind!r} dataset, found {kind!r}")
    return document


def _reject_unknown_top_level_fields(document: dict[str, Any], allowed: frozenset[str]) -> None:
    """Close the document schema, the way the metadata table is already closed.

    A misspelled field is the failure this guards against. Ignoring it would
    leave a typo indistinguishable from a deliberate omission, and combined with
    a missing entry array it would load a silently empty list.
    """
    unknown = sorted(set(document) - COMMON_TOP_LEVEL_FIELDS - allowed)
    if unknown:
        raise DatasetError(f"dataset file has unknown top-level fields: {unknown}")


def _read_metadata(document: dict[str, Any]) -> DatasetMetadata:
    raw = document.get("metadata")
    if not isinstance(raw, dict):
        raise DatasetError("dataset file has no metadata table")
    missing = [field for field in REQUIRED_METADATA_FIELDS if field not in raw]
    if missing:
        raise DatasetError(f"dataset metadata is missing required fields: {sorted(missing)}")
    unknown = sorted(set(raw) - set(REQUIRED_METADATA_FIELDS))
    if unknown:
        raise DatasetError(f"dataset metadata has unknown fields: {unknown}")
    values: dict[str, str] = {}
    for field_name in REQUIRED_METADATA_FIELDS:
        value = raw[field_name]
        if not isinstance(value, str):
            raise DatasetError(f"dataset metadata field {field_name!r} must be a string")
        values[field_name] = value
    if not values["name"] or not values["version"]:
        raise DatasetError("dataset metadata needs at least a name and a version")
    return DatasetMetadata(**values)


def _read_entries(document: dict[str, Any], key: str) -> list[Any]:
    """Read a required entry array.

    The key is mandatory even when the dataset is empty. A missing key and an
    empty array look identical once loaded, and three of the files this project
    ships are legitimately empty, so a typo in an entry array would produce a
    dataset that classifies nothing and looks exactly like the intended state.
    An empty dataset says so with `key = []`.
    """
    if key not in document:
        raise DatasetError(
            f"dataset file declares no {key!r} array; an empty dataset must write {key} = []"
        )
    entries = document[key]
    if not isinstance(entries, list):
        raise DatasetError(f"dataset field {key!r} must be a list")
    if len(entries) > MAX_DATASET_ENTRIES:
        raise DatasetError("dataset has more entries than the configured limit")
    return entries


def load_domain_dataset(text: str, *, kind: str) -> DomainDataset:
    """Load a list of domains, rejecting duplicates and unusable entries."""
    document = _read_document(text, expected_kind=kind)
    _reject_unknown_top_level_fields(document, frozenset({"domains"}))
    metadata = _read_metadata(document)

    domains: dict[str, str] = {}
    for entry in _read_entries(document, "domains"):
        if not isinstance(entry, str):
            raise DatasetError(f"a domain entry must be a string, found {type(entry).__name__}")
        normalized = normalize_dataset_domain(entry)
        key = _unicode_key(normalized)
        if key in domains:
            raise DatasetError(f"duplicate domain entry: {normalized!r}")
        domains[key] = normalized
    return DomainDataset(metadata=metadata, domains=frozenset(domains.values()))


def load_role_dataset(text: str) -> LocalPartDataset:
    """Load role local parts, each of which must be a usable dot-atom."""
    document = _read_document(text, expected_kind="role_local_parts")
    _reject_unknown_top_level_fields(document, frozenset({"local_parts"}))
    metadata = _read_metadata(document)

    parts: dict[str, str] = {}
    for entry in _read_entries(document, "local_parts"):
        if not isinstance(entry, str):
            raise DatasetError("a role entry must be a string")
        candidate = entry.strip().lower()
        if not candidate:
            raise DatasetError("a role entry cannot be empty")
        if local_part_issue(candidate) is not None:
            raise DatasetError(f"a role entry is not a usable local part: {candidate!r}")
        if "+" in candidate:
            # A tag is dropped before the lookup, so such an entry could never
            # match anything. Silently keeping it would look like coverage.
            raise DatasetError(f"a role entry cannot carry a tag: {candidate!r}")
        key = _unicode_key(candidate)
        if key in parts:
            raise DatasetError(f"duplicate role entry: {candidate!r}")
        parts[key] = candidate
    return LocalPartDataset(metadata=metadata, local_parts=frozenset(parts.values()))


def load_provider_dataset(text: str) -> ProviderPatternDataset:
    """Load MX suffix rules, rejecting wildcards and contradictory mappings."""
    document = _read_document(text, expected_kind="provider_mx_patterns")
    _reject_unknown_top_level_fields(document, frozenset({"patterns"}))
    metadata = _read_metadata(document)

    seen: dict[str, ProviderFamily] = {}
    patterns: list[ProviderPattern] = []
    for entry in _read_entries(document, "patterns"):
        if not isinstance(entry, dict):
            raise DatasetError("a provider pattern must be a table")
        unknown = sorted(set(entry) - {"family", "suffix", "evidence"})
        if unknown:
            raise DatasetError(f"a provider pattern has unknown columns: {unknown}")
        missing = sorted({"family", "suffix"} - set(entry))
        if missing:
            raise DatasetError(f"a provider pattern is missing columns: {missing}")

        raw_suffix = entry["suffix"]
        if not isinstance(raw_suffix, str):
            raise DatasetError("a provider suffix must be a string")
        if "*" in raw_suffix:
            raise DatasetError(
                "wildcards are not supported: a suffix already matches every subdomain"
            )
        suffix = normalize_dataset_domain(raw_suffix)

        raw_family = entry["family"]
        if not isinstance(raw_family, str):
            raise DatasetError("a provider family must be a string")
        try:
            family = ProviderFamily(raw_family)
        except ValueError as error:
            raise DatasetError(f"unknown provider family: {raw_family!r}") from error
        if family in {ProviderFamily.UNKNOWN, ProviderFamily.OTHER}:
            raise DatasetError(f"a pattern cannot map to {family.value!r}")

        if suffix in seen and seen[suffix] is not family:
            raise DatasetError(f"conflicting provider mapping for suffix {suffix!r}")
        if suffix in seen:
            raise DatasetError(f"duplicate provider suffix: {suffix!r}")
        seen[suffix] = family

        evidence = entry.get("evidence", "")
        if not isinstance(evidence, str):
            raise DatasetError("provider evidence must be a string")
        patterns.append(ProviderPattern(family=family, suffix=suffix, evidence=evidence))

    return ProviderPatternDataset(metadata=metadata, patterns=tuple(patterns))


def load_override_dataset(text: str) -> OverrideDataset:
    """Load local corrections, rejecting a domain that is corrected both ways.

    The file names the classification it corrects, and its two entry arrays are
    named after the membership they assert: `not_disposable` and `disposable`.
    An older draft called them `allow` and `deny`, which read as a decision
    about delivering mail; such a file is refused by name rather than half-read.
    """
    document = _read_document(text, expected_kind="overrides")

    legacy = sorted(name for name in LEGACY_OVERRIDE_FIELDS if name in document)
    if legacy:
        raise DatasetError(
            f"override fields {legacy} were renamed: write 'not_disposable' and "
            "'disposable', which describe list membership rather than delivery"
        )

    raw_target = document.get("target")
    if not isinstance(raw_target, str):
        raise DatasetError("an override file must name the classification it targets")
    try:
        override_target = OverrideTarget(raw_target)
    except ValueError as error:
        supported = sorted(item.value for item in OverrideTarget)
        raise DatasetError(
            f"unsupported override target: {raw_target!r}; supported targets are {supported}"
        ) from error

    off_field, on_field = OVERRIDE_ENTRY_FIELDS[override_target]
    _reject_unknown_top_level_fields(document, frozenset({"target", off_field, on_field}))
    metadata = _read_metadata(document)

    not_matched: dict[str, str] = {}
    matched: dict[str, str] = {}
    for key, collected in ((off_field, not_matched), (on_field, matched)):
        for entry in _read_entries(document, key):
            if not isinstance(entry, dict):
                raise DatasetError(f"a {key!r} override must be a table")
            unknown = sorted(set(entry) - {"domain", "reason"})
            if unknown:
                raise DatasetError(f"an override has unknown columns: {unknown}")
            if "domain" not in entry or "reason" not in entry:
                raise DatasetError("an override needs a domain and a reason")
            raw_domain = entry["domain"]
            reason = entry["reason"]
            if not isinstance(raw_domain, str) or not isinstance(reason, str):
                raise DatasetError("an override domain and reason must be strings")
            if not reason.strip():
                raise DatasetError("an override must record why it exists")
            domain = normalize_dataset_domain(raw_domain)
            if domain in collected:
                raise DatasetError(f"duplicate override for {domain!r}")
            collected[domain] = reason

    conflicting = sorted(set(not_matched) & set(matched))
    if conflicting:
        raise DatasetError(f"a domain cannot be corrected in both directions: {conflicting}")
    return OverrideDataset(
        metadata=metadata,
        not_disposable=not_matched,
        disposable=matched,
        target=override_target,
    )


def read_text(path: Path) -> str:
    """Read a dataset file, refusing one that is too large to be sane."""
    if not path.is_file():
        raise DatasetError(f"dataset file not found: {path.name}")
    if path.stat().st_size > MAX_DATASET_BYTES:
        raise DatasetError(f"dataset file is too large: {path.name}")
    return path.read_text(encoding="utf-8")
