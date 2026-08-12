# Dataset policy

## 1. Initial data categories

- disposable domains;
- free-mail domains;
- role local parts;
- provider MX patterns.

No dataset is included in the starter beyond illustrative placeholders.

`src/emailcheck/data/passive/` holds the current snapshots and `src/emailcheck/data/passive/README.md` records
the state of each one. As of Phase 3, only the role list ships populated: its
entries are authored in this repository, so its provenance is checkable. The
disposable, free-mail, and provider files ship empty because no upstream licence
could be verified, and ADR 0007 records that inventing one was refused.

## 2. Required metadata

Every dataset artifact must have:

```yaml
name:
source_url:
license:
version:
retrieved_at:
checksum:
normalization:
update_frequency:
maintainer:
```

Every field is a string, mandatory, and validated. A value is at most 512
characters and may not contain CR, LF, NUL, another control character, a Unicode
format character such as a bidirectional override, or a line or paragraph
separator. A metadata value becomes `Evidence.source_version` and can reach an
API response or a log line, so it must not be able to break one. Unknown
metadata fields are rejected rather than ignored.

The surrounding document is closed the same way: its entries array is mandatory
even when the dataset is empty (`domains = []`), and an unknown top-level field
fails the load. A typo therefore lands on a missing-key error or an
unknown-field error, never on a silently empty dataset.

## 2.1 Override files

An override file corrects one classification without editing a vendored
snapshot. It declares `target`, and only `"disposable"` is implemented; any
other target is rejected rather than ignored.

Its two arrays are `not_disposable` and `disposable`, named for the membership
they assert. They are not a delivery decision: allow/deny in this project means
the destination policy in `security/destination.py`, and the two vocabularies
are deliberately kept apart. A file using the earlier `allow` and `deny` names
is refused by name. Free-mail overrides are not supported; whether to add them
is decided before that list is populated.

## 3. Update process

1. Retrieve through a reviewed script.
2. Verify source and license.
3. Normalize deterministically.
4. Generate checksum and metadata.
5. Review additions and removals.
6. Run false-positive fixtures.
7. Commit data and metadata together.
8. Do not download mutable lists at application startup.

## 4. Role accounts

Role detection is a risk flag, not an invalid verdict. Keep the list small,
documented, and locale-aware. Avoid classifying common personal names as roles.

## 5. Provider patterns

Provider patterns may select a response parser or metadata label. They may not
produce mailbox validity by themselves.

The list is expected to hold tens of rows, low hundreds at the most: one suffix
covers every subdomain beneath it. Matching is a linear scan, which suits that
size. A submission above 500 rows is reviewed rather than merged, and a genuine
need for a large one means indexing the matcher first.
