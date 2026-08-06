# Dataset policy

## 1. Initial data categories

- disposable domains;
- free-mail domains;
- role local parts;
- provider MX patterns.

No dataset is included in the starter beyond illustrative placeholders.

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
