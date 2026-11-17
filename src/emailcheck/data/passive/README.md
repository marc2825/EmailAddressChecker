# Passive classification datasets

These files decide what this project says about other people's domains, and a wrong entry labels a real business as disposable, so provenance matters more than coverage. `docs/data-sources.md` is the policy; this file records the state of each dataset.

## Format

One TOML file per dataset, each with `schema_version`, a `kind`, the metadata block required by `docs/data-sources.md`, and its entries. The loader refuses a file with an unknown schema version, missing or unknown metadata fields, duplicate entries, an unusable hostname, an IP literal, a wildcard, a contradictory override, or more entries or bytes than the configured limits.

The schema is closed at both levels, so a typo causes an error instead of being absorbed:

- The entries array is mandatory, even when empty (`domains = []`). A missing or misspelled key (`domians`) is refused, because a silently empty dataset would look like the files that are empty on purpose.
- Unknown top-level fields are refused (`surprise = "x"` fails the load).
- Metadata values are at most 512 characters and may not contain CR, LF, NUL, other control characters, Unicode format characters such as bidirectional overrides, or line and paragraph separators. A metadata value becomes `Evidence.source_version` and can reach a response or a log line.

Nothing is read at import time. `load_passive_datasets(directory)` is called explicitly, and a malformed file fails that call instead of degrading a later answer.

## Current state

| Dataset | File | State |
|---|---|---|
| Role local parts | `role_local_parts.toml` | Populated |
| Disposable domains | `disposable_domains.toml` | Declared unavailable |
| Free-mail domains | `free_mail_domains.toml` | Declared unavailable |
| Provider MX patterns | `provider_mx_patterns.toml` | Declared unavailable |
| Disposable overrides | `overrides.toml` | Empty, maintained by operators |

The three unavailable datasets are empty on purpose. No upstream licence, source, or version could be verified without network access, and no licence is ever invented, so the files ship empty with illustrative `.example` files beside them. The matchers and loader are complete and tested against fixtures; role classification works.

## Declared unavailable

The disposable, free-mail, and provider datasets are declared unavailable for the limited beta. `emailcheck --report-versions` reports them as `unavailable-by-declaration` instead of an empty version string, so "unavailable on purpose" cannot be confused with "the loader failed". A dataset reports that category only while it is both declared here and observed empty; once it holds entries it reports its own version, and the command prints `dataset_entry_counts` so this can be checked.

### What the absence means

An empty dataset produces no evidence at all. It does not produce negative evidence, and nothing downstream may read it as:

- "this domain is not disposable";
- "this domain is not free mail";
- "this domain's provider is not one of the known families";
- any `Verdict`, any `Status`, any confidence level, or a risk flag in either direction.

With the shipped data every domain is unclassified on these three signals. A caller who reads a missing `disposable` flag as a clean result has drawn a conclusion this project cannot offer, because it had no list to check. For providers, `unknown` means the question could not be answered and `other` means it was answered and nothing matched; with no dataset the answer is `unknown`.

No placeholder dataset was created. A file with a few well-known domains would make the feature look present, be wrong about every domain missing from it, and give a reviewer nothing to verify.

### Lifting the declaration

Populating a dataset is a data change, not a code change; a test populates a declared dataset in a fixture directory, loads it through the production loader, and requires the report to show its version. Following `docs/data-sources.md` section 3, it needs:

1. an upstream licence that permits redistribution, read and recorded;
2. the exact release or commit, and a checksum of the snapshot;
3. the metadata block filled in, including `version` and `retrieved`;
4. the false-positive fixtures run;
5. this section updated to say the dataset is available, with the date;
6. for free mail, the override decision below settled first.

## Role local parts

- Purpose: flag a shared or functional mailbox as a risk attribute.
- Source: entries authored in `role_local_parts.toml` under the role policy in `docs/data-sources.md`. No third-party data.
- Licence: the same as this repository.
- Version: `2026-08-07.1`, authored 2026-08-07.
- Normalization: trim, lowercase, and drop a `+tag`, then match exactly. `LocalPart` itself is never changed.
- Updates: edit the file, bump `version`, and add a test for the changed behavior.
- False positives: delete the entry and bump `version`. The list is small enough to edit directly, so there is no role override file.
- Limitations: English conventions and exact matching only, so `support-team` and localized names are not roles unless added. A role flag never means invalid, and there is no substring rule because it would catch personal names (`docs/data-sources.md` section 4).

## Disposable domains

- Purpose: flag a domain that offers temporary mailboxes.
- Source and licence: none selected; the file is empty.
- Before populating: verify that the upstream licence permits redistribution, record the exact release or commit, take a checksum, and run the false-positive fixtures. Do not merge several upstream lists into one file without recording where each entry came from.
- False positives: add the domain to `overrides.toml` under `not_disposable` with a reason. The override wins, so the vendored file stays byte-identical to its upstream snapshot.
- Limitations: such lists are always stale and always have false positives, which is why the result is a risk flag and never a status.

## Overrides

`overrides.toml` corrects one list without editing a vendored snapshot.

```toml
schema_version = 1
kind = "overrides"
target = "disposable"

[[not_disposable]]
domain = "wrongly-listed.example"
reason = "reported 2026-08-07; operating company, not a throwaway service"

[[disposable]]
domain = "missed.example"
reason = "observed offering throwaway mailboxes"
```

- `target` names the classification being corrected. Only `"disposable"` is supported; any other value, including `"free_mail"`, is rejected at load time, so adding a target is always a deliberate code change.
- `not_disposable` says a domain is not disposable although the upstream list says it is; `disposable` says it is although the list does not.
- Neither is a delivery decision. The allow/deny vocabulary in `security/destination.py` decides whether an address may be connected to, and these names must not read like it, which is why the older `allow` and `deny` names were replaced. A file still using them is refused with a message naming the replacement.
- Both arrays are mandatory, empty or not, and every entry needs a reason. A domain corrected in both directions is rejected.

There is no free-mail override yet. Disposable false positives are frequent and damaging and come from an upstream snapshot that must stay unchanged; free mail is a smaller, slower-moving membership and ships empty. Decide whether it needs an override file before the free-mail list is populated. Adding one means a second `target` value, and the loader already rejects targets it does not implement.

## Free-mail domains

- Purpose: flag a consumer mailbox provider's own domain.
- Source and licence: none selected; the file is empty.
- Normalization: as above.
- Limitations: free mail is a property of the domain, not of whoever hosts its mail. A company domain whose MX points at a large provider must not be listed. Disposable and free mail are independent: a domain may be either, both, or neither.

## Provider MX patterns

- Purpose: metadata about who appears to host a domain's mail, so a reply parser could be chosen later.
- Source and licence: none selected; the file is empty, and every row will need its own `evidence`.
- Matching: label-bounded suffix. Wildcards are rejected because a suffix already covers every subdomain. Two different families among a domain's MX hosts give `unknown`, not a guess.
- Expected size: tens of rows, a few hundred at most. One row covers every subdomain below its suffix, so growth usually means the rows are too specific.
- Size policy: review anything above 500 rows before merging. The matcher scans every pattern for every MX host, which suits a short list; at the loader's 200,000-entry ceiling one classification would take about a tenth of a second. That ceiling and the 8 MiB byte limit guard memory for every dataset kind and do not make a provider list that large reasonable. If one is really needed, index the matcher first.
- Limitations: provider identity is never evidence of deliverability and never sets a status. Hosting changes without notice, so a stale row mislabels without failing.

## Updating a dataset

Follow `docs/data-sources.md` section 3. Retrieval is a reviewed, manual step: nothing in this project downloads a list, at startup or any other time, and no test may reach the network.
