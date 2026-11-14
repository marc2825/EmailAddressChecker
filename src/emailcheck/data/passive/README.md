# Passive classification datasets

Every file here decides what this project publishes about somebody's domain. A
wrong entry labels a real business as disposable, so provenance matters more
than coverage. `docs/data-sources.md` is the policy; this file records the
current state of each dataset.

## Format

One TOML file per dataset. Each carries `schema_version`, a `kind`, the full
metadata block `docs/data-sources.md` requires, and its entries. The loader
refuses a file with an unknown schema version, missing or unknown metadata
fields, duplicate entries, an unusable hostname, an IP literal, a wildcard, a
contradictory override, or more entries or bytes than the configured limits.

The document schema is closed at both levels, so a typo lands on an error
instead of being absorbed:

- **the entries array is mandatory**, even when the dataset is empty. An empty
  list is written `domains = []`. A missing key and a misspelled one
  (`domians`) are both refused, because a silently empty dataset is
  indistinguishable from the three files here that are empty on purpose;
- **unknown top-level fields are refused**, the same way unknown metadata
  fields already were. `surprise = "x"` fails the load;
- **metadata values are validated**. Each is at most 512 characters and may not
  contain CR, LF, NUL, another control character, a Unicode format character
  such as a bidirectional override, or a line or paragraph separator. A
  metadata value becomes `Evidence.source_version` and can reach a response or
  a log line, so it may not be able to break one.

Nothing is read at import time. `load_passive_datasets(directory)` is called
explicitly, and a malformed file fails that call rather than degrading a later
answer.

## Current state

| Dataset | File | State |
|---|---|---|
| Role local parts | `role_local_parts.toml` | **Populated** |
| Disposable domains | `disposable_domains.toml` | **Declared unavailable** |
| Free-mail domains | `free_mail_domains.toml` | **Declared unavailable** |
| Provider MX patterns | `provider_mx_patterns.toml` | **Declared unavailable** |
| Disposable overrides | `overrides.toml` | Empty, operator-maintained |

Three of the five ship empty on purpose. `docs/data-sources.md`
requires that when no redistributable dataset with verified provenance has been
selected, the loader and format ship with illustrative `.example` data and
production data stays empty, and that no licence is invented. The environment
this Phase was implemented in has no network access and could not verify any
upstream list's licence, source, or version, so none was asserted.

This is a data gap, not a code gap; the matchers and the loader are complete and
tested against fixtures. Role classification works.

## Declared unavailable for the limited beta

ADR 0007 set a deadline: by the Phase 8 limited beta each empty dataset is
either populated from a reviewed source or **documented as unavailable
functionality**. Phase 8 took the second option for all three, and this section
is that declaration. ADR 0007 records why.

`emailcheck --report-versions` reports these three as
`unavailable-by-declaration` rather than as an empty version string, so an
operator can tell "unavailable on purpose" from "the loader failed".

**The category is derived from the data, not from the name.** A dataset reports
`unavailable-by-declaration` only while it is *both* named here and observed
empty; the moment one holds entries it reports its own version, and the command
publishes `dataset_entry_counts` beside the versions so the derivation can be
checked rather than trusted. That is what makes the promise below true: an
independent review found an earlier build keying the category on the dataset's
name alone, which would have gone on printing "unavailable" over real data.

### What the absence does and does not mean

An empty dataset produces **no evidence at all**. It does not produce negative evidence, and nothing downstream may read it as any of the following:

- **not** "this domain is not disposable";
- **not** "this domain is not free mail";
- **not** "this domain's provider is not one of the known families";
- **not** any `Verdict`, any `Status`, any confidence level, and no risk flag in
  either direction.

The distinction is the whole point. With the shipped data every domain is
*unclassified* on these three signals. A caller who reads a missing
`disposable` flag as a clean bill of health has drawn a conclusion this project
did not offer, and one it cannot offer, because it has no list to have checked
against.

`provider_family` already has the vocabulary for this and it is worth copying:
`unknown` means the question could not be answered, and `other` means it was
answered and nothing matched. With no dataset the honest answer is `unknown`,
and that is what is produced.

### Why declaring, rather than populating

No dataset with verified provenance could be selected. Verifying one means
reading an upstream licence, recording the exact release or commit, and taking a
checksum of a snapshot — all of which require reaching the upstream source, and
none of the Phases through 8 has been permitted network access. Inventing a
licence, or vendoring a list whose terms nobody read, is worse than shipping
without one: it puts this repository's name behind a redistribution nobody
checked.

**No placeholder dataset was created.** A file with a handful of well-known
domains in it would make the feature look present, would be wrong about every
domain not in it, and would give a reviewer nothing to check the provenance of.
An empty list that says it is empty is the honest shape.

### Lifting the declaration

Populating a dataset later is an ordinary data change, not a code change — and
that is enforced rather than asserted: a test populates a declared dataset in a
fixture directory, loads it through the production loader, and requires the
report to name its version. It needs, per `docs/data-sources.md` section 3:

1. an upstream licence that permits redistribution, read and recorded;
2. the exact release or commit, and a checksum of the snapshot;
3. the metadata block filled in, including `version` and `retrieved`;
4. the false-positive fixtures run;
5. this section and ADR 0007 updated to say the dataset is now available, with
   the date;
6. for free-mail, the override-file decision below settled first.

## Role local parts

- **Purpose**: flag a shared or functional mailbox as a risk attribute.
- **Source**: authored entries in `role_local_parts.toml` in this repository,
  under the role-account policy in `docs/data-sources.md`. No third-party data is included.
- **Licence**: same as this repository.
- **Version**: `2026-08-07.1`.
- **Retrieved**: authored in repository, 2026-08-07.
- **Normalization**: trim, lower-case, and drop a `+tag`; then exact match.
  `LocalPart` itself is never modified.
- **Update procedure**: edit the file, bump `version`, and add a test case for
  the behavior being changed.
- **False-positive removal**: delete the entry and bump `version`. There is no
  override file for roles: the list is small enough to edit directly.
- **Known limitations**: English conventions only, and exact match only, so
  `support-team` and localized equivalents are not roles unless added. A role
  flag is never invalidity: `docs/data-sources.md` section 4 warns against
  classifying personal names, which is why no substring rule exists.

## Disposable domains

- **Purpose**: flag a domain that offers temporary mailboxes.
- **Source**: none selected.
- **Licence**: none; the file is empty.
- **Before populating**: verify the upstream licence permits redistribution,
  record the exact release or commit, take a checksum, and run the false
  positive fixtures. Do not merge several upstream lists into one file without
  recording which entry came from where.
- **False-positive removal**: add the domain to `overrides.toml` under
  `not_disposable` with a reason. The override wins over the dataset, so the
  vendored file stays byte-identical to its upstream snapshot.
- **Known limitations**: a list of this kind is always stale and always has
  false positives, which is why the result is a risk flag and never a status.

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

- `target` names the classification these entries correct. **Only
  `"disposable"` is supported.** Any other value, including `"free_mail"`, is
  rejected at load time rather than ignored, so adding a second target is a
  deliberate code change and never a silent data change.
- `not_disposable` asserts that a domain is **not** disposable even though the
  upstream list says it is. `disposable` asserts that a domain **is**
  disposable even though the upstream list does not say so.
- **Neither is a delivery decision.** These names describe membership of one
  risk list. This project also has an allow/deny vocabulary, in
  `security/destination.py`, and that one does decide whether an address may be
  connected to. The two must not read alike, which is why the earlier `allow`
  and `deny` names were replaced. A file still using them is refused by name
  with a message pointing at the replacement.
- Both arrays are mandatory, empty or not.
- Every entry needs a reason, so a later reviewer can tell a considered
  exception from a forgotten one. A domain corrected in both directions is
  rejected at load time.

### No free-mail override yet

Only the disposable list has an override file. The reason is that the
disposable list is the one whose false positives are damaging and frequent: it
labels a real business as a throwaway service, and it comes from an upstream
snapshot that must stay byte-identical. Free-mail is a smaller, slower-moving,
and less contentious membership, and it ships empty, so there is nothing yet to
correct.

That is a decision to revisit rather than a permanent one. **Before the
free-mail list is populated, decide whether it needs an override file.** The
Phase 8 deadline on this question is discharged by the declaration above: the
free-mail dataset is declared unavailable, so there is nothing to override and
the question moves to whenever it is populated. Adding an override file means a
second `target` value and a second override file; the loader already rejects any
target it does not implement, so the gap fails loudly rather than quietly.

## Free-mail domains

- **Purpose**: flag a consumer mailbox provider's own domain.
- **Source**: none selected.
- **Licence**: none; the file is empty.
- **Normalization**: as above.
- **Known limitations**: free-mail is a property of the destination domain, not
  of whoever hosts its mail. A company domain whose MX points at a large
  provider must not be listed here. Disposable and free-mail are independent:
  a domain may be either, both, or neither.

## Provider MX patterns

- **Purpose**: metadata about who appears to host a domain's mail, so a later
  Phase can pick a reply parser.
- **Source**: none selected; every row needs its own `evidence`.
- **Licence**: none; the file is empty.
- **Matching**: label-bounded suffix. Wildcards are rejected because a suffix
  already matches every subdomain. Two different families among a domain's MX
  hosts resolve to `unknown` rather than to a guess.
- **Expected size**: tens of rows, low hundreds at the most. This dataset is a
  short list of the naming patterns of a handful of large mail hosts, not a
  domain list. One row covers every subdomain beneath its suffix, so growth
  here usually means the rows are too specific.
- **Size policy**: **above 500 rows, review before merging.** The matcher is a
  linear scan of every pattern for every MX host of the domain being checked,
  which is the right shape for a list of this size and the wrong shape for a
  large one. At a few hundred rows the cost is immeasurable; at the loader's
  200,000-entry ceiling one classification would take roughly a tenth of a
  second. That ceiling and the 8 MiB byte limit are memory-exhaustion guards
  shared by every dataset kind, not a statement that a provider list of that
  size is reasonable. If a genuine need for one appears, index the matcher
  first rather than raising this threshold.
- **Known limitations**: provider identity is never evidence of deliverability
  and never sets a status. Hosting arrangements change without notice, so a
  stale row silently mislabels rather than failing.

## Updating a dataset

Follow `docs/data-sources.md` section 3. Retrieval is a reviewed, manual step:
nothing in this project downloads a list, at startup or at any other time, and
no test may reach the network.
