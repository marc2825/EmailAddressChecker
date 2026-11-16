# Dataset policy

## 1. Data categories and current state

| Dataset | Used for | State |
| --- | --- | --- |
| Role local parts | `role_account` risk flag | Populated; entries authored in this repository (`source: project-maintained`) |
| Disposable domains | `disposable_domain` risk flag | Empty; declared unavailable |
| Free-mail domains | `free_mail` risk flag | Empty; declared unavailable |
| Provider MX patterns | Provider metadata | Empty; declared unavailable |

`src/emailcheck/data/passive/` holds the snapshots, and its `README.md` records the state of each one and how to lift the declaration.

The three empty datasets are declared unavailable because no upstream licence, source, or version could be verified; checking provenance needs network access to the upstream, which development did not have, and no licence is ever invented. No placeholder dataset was created. A short list of well-known domains would make the feature look present while being wrong about every domain missing from it, and would give a reviewer nothing to verify. An empty list that says it is empty is something a caller can reason about.

Absence produces no evidence, and no negative evidence. An empty disposable list does not mean a domain is not disposable, an empty free-mail list does not mean a domain is not free mail, and an empty provider list gives `provider_family = unknown` ("could not be answered", not "nothing matched"). None of them can produce a verdict, status, confidence level, or risk flag in either direction.

`emailcheck --report-versions` reports an empty dataset as `unavailable-by-declaration` and a populated one by its own version, together with the entry counts. It reports the snapshot the deployment actually loaded.

The declaration is reversible by data. Populating a dataset needs the steps in section 3 and an update to `src/emailcheck/data/passive/README.md` recording when it became available. No code change is needed.

### Classification rules

Classification produces risk flags, provider metadata, and weak, non-temporary evidence. It never produces `invalid` or `likely_deliverable`; `PassiveClassification` has no status field.

The four signals are separate values, not a score or one combined enum, because each answers a different question: a disposable domain may accept mail, a role mailbox is usually deliverable and monitored, a free-mail domain says nothing about one mailbox, and a provider family says nothing about any of them. `free_mail = true, disposable = false` must stay expressible.

Free mail is a property of the domain, not of its mail host. A company domain whose MX points at a consumer provider is not free mail, so provider inference and free-mail membership read different inputs. Role and provider rules are in sections 4 and 5.

## 2. Required metadata

Every dataset file carries:

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

Every field is a mandatory, validated string of at most 512 characters, without CR, LF, NUL, other control characters, Unicode format characters such as bidirectional overrides, or line and paragraph separators. A metadata value becomes `Evidence.source_version` and can reach an API response or a log line, so it must not be able to break one. Unknown metadata fields are rejected.

The document around it is closed in the same way. The entries array is mandatory even when empty (`domains = []`), and an unknown top-level field fails the load, so a typo causes an error, never a silently empty dataset. The loader fails closed.

## 2.1 Override files

An override file corrects one classification without editing a vendored snapshot; false positives are fixed in data, not in code. It declares a `target`; only `"disposable"` is implemented, and any other target is rejected.

Its two arrays, `not_disposable` and `disposable`, are named for the membership they assert. They are not delivery decisions: allow and deny in this project mean the destination policy in `security/destination.py`, and the two vocabularies are kept apart. A file that uses the older `allow` and `deny` names is refused. Free-mail overrides are not supported yet; whether to add them is decided before that list is populated.

## 3. Update process

1. Retrieve the data with a reviewed script.
2. Verify the source and the licence.
3. Normalize deterministically.
4. Generate the checksum and metadata.
5. Review additions and removals.
6. Run the false-positive fixtures.
7. Commit the data and metadata together.

Never download a mutable list when the application starts.

## 4. Role accounts

Role detection is a risk flag, never an invalid verdict. Keep the list small, documented, and aware of locale, and do not classify common personal names as roles.

Matching is exact, on a comparison form that is lowercased and drops a `+tag`; the `LocalPart` itself is never changed. There is no substring rule: `mysupport` and `support-team` are not roles unless the dataset lists them, and dots are kept, so `info.desk` is not `info`.

## 5. Provider patterns

Provider patterns may select a reply parser or a metadata label, never mailbox validity on their own. Inference is a guess from naming: hosting changes, gateways and filtering services hide the real provider, and nobody refreshes the guess.

- A host matches a suffix only when it equals it or ends with `"." + suffix`, so `google.com.evil.example` and `notgoogle.com` never match.
- Families are collected as a set across a domain's MX hosts, so record order does not matter, and two different families give `unknown`. `unknown` means the question could not be answered; `other` means it was answered and nothing matched.
- Only MX hosts are read. An implicit A/AAAA route and a Null MX have no provider.

The list should hold tens of rows, a few hundred at most, because one suffix covers every subdomain beneath it. Matching is a linear scan, which suits that size. A submission over 500 rows is reviewed instead of merged, and a real need for a large list means indexing the matcher first.
