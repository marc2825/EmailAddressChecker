# ADR 0007: Passive classification, kept separate and kept honest

- Status: Accepted
- Date: 2026-08-07
- Phase: 3

## Context

Phase 3 adds four signals that need no network: is the local part a role, is the
domain disposable, is it free-mail, and who appears to host its mail. Each is
easy to misuse. A validator that rejects every disposable address, or treats
every role mailbox as invalid, is confidently wrong about addresses that receive
mail every day.

## Decision: passive signals never touch a status

Every result of this Phase is a risk flag, provider metadata, or evidence. None
of it can produce `invalid`, and none of it can produce `likely_deliverable`.

`PassiveClassification` has no status field, so the layer cannot express one.
The three reason codes it may emit (`disposable_domain`, `role_account`,
`free_mail`) are already published as risk-only in `docs/status-model.md`, and
its confidence table already records that a passive risk list is not confidence
evidence. ADR 0002 made this separation; this is where it is enforced.

The evidence is `WEAK` and non-temporary. Phase 5 decides what that means for a
verdict; nothing here decides it in advance.

## Decision: the four signals stay independent

They are stored as four separate values, not as a score or a single enum,
because they answer different questions and are wrong in different ways:

- a disposable domain may accept mail perfectly well;
- a role mailbox is usually deliverable and usually monitored;
- a free-mail domain says nothing about a specific mailbox;
- a provider family says nothing about either.

`free_mail = true, disposable = false` is an ordinary combination and must stay
expressible. Collapsing them would lose the ability to answer why, and would
make the risk vocabulary a single blunt instrument.

## Decision: free-mail is membership of the domain, not of its host

A company domain whose MX points at a large consumer provider is not free-mail.
Free-mail describes a domain that offers mailboxes to the public, which is a
property of the domain itself. Inferring it from MX hosting would mislabel every
business that outsources its mail, which is most of them.

Provider inference and free-mail membership therefore read different inputs and
can never be derived from each other.

## Decision: role matching is exact, on a derived comparison form

The comparison form lowercases and drops a `+tag`; the `LocalPart` value is
never modified, because Phase 1 promises that and only the receiving server
knows whether two spellings are one mailbox.

Matching is exact. A substring rule would classify `mysupport` and every
personal mailbox containing a role word, and `docs/data-sources.md` section 4
warns against exactly that. A compound such as `support-team` is not a role
unless a deployment adds it to the dataset. Dots are not removed: `info.desk` is
not `info`.

## Decision: provider inference is label-bounded, set-based, and may abstain

A host matches a suffix only when it equals it or ends with `"." + suffix`.
`google.com.evil.example` and `notgoogle.com` must never be attributed to a
provider, and a naive `endswith` would attribute the second.

Families are collected as a set across a domain's MX hosts, so the order records
arrive in cannot change the answer. Two different families resolve to `unknown`:
an ambiguous guess is worth less than an honest absence of one. `unknown` means
the question could not be answered; `other` means it was answered and nothing
matched.

Only MX-sourced hosts are read. An implicit A/AAAA route means the domain
published no MX at all, and its own address says nothing about who runs its
mail. A Null MX has no provider by definition.

### The limits of provider inference

It is a guess from naming, refreshed by nobody. Hosting changes without notice,
resellers and gateways sit in front of providers, and a filtering service in the
MX chain hides whoever is behind it. It may select a reply parser later. It may
never select a verdict, and no code path allows it to.

## Decision: no dataset ships without verifiable provenance

`prompts/03-passive-classification.md` requires that when no redistributable
dataset with verified provenance has been selected, the loader and format ship
with illustrative `.example` data and production data stays empty, and that no
licence is invented.

This Phase was implemented without network access, so no upstream list's
licence, source, or version could be verified. Disposable, free-mail, and
provider data therefore ship **empty**, with full metadata blocks, `.example`
files showing the format, and `data/passive/README.md` recording what must be
established first.

The role list is the exception. Its entries are enumerated in this repository's
own work order, so its provenance is checkable without trusting anyone. It ships
populated with `source: project-maintained`.

The consequence is stated plainly rather than hidden: with the shipped data, no
domain is disposable, none is free-mail, and every provider family is `unknown`.
That is a data gap, not a code gap.

It is also a gap with a deadline. By the Phase 8 limited beta each empty dataset
is either populated from a reviewed source or documented as unavailable
functionality; a beta that answers "not disposable" for every address without
saying so is neither. `IMPLEMENTATION_STATUS.md` and `data/passive/README.md`
carry the same deadline.

## Decision: false positives are fixed in data, not in code

`overrides.toml` carries `not_disposable` and `disposable` entries, each with a
mandatory reason. An override always beats the dataset:

```text
local not_disposable override  >  disposable dataset match
```

A vendored snapshot therefore stays byte-identical to its upstream, and a
reported false positive is corrected by adding one row with a note about why.
A domain corrected in both directions is rejected at load time rather than
silently resolved.

### Why those names, and not `allow` and `deny`

The first implementation called the two arrays `allow` and `deny`. Those words
already mean something else here: `security/destination.py` decides whether a
resolved address may be connected to, and that decision genuinely is an
allow/deny one. Reading `deny = ["example.com"]` in a mail product as "refuse
this domain" is the obvious mistake, and it is the opposite of what the entry
does — it adds a risk flag and changes no status at all.

`not_disposable` and `disposable` say what the entry asserts: membership of one
risk list. They cannot be read as a delivery decision. The names are derived
from the file's `target`, so a future free-mail override file would use
`not_free_mail` and `free_mail` by the same rule.

The rename is not backward compatible and is not meant to be. An override file
still declaring `allow` or `deny` is refused by name, with a message naming the
replacement, rather than being read as an empty override file. Silently
accepting the old spelling would leave a deployment believing its corrections
were applied.

## Decision: an override file names the classification it corrects

Only the disposable list has an override file today. Rather than leave that
implicit, the file declares `target = "disposable"`, and a file naming any other
target — including `"free_mail"` — is rejected at load time.

The alternative was to accept any target and apply the ones implemented. That
fails open in the worst way: an operator writes free-mail corrections, the file
loads, and nothing happens. Adding a second target must be a deliberate change
to this code, and until it is made the gap fails loudly.

## Decision: the loader fails closed

A dataset decides what this project publishes about somebody's domain, so a file
that cannot be trusted is not partially applied. The loader rejects an unknown
schema version, missing or unknown metadata fields, a duplicate entry, entries
differing only by Unicode normalization, an unusable hostname, an IP literal, a
wildcard, a wrong dataset kind, a contradictory override, and input beyond the
byte and entry limits. A missing file is an error, not an empty list.

### Closing the two gaps a review found

The first version of the loader read entries with `document.get(key, [])` and
ignored unknown top-level fields. Both are fail-open, and they compound: a file
whose array is named `domians` loaded successfully, with zero entries.

That is the worst possible failure for this particular project, because three of
the datasets here are *legitimately* empty. A silently empty list is
indistinguishable from the intended state, so nobody would look. The entries
array is therefore mandatory even for an empty dataset, which writes
`domains = []`, and unknown top-level fields are refused the way unknown
metadata fields already were. Every typo now lands on one of those two errors.

### Metadata values are validated, because they travel

A metadata value is the one operator-authored string that leaves this layer: it
becomes `Evidence.source_version` and can reach an API response or a log line in
a later Phase. A version of `"v1\r\nX-Injected: yes"` loaded without complaint.

Each value is now bounded at 512 characters — generous for a URL, an SPDX
identifier, a checksum, or a normalization sentence — and rejects control
characters, Unicode format characters including the bidirectional overrides, and
line and paragraph separators. The check lives on `DatasetMetadata` rather than
in the loader, so a value built directly is checked the same way a loaded one
is. A parser's own wording is never copied into a `DatasetError`.

Nothing is read at import time and nothing is ever downloaded, at startup or
otherwise. `docs/data-sources.md` section 3 keeps retrieval a reviewed manual
step.

## Decision: the domain and the role name are values, not strings

`PassiveClassification.domain` was a `str` and `RoleMatch.name` was a `str`. The
service always passed the right thing, but the types permitted a complete
address, a submitted local part, or a value carrying CR and LF, and all three
reach `details` and therefore evidence. Phases 1 and 2 closed exactly this gap
in their own values after the same observation.

`domain` is a Phase 2 `HostName`, reusing the validation that already exists
rather than writing a second domain validator. A role match holds a `RoleName`,
which is obtained only from `LocalPartDataset.canonical`, so it always names
something a dataset published. `Support+Billing.SECRET@example.com` cannot be
stored anywhere in a classification, which is a stronger statement than "the
service does not store it".

## Consequences

- A deployment that wants disposable or provider detection must review a licence
  and populate the files. The code is ready; the data is a decision.
- Every answer carries the dataset version that produced it, so a result can be
  reproduced against the snapshot that gave it.
- Adding a fifth signal means adding a value, not widening an enum.
- Classification cannot be tested into producing a status, because there is no
  status to produce.
