# ADR 0005: IDNA domain encoding and conservative address syntax

- Status: Accepted
- Date: 2026-08-06
- Phase: 1

## Context

Phase 1 turns untrusted text into the only value later DNS and SMTP work may
act on. Two decisions are durable enough to record: which IDNA behavior encodes
a domain, and where the boundary sits between "breaks the supported grammar"
and "outside MVP support".

The standard library is not sufficient for the first. `str.encode("idna")`
implements IDNA 2003, which maps some characters instead of encoding them:

```text
straße.de -> strasse.de          # stdlib, IDNA 2003
straße.de -> xn--strae-oqa.de    # idna 3.x, IDNA 2008 with UTS-46
```

`strasse.de` and `xn--strae-oqa.de` are different domains with different owners
and different MX records. A mapping difference here silently redirects an SMTP
probe to a third party, which is a reputation and privacy problem, not only a
correctness one. The standard library also raises `UnicodeError` without a
stable machine-readable cause, so a caller cannot tell one failure from another
without reading a message that is free to change.

## Decision

Depend on `idna>=3.10,<4` as a production dependency and encode domains with
`idna.encode(domain, uts46=True, transitional=False)`.

- IDNA 2008 with UTS-46 mapping, non-transitional. `ß` and `ς` are encoded, not
  folded, so the encoded domain keeps the submitted identity.
- Only domains containing non-ASCII characters go through the library. An
  ASCII domain is lowercased directly, so this project reports its own specific
  cause (for example an underscore) rather than a library message.
- The library's exception text is never exposed. Failures map to the single
  issue `domain_idna_failure`, and the public reason stays `invalid_syntax`.
- The encoded ASCII form is revalidated by this project against letter-digit-
  hyphen, label-length, and total-length rules before it can be constructed
  into a `DomainName`.

The dependency is pure Python, performs no I/O, and ships type information, so
it does not violate the rule that domain code stays free of network, framework,
and storage libraries.

### What UTS-46 mapping changes about a submitted domain

UTS-46 is a mapping step, not only a validation step, so some domains are
accepted in a form the user did not type. The label separators below all become
an ASCII dot, and fullwidth Latin becomes its ASCII equivalent:

```text
example。com   -> example.com     # U+3002 ideographic full stop
example．com   -> example.com     # U+FF0E fullwidth full stop
example｡com   -> example.com     # U+FF61 halfwidth ideographic full stop
ｅｘａｍｐｌｅ.com  -> example.com     # fullwidth Latin letters
```

This is deliberate: it is what mail clients and browsers do, so the address
resolves to the same domain the user believes they typed.

It is not a general tolerance for look-alike characters. Only the separators
UTS-46 defines are mapped; a visually similar character that UTS-46 does not
define is rejected rather than converted. For example `exam․ple.com` with
U+2024 (one dot leader) is reported as `domain_idna_failure`, not silently read
as `example.com`. Detecting look-alike domains in general is a separate concern
and is not attempted here.

### The parser is domain logic, not a port

`docs/architecture.md` once listed an `AddressParser` port. It is now described
as pure domain logic instead. Parsing performs no I/O and has no clock or
randomness, so it does not meet this project's definition of a port, and there
is no second implementation to swap in. More importantly, a replaceable parser
would be a seam: the guarantee that only validated text becomes a
`NormalizedAddress` holds precisely because there is one construction path. A
later syntax policy change, such as SMTPUTF8 support, belongs in the domain as a
policy, not behind an I/O port.

## Syntax boundary judgments

These follow `docs/requirements.md` section 6 and resolve cases it does not
name. They are recorded here because reversing one changes public results.

1. **Surrounding whitespace is trimmed before parsing, including CR and LF.**
   A pasted trailing newline is user-interface framing, not an injection.
   Any control character that survives trimming, anywhere in the text, is
   rejected. The parsed value is rebuilt from validated parts, so a target can
   never carry CR, LF, or NUL regardless of what was submitted.
2. **Only ASCII whitespace is trimmed**, so a look-alike separator cannot be
   read as framing. Any other Unicode space stays in the text and is then
   rejected by judgment 9 or, in a domain, by encoding.
3. **A trailing dot makes the domain invalid.** `example.com.` is a DNS
   presentation form, not an RFC 5321 domain. It is reported as an empty label.
4. **A single-label domain stays syntactically acceptable.** `user@localhost`
   is not declared invalid here. DNS in Phase 2 and the destination policy
   produce better evidence than a syntax guess, and hard-invalid results must
   keep very high precision.
5. **An underscore in a domain is invalid.** RFC 5321 requires a
   letter-digit-hyphen domain, so this is a grammar violation, not an
   unsupported form.
6. **A domain that cannot be IDNA-encoded is invalid, not unsupported.**
   Requirements section 6 lists an IDNA-convertible domain as the accepted
   form. The specific issue is retained so Phase 5 can reclassify a class of
   failures without parsing text again, if evidence shows this is too strict.
7. **The domain is validated before the local part.** A domain that breaks the
   supported grammar outranks a local part that is merely unsupported, which
   matches the aggregation precedence in `docs/status-model.md` section 4.
   Quoted local parts and domain literals are detected earlier, because such an
   address cannot be split reliably.
8. **The full RFC 5322 atext set is accepted in the local part**, including
   `+`, `_`, and `-`. Case, dots, and plus tags are never rewritten: only the
   receiving server knows whether two forms are the same mailbox.
9. **An invisible or separator character in the local part is invalid, not
   unsupported.** A non-ASCII local part is normally reported as unsupported,
   because this MVP does not implement SMTPUTF8 and cannot judge such an
   address. That reasoning does not apply to Unicode categories `Cc`, `Cf`,
   `Zs`, `Zl`, and `Zp`: controls, formatting and bidirectional overrides, and
   the space and line separators. They are never part of a mailbox name under
   any grammar, and calling them merely unsupported would suggest the address
   might be fine on a server this project cannot talk to. They are reported as
   `local_part_disallowed_unicode` with the public reason `invalid_syntax`.
   Ordinary non-ASCII letters keep the unsupported classification, so
   `usér@example.com` stays `unsupported_smtputf8` while a zero-width space or a
   bidirectional override is invalid.
10. **A domain literal is recognized only when it is bracketed on both sides.**
    `user@[192.0.2.1]` is an unsupported address literal. A single stray bracket
    is a broken domain and is reported as an invalid character, because reading
    it as a literal would turn a typo into `unknown` instead of `invalid`.

## Consequences

- Encoding a domain is deterministic and testable without network access.
- Adding SMTPUTF8 later replaces the unsupported Unicode local-part path; it
  does not change domain encoding.
- An IDNA library upgrade can change which domains encode. The version range is
  pinned below the next major version, and the encoding rules are covered by
  tests.
- Judgments 3 to 6 are stricter than some general-purpose validators. Any
  relaxation needs a test and an update to this ADR.
