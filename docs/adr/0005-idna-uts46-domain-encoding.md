# ADR 0005: IDNA domain encoding and conservative address syntax

- Status: Accepted
- Date: 2026-08-06

## Context

The address parser turns untrusted text into the only value DNS and SMTP code may act on. Two choices matter beyond the code: how a domain is IDNA-encoded, and where the line falls between "breaks the supported grammar" and "outside MVP support".

The standard library cannot do the first. `str.encode("idna")` implements IDNA 2003, which maps some characters instead of encoding them:

```text
straße.de -> strasse.de          # stdlib, IDNA 2003
straße.de -> xn--strae-oqa.de    # idna 3.x, IDNA 2008 with UTS-46
```

These are different domains with different owners and MX records, so the stdlib behavior would send a probe to a third party. It also raises `UnicodeError` without a stable, machine-readable cause.

## Decision

Depend on `idna>=3.10,<4` in production and encode with `idna.encode(domain, uts46=True, transitional=False)`.

- IDNA 2008 with non-transitional UTS-46 mapping: `ß` and `ς` are encoded, not folded.
- Only domains with non-ASCII characters go through the library. An ASCII domain is lowercased directly, so this project reports its own specific cause, such as an underscore.
- Library exception text is never exposed. Failures become the issue `domain_idna_failure` with the public reason `invalid_syntax`.
- The encoded ASCII form is checked again against letter-digit-hyphen, label-length, and total-length rules before a `DomainName` can exist.
- UTS-46 maps its defined label separators (`。`, `．`, `｡`) to a dot and fullwidth Latin to ASCII, as mail clients and browsers do. Characters it maps to nothing are refused (judgment 12), and look-alike characters it does not define are rejected, not converted: `exam․ple.com` with U+2024 is `domain_idna_failure`. Detecting look-alike domains in general is out of scope.
- The parser is domain logic, not a port. It does no I/O, and having one construction path is what guarantees that only validated text becomes a `NormalizedAddress`.

The dependency is pure Python, does no I/O, and ships type information.

## Syntax judgments

These settle cases `docs/requirements.md` section 6 does not name. Reversing one changes public results.

1. Surrounding ASCII whitespace, including CR and LF, is trimmed before parsing; a pasted trailing newline is framing, not injection. A control character anywhere after trimming is rejected, and the parsed value is rebuilt from validated parts, so a target can never carry CR, LF, or NUL.
2. Only ASCII whitespace is trimmed, so a look-alike separator is not read as framing. Other Unicode spaces stay and are rejected by judgment 9 or by encoding.
3. A trailing dot makes the domain invalid. `example.com.` is a DNS presentation form, not an RFC 5321 domain, and is reported as an empty label.
4. A single-label domain such as `user@localhost` is syntactically acceptable. DNS and the destination policy give better evidence than a syntax guess, and hard-invalid results must keep very high precision.
5. An underscore in a domain is invalid: RFC 5321 requires letter-digit-hyphen labels.
6. A domain that cannot be IDNA-encoded is invalid, not unsupported, because an IDNA-convertible domain is the accepted form. The specific issue is kept so the classification can be revisited without parsing again.
7. The domain is checked before the local part, so a domain that breaks the grammar outranks a local part that is merely unsupported, matching the precedence in `docs/status-model.md` section 4. Quoted local parts and domain literals are detected first, because such an address cannot be split reliably.
8. The full RFC 5322 atext set is accepted in the local part, including `+`, `_`, and `-`. Case, dots, and plus tags are never rewritten; only the receiving server knows whether two spellings are one mailbox.
9. An invisible or separator character in the local part (Unicode categories `Cc`, `Cf`, `Zs`, `Zl`, `Zp`) is invalid (`local_part_disallowed_unicode`, public reason `invalid_syntax`), not unsupported, because it is never part of a mailbox name. Ordinary non-ASCII letters stay unsupported: `usér@example.com` is `unsupported_smtputf8`.
10. A domain literal is recognized only when bracketed on both sides. `user@[192.0.2.1]` is an unsupported address literal; a single stray bracket is an invalid character, so a typo stays `invalid` instead of becoming `unknown`.
11. An unbracketed numeric domain such as `user@192.0.2.1` or `user@example.123` is a DNS name, accepted by the grammar like judgment 4. That a top-level label is never all-numeric is a fact about the root zone, which DNS reports as NXDOMAIN (`domain_nxdomain`). The parser never rewrites it into the literal `[192.0.2.1]` (judgment 10), which would bypass DNS, and connection targets come only from DNS answers screened by the destination policy, so neither form can direct a connection to an arbitrary IP. Pinned by `test_single_label_and_numeric_domains_stay_dns_names` and the mail-route tests.

12. A domain containing a character that UTS-46 maps to nothing is invalid (`domain_invalid_character`). Encoding would silently delete such characters (U+200B, U+00AD, U+FEFF, U+2060, U+180E, U+034F, variation selectors) and look up a different domain from the one submitted, which is what this ADR rejected IDNA 2003 for; the local part already treats invisible characters as invalid (judgment 9). The check is in the shared encoder, so operator blocks and lab allowlists refuse such names too. Mappings that keep a character, such as U+3002 to a dot, still apply. Added after issue #3; pinned by `test_a_character_uts46_would_delete_makes_the_domain_invalid`.

## Consequences

- Domain encoding is deterministic and testable without a network.
- SMTPUTF8 support, if added, replaces the unsupported Unicode local-part path without changing domain encoding.
- An `idna` upgrade could change which domains encode, so the version is capped below the next major release and the rules are covered by tests.
- Judgments 3 to 6 are stricter than some general validators; relaxing one needs a test and an update here.
