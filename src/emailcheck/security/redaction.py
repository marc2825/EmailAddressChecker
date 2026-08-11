"""Turning an address into something that may be written down.

`docs/requirements.md` section 16 and `docs/privacy.md` sections 2 and 4: an
ordinary log never carries a full address, and what it may carry instead is a
redacted display form.

```text
alice@example.com → a***@example.com
a@example.com     → *@example.com
```

**Redaction is not anonymization, and this module says so where somebody will
read it.** `docs/privacy.md` section 4 states it and repeating it here is not
decoration: a first initial and a domain identify one person at a small domain,
and code that treats a redacted form as safe to publish widely is making a
claim this function does not support. It is safe for an *operator log*, which
is what it exists for.

**The domain survives; the local part does not.** `docs/requirements.md`
section 16 permits analytics aggregated by domain, and `docs/privacy.md`
section 1 lists the normalized domain as its own data category. Nothing here
keeps a plus tag, a dot pattern, or a length beyond the first character —
`a***@` is a fixed three asterisks whatever the length, because the length of a
local part is itself a distinguishing feature.

**A value that is not an address is not made into one.** Text with no `@`
redacts to a fixed marker rather than being echoed, so this function cannot
become a way to write arbitrary user input into a log.
"""

from __future__ import annotations

from typing import Final

#: What a redacted local part looks like, whatever its length.
_MASK: Final = "***"

#: What text that is not an address redacts to. Fixed, so an unparseable value
#: is never echoed into a log line.
UNREDACTABLE: Final = "<redacted>"

#: A domain longer than this is not one; refusing to echo it keeps a log line
#: bounded whatever was submitted.
MAX_DOMAIN_LENGTH: Final = 255


def redact_address(value: object) -> str:
    """The display-safe form of one submitted address.

    Total, and total on purpose: this is called on the failure paths where
    something has already gone wrong, and a redaction function that raises would
    replace a log line with a traceback carrying the value it was meant to hide.
    """
    if not isinstance(value, str) or not value:
        return UNREDACTABLE
    local, separator, domain = value.rpartition("@")
    if not separator or not local or not domain:
        return UNREDACTABLE
    if len(domain) > MAX_DOMAIN_LENGTH or "@" in local:
        # Two `@` means this is not one mailbox, and Phase 1 already refuses it.
        # Not echoed, because whatever it is, it is not the shape this function
        # promises to have redacted.
        return UNREDACTABLE
    if any(character.isspace() or not character.isprintable() for character in domain):
        return UNREDACTABLE
    return f"{local[0]}{_MASK}@{domain}" if len(local) > 1 else f"*@{domain}"


def redact_domain(value: object) -> str:
    """A domain, checked for the things that make text unsafe to log.

    Used where a caller has a domain rather than an address. It is *not* a
    validator — Phase 1 and Phase 2 own that — only the last barrier before a
    string reaches an operator log.
    """
    if not isinstance(value, str) or not value or len(value) > MAX_DOMAIN_LENGTH:
        return UNREDACTABLE
    if "@" in value:
        return UNREDACTABLE
    if any(character.isspace() or not character.isprintable() for character in value):
        return UNREDACTABLE
    return value
