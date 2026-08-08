"""What the server said it supports, read as narrowly as possible.

An EHLO reply is a list of extension keywords. This project needs exactly one of
them — `STARTTLS` — and reads `SIZE` as metadata because it is the only other
keyword whose absence or presence a later gate might legitimately record.

Everything else is ignored on purpose. `docs/architecture.md` keeps provider
family as metadata that never decides behaviour, and an extension keyword is a
better fingerprint than an MX name: branching on `X-…` would make this client
behave differently for one operator, which is the thing Phase 3 was careful not
to do.

Pure. No I/O, no clock, and no reply parsing — this reads the lines a reply was
already framed from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

#: The keyword this gate acts on. One entry, deliberately: a set that grows is a
#: set of behavioural branches.
STARTTLS_KEYWORD: Final = "STARTTLS"

#: Read as metadata only. It bounds a message, and this project sends none, so
#: nothing may branch on it.
SIZE_KEYWORD: Final = "SIZE"

#: A keyword is a bounded token. Anything longer is not one, and keeping it
#: would put unbounded remote text in a value that reaches evidence.
MAX_KEYWORD_LENGTH: Final = 32

#: How many keywords are retained. A server offering more than this is not
#: describing itself, and the reply parser's own line cap already bounds the
#: input; this bounds what survives into a value.
MAX_KEYWORDS: Final = 64


@dataclass(frozen=True, slots=True)
class Capabilities:
    """The extension keywords a server advertised, as an opaque set.

    `keywords` holds upper-cased keyword names with their parameters dropped.
    Parameters are not kept because nothing in this gate reads one, and remote
    text that is not read is remote text that cannot leak.
    """

    keywords: frozenset[str] = field(default_factory=frozenset)
    size_limit: int | None = None

    @property
    def supports_starttls(self) -> bool:
        """Whether the server advertised `STARTTLS`.

        Advertisement only. Whether TLS is then attempted, and what happens when
        it is absent, is the TLS policy's decision, not this value's.
        """
        return STARTTLS_KEYWORD in self.keywords

    def advertises(self, keyword: str) -> bool:
        return keyword.strip().upper() in self.keywords


def _without_reply_code(raw: str) -> str:
    """Drop the `250-` or `250 ` a reply line begins with.

    These are the framed lines exactly as they came off the wire, because the
    keywords live in the text the reply parser discards. A line that carries no
    code is used as it stands rather than guessed at.
    """
    line = raw.rstrip("\r\n")
    if len(line) >= 4 and line[:3].isdigit() and line[3] in {" ", "-"}:
        return line[4:]
    if len(line) == 3 and line.isdigit():
        return ""
    return line


def parse_capabilities(lines: list[str]) -> Capabilities:
    """Read the extension keywords out of the lines of an EHLO reply.

    The first line is the greeting — `250-mx.example.com at your service` — and
    is not a keyword. Every later line begins with one.

    Robust by ignoring rather than by guessing. A malformed line contributes
    nothing, an unknown extension contributes its name and no behaviour, a
    duplicate collapses into the set, and a keyword with parameters is read as
    its keyword. Nothing here can fail: a server that answers nonsense produces
    an empty capability set, and an empty set means no STARTTLS, which the
    policy then decides about.
    """
    keywords: set[str] = set()
    size_limit: int | None = None

    for raw in lines[1:]:
        token, _, parameters = _without_reply_code(raw).strip().partition(" ")
        keyword = token.strip().upper()
        if not keyword or len(keyword) > MAX_KEYWORD_LENGTH:
            continue
        if not keyword.replace("-", "").replace("_", "").isalnum():
            # A keyword is `ALPHA *(ALPHA / DIGIT / "-")` by RFC 5321. Anything
            # else is not an extension name, so it is not recorded as one.
            continue
        if len(keywords) >= MAX_KEYWORDS:
            break
        keywords.add(keyword)
        if keyword == SIZE_KEYWORD and size_limit is None:
            size_limit = _read_size(parameters)

    return Capabilities(keywords=frozenset(keywords), size_limit=size_limit)


def _read_size(parameters: str) -> int | None:
    """Read the `SIZE` argument, or None when it is not a plain number.

    Metadata. This project transmits no message, so the value cannot change what
    it does; it is read because a bounded integer is safe to record and a later
    gate may want it.
    """
    candidate = parameters.strip().split(" ")[0] if parameters.strip() else ""
    if not candidate.isdigit() or len(candidate) > 19:
        return None
    return int(candidate)
