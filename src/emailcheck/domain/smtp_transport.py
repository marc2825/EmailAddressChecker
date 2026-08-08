"""What a transport may promise, expressed without a socket.

This module is pure. It holds the bounds and the failure vocabulary a transport
answers in, so the application can reason about a connection without importing
`socket` or `asyncio`, and so a fake transport and the real one are constrained
by the same values.

Nothing here reads or writes. `adapters/smtp/` does that; these are the limits
it must respect and the typed answers it must give.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from emailcheck.domain.smtp_contract import SMTPContractError

#: No single operation may be given a deadline beyond this. A timeout of an hour
#: is a configuration mistake, and `docs/requirements.md` section 9 requires
#: every read, write, and connect to be bounded — a bound nobody would reach is
#: not one.
MAX_TIMEOUT_SECONDS: Final = 300.0

#: An SMTP reply line is 512 octets by RFC 5321; servers exceed it, so the
#: transport's own ceiling is generous. `smtp_reply.py` applies the parser's
#: stricter limit to what it is given.
DEFAULT_MAX_LINE_BYTES: Final = 4096

#: Everything one connection may read, across every line. A banner and a handful
#: of replies is a few kilobytes; this is the tarpit ceiling.
DEFAULT_MAX_TOTAL_BYTES: Final = 64 * 1024

#: How much is asked of the socket at once. Bounded so a single read cannot be
#: asked to allocate an arbitrary buffer.
READ_CHUNK_BYTES: Final = 4096


class TransportFailure(StrEnum):
    """Why a connection could not be made, used, or trusted.

    Every member is this project's own vocabulary. A library's exception text
    never reaches a caller: `docs/requirements.md` section 11 forbids returning
    full exception text, and an `OSError` message is not a stable contract.
    """

    # --- reaching the peer -------------------------------------------------
    CONNECT_TIMEOUT = "connect_timeout"
    CONNECTION_REFUSED = "connection_refused"
    NETWORK_UNREACHABLE = "network_unreachable"

    # --- judging the peer, before a single byte is written -----------------
    #: The policy refuses the address the socket actually reached.
    PEER_DENIED_BY_POLICY = "peer_denied_by_policy"
    #: The peer is permitted but is not the address that was approved.
    PEER_ADDRESS_MISMATCH = "peer_address_mismatch"
    #: The peer is the approved address on a port that was not approved.
    PEER_PORT_MISMATCH = "peer_port_mismatch"
    #: `getpeername()` returned something unusable.
    PEER_MALFORMED = "peer_malformed"
    #: The socket reports a family the destination did not belong to.
    PEER_UNEXPECTED_FAMILY = "peer_unexpected_family"

    # --- the destination itself --------------------------------------------
    #: The policy refuses the address at the moment of connecting. No socket is
    #: opened; this is the defence-in-depth re-check.
    DESTINATION_DENIED_BY_POLICY = "destination_denied_by_policy"

    # --- reading and writing -----------------------------------------------
    READ_TIMEOUT = "read_timeout"
    WRITE_TIMEOUT = "write_timeout"
    CONNECTION_RESET = "connection_reset"
    CONNECTION_CLOSED = "connection_closed"
    LINE_TOO_LONG = "line_too_long"
    TOTAL_LIMIT_EXCEEDED = "total_limit_exceeded"

    # --- upgrading to TLS ---------------------------------------------------
    #: The handshake failed for a reason that is not the certificate.
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    #: The chain did not verify against the configured trust anchors.
    TLS_CERTIFICATE_INVALID = "tls_certificate_invalid"
    #: The chain verified and the name did not match the MX host.
    TLS_HOSTNAME_MISMATCH = "tls_hostname_mismatch"
    #: The handshake did not finish inside its deadline.
    TLS_TIMEOUT = "tls_timeout"
    #: The endpoint underneath the upgrade is not the one that was confirmed.
    TLS_PEER_CHANGED = "tls_peer_changed"
    #: A second upgrade was asked for. There is only ever one.
    TLS_ALREADY_ACTIVE = "tls_already_active"

    # --- this project ------------------------------------------------------
    INTERNAL_ERROR = "internal_error"

    @property
    def is_peer_rejection(self) -> bool:
        """Whether the connection was refused because of who answered it.

        These are the ones that must happen before anything is written, and
        they say nothing about the address being probed.
        """
        return self in _PEER_REJECTIONS

    @property
    def is_about_the_target(self) -> bool:
        """Always false. A transport failure is never mailbox evidence.

        A refused connection, a timeout, and a peer that failed the policy are
        facts about the network and about this project's own rules. Phase 4D
        maps them to `connection_error`, never to anything target-specific.
        """
        return False


_PEER_REJECTIONS: Final[frozenset[TransportFailure]] = frozenset(
    {
        TransportFailure.PEER_DENIED_BY_POLICY,
        TransportFailure.PEER_ADDRESS_MISMATCH,
        TransportFailure.PEER_PORT_MISMATCH,
        TransportFailure.PEER_MALFORMED,
        TransportFailure.PEER_UNEXPECTED_FAMILY,
    }
)


class TransportError(Exception):
    """A transport operation failed, named in this project's vocabulary.

    It carries a `TransportFailure` and no remote or library text. Callers match
    on `failure`, never on the message.
    """

    def __init__(self, failure: TransportFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


def _check_seconds(name: str, value: float) -> None:
    """Reject a timeout that is not a usable positive number of seconds.

    `bool` is refused explicitly because `True` is `1` in Python, and a
    `timeouts.read_seconds = True` would silently mean one second.
    """
    if isinstance(value, bool):
        raise SMTPContractError(f"{name} must be a number of seconds, not a boolean")
    if not isinstance(value, int | float):
        raise SMTPContractError(f"{name} must be a number of seconds")
    if math.isnan(value) or math.isinf(value):
        raise SMTPContractError(f"{name} must be finite")
    if value <= 0:
        raise SMTPContractError(f"{name} must be positive")
    if value > MAX_TIMEOUT_SECONDS:
        raise SMTPContractError(f"{name} exceeds the maximum allowed timeout")


@dataclass(frozen=True, slots=True)
class TransportTimeouts:
    """A deadline for every operation the transport performs.

    Separate values rather than one, because `docs/smtp-state-machine.md`
    section 6 keeps the budget separate per operation. The whole-session
    deadline is gate 4C's and is not represented here.

    `close_seconds` exists so a close cannot hang: a peer that accepts a FIN and
    never answers must not hold a worker.
    """

    connect_seconds: float = 10.0
    read_seconds: float = 30.0
    write_seconds: float = 10.0
    close_seconds: float = 5.0

    def __post_init__(self) -> None:
        _check_seconds("connect_seconds", self.connect_seconds)
        _check_seconds("read_seconds", self.read_seconds)
        _check_seconds("write_seconds", self.write_seconds)
        _check_seconds("close_seconds", self.close_seconds)


@dataclass(frozen=True, slots=True)
class TransportLimits:
    """How much a connection may read before it is abandoned."""

    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        for name, value in (
            ("max_line_bytes", self.max_line_bytes),
            ("max_total_bytes", self.max_total_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise SMTPContractError(f"{name} must be a whole number of bytes")
            if value <= 0:
                raise SMTPContractError(f"{name} must be positive")
        if self.max_total_bytes < self.max_line_bytes:
            raise SMTPContractError("the total limit cannot be smaller than one line")


@dataclass(frozen=True, slots=True)
class LineRead:
    """One complete line, without its terminator, within the limits."""

    line: bytes


@dataclass(frozen=True, slots=True)
class ReadFailed:
    """No line could be read, and why. The caller closes the connection."""

    failure: TransportFailure


ReadOutcome = LineRead | ReadFailed


@dataclass(frozen=True, slots=True)
class WriteSucceeded:
    """The command line reached the socket. Nothing is claimed about the peer."""

    payload_bytes: int


@dataclass(frozen=True, slots=True)
class WriteFailed:
    """The command line did not go out, and why. The caller closes."""

    failure: TransportFailure


WriteOutcome = WriteSucceeded | WriteFailed


@dataclass(frozen=True, slots=True)
class TLSNegotiated:
    """The connection is now encrypted, verified, and on the same peer."""


@dataclass(frozen=True, slots=True)
class TLSFailed:
    """The upgrade did not happen, and why, in this project's vocabulary.

    A failed upgrade is terminal. `docs/smtp-state-machine.md` has no transition
    from a TLS failure back to plaintext, so the caller closes rather than
    continuing — and none of these is ever evidence about the recipient.
    """

    failure: TransportFailure


TLSOutcome = TLSNegotiated | TLSFailed
