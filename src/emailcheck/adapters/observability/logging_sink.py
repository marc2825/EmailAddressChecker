"""The operator's copy of what went wrong, through the standard logger.

Phase 5 stop condition 5 asks that `internal_error` reach an operator rather
than disappearing into the `unknown` a caller sees constantly. This is the
default way it does.

**What is logged is the event, field by field.** `OperatorEvent` already refuses
an `@` in any of its fields and bounds their length, so this adapter formats
published vocabulary and nothing else: a kind, a reason code, a recipient
domain, a category this project chose. `docs/requirements.md` section 16 keeps a
full address out of ordinary logs, and section 16's analytics guidance is
exactly the shape of this record — aggregate by domain and reason.

There is no exception object, no traceback, and no remote text anywhere in this
module, and an inspection test says so.
"""

from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass, field

from emailcheck.ports.observability import OperatorEvent

#: A named logger, so a deployment can route operational events separately from
#: anything else this process writes.
LOGGER_NAME = "emailcheck.operator"

#: A value printed as it is. Anything else is printed with `repr`, so a space,
#: quote, or line break inside a field cannot break or forge a log line.
_TOKEN = re.compile(r"[A-Za-z0-9._:/+-]+")


def _field(value: str | None) -> str:
    if value is None:
        return "-"
    return value if _TOKEN.fullmatch(value) else repr(value)


@dataclass(frozen=True, slots=True)
class LoggingOperatorSink:
    """Writes one structured line per event, and never raises.

    `record` is called from inside a `finally`-shaped path in the verification
    service, so an exception here would replace an operational report with a
    different failure. Logging is best effort by design.
    """

    logger: logging.Logger = field(default_factory=lambda: logging.getLogger(LOGGER_NAME))

    def record(self, event: OperatorEvent) -> None:
        payload = {
            "event": event.kind.value,
            "reason": None if event.reason is None else event.reason.value,
            "domain": event.domain,
            "detail": event.detail,
        }
        # A broken handler must not turn an operational report into a request
        # failure. There is nothing useful to do about it and nowhere left to
        # report it to, so it is suppressed rather than logged.
        with contextlib.suppress(Exception):  # pragma: no cover - handler's own failure
            # The fields go into the message itself: a plain formatter prints
            # only the message, and `extra` is kept for structured handlers.
            self.logger.warning(
                "emailcheck.operator event=%s reason=%s domain=%s detail=%s",
                *(_field(payload[key]) for key in ("event", "reason", "domain", "detail")),
                extra={"emailcheck": payload},
            )


@dataclass(slots=True)
class CollectingOperatorSink:
    """Keeps events in memory. For a composition test, and for a lab profile.

    Production uses `LoggingOperatorSink`; this exists so a test can assert that
    a sink was called at all, which is the property Phase 5 stop condition 5
    actually requires.
    """

    events: list[OperatorEvent] = field(default_factory=list)

    def record(self, event: OperatorEvent) -> None:
        self.events.append(event)
