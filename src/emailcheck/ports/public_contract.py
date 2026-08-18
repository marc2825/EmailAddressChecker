"""The published data contract, as the transport and the ports speak it.

**This is a lower layer than the code that fills it in, and that is the whole
point of the file.** `ports/remote_check.py` describes talking to another
instance of this service, and it needed to name the type that crosses that
boundary — so it imported `application/public_job.py`, and a port depended on
the layer above it. `docs/architecture.md` runs the dependency the other way:
apps depend on application, application on domain and ports, adapters on ports.
The final system audit found the reversed edge.

So the *shape* moved down and the *projection* stayed up. What lives here is the
contract itself: the fields, their validation against published vocabulary, how
they serialize, and how an untrusted body is parsed back into them. What stays
in `application/` is the conversion from this project's own values — a `Verdict`,
a `CheckJob` — into that contract, because reading an internal record is
orchestration and orchestration does not belong in a port.

Both application modules re-export these names, so nothing that already imported
`PublicResult` or `PublicJob` from `application/` had to change, and the public
JSON, the API body, the CLI output, and the remote wire schema are byte-for-byte
what they were.

Nothing internal crosses this boundary: no `Evidence`, no `Evidence.details`, no
attempt record, no transcript, no exception text, no principal, no digest, no
cache key. A failure is a stable category from `JobFailure`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from emailcheck.domain.job import JobFailure, JobId, JobState
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.risk import RiskFlag
from emailcheck.domain.verdict import ConfidenceLevel, Status

_PUBLIC_CHECK_KEY: Final = "result"


@dataclass(frozen=True, slots=True)
class PublicCheck:
    """One layer's public summary: what it concluded, and nothing else."""

    result: str


@dataclass(frozen=True, slots=True)
class PublicResult:
    """What a caller is told. Built by allowlist from a `Verdict`.

    Every value is a published enum's `.value` — a documented string — rather
    than a Python `repr`. `Status.INVALID` is an implementation detail;
    `"invalid"` is the contract `docs/requirements.md` section 3 publishes.
    """

    status: str
    confidence: str
    primary_reason: str | None
    reasons: tuple[str, ...]
    risk_flags: tuple[str, ...]
    checks: Mapping[str, PublicCheck]
    no_message_data_sent: bool
    ruleset: str

    def __post_init__(self) -> None:
        if self.status not in {member.value for member in Status}:
            raise ValueError("a public result must carry a published status value")
        if self.confidence not in {member.value for member in ConfidenceLevel}:
            raise ValueError("a public result must carry a published confidence level")
        published = {member.value for member in ReasonCode}
        if self.primary_reason is not None and self.primary_reason not in published:
            raise ValueError("a public primary reason must be a published reason code")
        for reason in self.reasons:
            if reason not in published:
                raise ValueError("every public reason must be a published reason code")
        flags = {member.value for member in RiskFlag}
        for flag in self.risk_flags:
            if flag not in flags:
                raise ValueError("every public risk flag must be a published risk flag")
        if not isinstance(self.no_message_data_sent, bool):
            raise ValueError("no_message_data_sent must be a boolean")

    def as_json_object(self) -> dict[str, object]:
        """A JSON-safe mapping. Strings, booleans, lists, and nothing else.

        No float appears anywhere in this object, which is the structural half
        of "no uncalibrated score": there is no field a number could be put in
        without changing this method.
        """
        return {
            "status": self.status,
            "confidence": self.confidence,
            "primary_reason": self.primary_reason,
            "reasons": list(self.reasons),
            "risk_flags": list(self.risk_flags),
            "checks": {
                name: {_PUBLIC_CHECK_KEY: check.result} for name, check in self.checks.items()
            },
            "no_message_data_sent": self.no_message_data_sent,
            "ruleset": self.ruleset,
        }


@dataclass(frozen=True, slots=True)
class PublicJob:
    """One job, as published."""

    id: str
    state: str
    created_at: str
    updated_at: str
    result: PublicResult | None = None
    failure: str | None = None

    def __post_init__(self) -> None:
        if self.state not in {member.value for member in JobState}:
            raise ValueError("a public job must carry a published state")
        if self.failure is not None and self.failure not in {member.value for member in JobFailure}:
            raise ValueError("a public job failure must be a published category")
        if self.result is not None and self.state != JobState.COMPLETED.value:
            raise ValueError("only a completed job publishes a result")
        if self.failure is not None and self.state != JobState.FAILED.value:
            raise ValueError("only a failed job publishes a failure")
        JobId(self.id)

    def as_json_object(self) -> dict[str, object]:
        """A JSON-safe mapping. Strings, objects, null — and no number."""
        return {
            "id": self.id,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result": None if self.result is None else self.result.as_json_object(),
            "failure": self.failure,
        }


def public_result_from_json_object(payload: object) -> PublicResult:
    """Rebuild a result from a published body, refusing anything unpublished.

    Used only by `--remote`, where the body came from another instance rather
    than from this process's aggregator. The validation is `PublicResult`'s own:
    a remote server is not a trusted source of vocabulary, so a status,
    confidence level, reason, or risk flag this build does not publish is
    refused rather than displayed to a user as though this project had said it.

    This parses; it decides nothing. There is no branch here that could turn one
    published value into another.
    """
    if not isinstance(payload, dict):
        raise ValueError("a result must be an object")
    checks: dict[str, PublicCheck] = {}
    raw_checks = payload.get("checks")
    if isinstance(raw_checks, Mapping):
        for name, entry in raw_checks.items():
            if isinstance(entry, Mapping) and isinstance(entry.get(_PUBLIC_CHECK_KEY), str):
                checks[str(name)] = PublicCheck(result=str(entry[_PUBLIC_CHECK_KEY]))
    primary = payload.get("primary_reason")
    return PublicResult(
        status=_text(payload, "status"),
        confidence=_text(payload, "confidence"),
        primary_reason=None if primary is None else str(primary),
        reasons=_text_tuple(payload, "reasons"),
        risk_flags=_text_tuple(payload, "risk_flags"),
        checks=checks,
        no_message_data_sent=_safety_boolean(payload, "no_message_data_sent"),
        ruleset=_text(payload, "ruleset"),
    )


def _text(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"a result needs a text {name}")
    return value


def _safety_boolean(payload: Mapping[str, object], name: str) -> bool:
    """A published safety assertion, parsed strictly. Never coerced.

    **This replaced `bool(payload.get(name, True))`, which laundered a remote
    server's silence into this project's strongest promise.** Three ways in, all
    measured by the final system audit:

    - the field **absent** became `True`, so a server that had sent message
      content and simply omitted the field was displayed as one that had not;
    - the string `"false"` became `True`, because every non-empty string is
      truthy — the single most likely shape for a hand-rolled or
      loosely-typed remote encoder to produce;
    - `0`, `[]`, and `{}` became `False`, which is the right answer reached by
      the wrong rule and would have flipped the moment the encoder changed.

    `docs/requirements.md` section 2 makes "no message content was sent" a
    promise to the user rather than a field, and a promise this project repeats
    on another instance's behalf has to have been *made* by that instance. So
    the field is **required** and must be a real JSON boolean. Absence is a
    malformed body, not a safe default: `--remote` is the one path where the
    value is not this build's own invariant, and there is no honest way to infer
    it.

    `isinstance(value, bool)` rather than a truthiness test, and the `bool`
    check comes with the ordering Python requires — `True` and `False` are the
    only two values that pass, and `1` and `0` do not, even though they are
    `int` instances that compare equal.
    """
    if name not in payload:
        raise ValueError(f"a result needs a published {name}")
    value = payload[name]
    if not isinstance(value, bool):
        raise ValueError(f"a result needs a boolean {name}")
    return value


def _text_tuple(payload: Mapping[str, object], name: str) -> tuple[str, ...]:
    value = payload.get(name, ())
    if not isinstance(value, list | tuple):
        raise ValueError(f"a result needs a list of {name}")
    return tuple(str(item) for item in value)


def public_job_from_json_object(payload: object) -> PublicJob:
    """Parse a remote instance's answer, refusing anything unpublished.

    Used by `--remote`. The validation is the point: a remote server is not a
    trusted source of vocabulary, and `PublicJob` and `PublicResult` both refuse
    a status, confidence, reason, or flag this build does not publish. A
    malformed answer raises rather than being displayed as a result.
    """
    if not isinstance(payload, dict):
        raise ValueError("a job response must be an object")
    for name in ("id", "state", "created_at", "updated_at"):
        if not isinstance(payload.get(name), str):
            raise ValueError(f"a job response needs a text {name}")
    failure = payload.get("failure")
    if failure is not None and not isinstance(failure, str):
        raise ValueError("a job failure must be text or null")
    body = payload.get("result")
    return PublicJob(
        id=str(payload["id"]),
        state=str(payload["state"]),
        created_at=str(payload["created_at"]),
        updated_at=str(payload["updated_at"]),
        result=None if body is None else public_result_from_json_object(body),
        failure=failure,
    )
