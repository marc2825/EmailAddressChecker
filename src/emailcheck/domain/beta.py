"""Who may be probed during the limited beta, and on whose authority.

`docs/beta-report-template.md`: *require an explicit allowlist or
authorization record for beta targets*. This is that record, and it is a domain
value with no I/O in it — the loader lives in `application/beta.py`.

**The corpus is an allowlist, and an empty one permits nothing.** That is the
default and it is the safe direction: a beta harness whose corpus is missing must
probe nothing rather than fall back to whatever a caller typed.
`docs/beta-report-template.md` says manual tests "must use owned or explicitly
authorized infrastructure", so an address with no authorization record is not a
target this project may reach.

**Every entry carries three things and none is optional.** The address, the
controlled-truth class, and a free-text authorization reference an operator can
be held to. A target without a reference is one nobody has said yes to, and the
type refuses it rather than treating an empty string as consent.

**The truth classes are the repository's own.** `docs/test-strategy.md`'s
"Manual controlled network" section names exactly seven, and this enum is those
seven. Inventing an eighth would be inventing a beta category nobody asked for,
and a class like "a real address I found somewhere" is precisely what
`docs/beta-report-template.md`'s "do not populate third-party address lists"
forbids.

**A truth class is not a prediction.** It records what an operator *arranged* —
that a mailbox exists and receives, that an address was never created — and
`application/beta.py` compares it with a `Verdict` without either becoming the
other. `docs/requirements.md` section 1 is unchanged by a beta: this project
still does not prove mailbox existence, so an `owned_mailbox` entry answering
`likely_deliverable` is *agreement between an arrangement and an observation*,
never a proof that the observation was correct about existence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

#: The most targets one beta corpus may name. `docs/beta-report-template.md`
#: forbids mass tests, and a ceiling in the type is what stops an operator's
#: typo becoming one. Deliberately small: a limited beta over owned
#: infrastructure is tens of addresses, not thousands.
MAX_CORPUS_ENTRIES: Final = 200

#: Bounds on the authorization reference. Long enough for a ticket identifier, a
#: contract reference, or a sentence naming who agreed; short enough that it
#: cannot become a place to hide data.
MIN_AUTHORIZATION_LENGTH: Final = 8
MAX_AUTHORIZATION_LENGTH: Final = 200


class BetaCorpusError(ValueError):
    """A beta target this project may not accept."""


class BetaExecutionState(StrEnum):
    """What happened to one selected target, as an execution fact.

    **Deliberately separate from `Status`.** `docs/requirements.md` section 3
    publishes exactly four deliverability statuses, and an earlier build put
    `"not_run"` and `"refused"` into the same field — so a beta's "unknown
    distribution" was computed over a mixture of mailbox answers and harness
    bookkeeping. An execution state says what the *harness* did; a `Status` says
    what the *evidence* concluded, and only a completed run has one.

    Closed and exhaustive: `docs/beta-report-template.md`'s metrics are counted per
    target, so every selected target must land in exactly one of these.
    """

    #: The verification ran to a verdict. The only state carrying a `Status`.
    COMPLETED = "completed"
    #: A local operational refusal — admission, a budget, a kill switch, or the
    #: harness's own authorization. ADR 0013: not a verdict, not about the
    #: address.
    REFUSED = "refused"
    #: The verification **started** and the run's total budget expired before it
    #: answered. A remote host was contacted and no verdict exists.
    TIMED_OUT = "timed_out"
    #: Never started. The budget expired first, or this was a dry run.
    NOT_RUN = "not_run"


class ControlledTruth(StrEnum):
    """What an operator arranged, from `docs/test-strategy.md`'s own list.

    These are *arrangements*, not verdicts. Each names something an operator set
    up and can re-check independently of anything this project observes, which
    is the only kind of ground truth a beta evaluation may use:
    `docs/test-strategy.md` section 1 says correctness is measured by evidence
    class, and an SMTP reply is the thing being evaluated rather than the thing
    it is evaluated against.
    """

    #: A mailbox the operator owns and can confirm receives mail.
    OWNED_MAILBOX = "owned_mailbox"
    #: A local part the operator owns the domain for and has never created.
    OWNED_NONEXISTENT = "owned_nonexistent"
    #: An alias the operator configured to another owned mailbox.
    OWNED_ALIAS = "owned_alias"
    #: An address the operator configured to forward off the domain.
    OWNED_FORWARDING = "owned_forwarding"
    #: A domain the operator configured to accept every recipient.
    OWNED_ACCEPT_ALL = "owned_accept_all"
    #: A domain the operator published RFC 7505 Null MX for.
    OWNED_NULL_MX = "owned_null_mx"
    #: Somebody else's infrastructure, with written permission on file.
    AUTHORIZED_TENANT = "authorized_tenant"


#: The classes whose arrangement means "a mailbox is there to receive". Named as
#: a set rather than checked with an `if`, and deliberately **not** called
#: "expected likely_deliverable": an accept-all domain answers `250` to
#: everything, so agreement there says nothing about the mailbox, and
#: `docs/requirements.md` section 10 keeps accept-all out of the MVP entirely.
ARRANGED_RECEIVING: Final[frozenset[ControlledTruth]] = frozenset(
    {
        ControlledTruth.OWNED_MAILBOX,
        ControlledTruth.OWNED_ALIAS,
        ControlledTruth.OWNED_FORWARDING,
    }
)

#: The one class whose arrangement means "no mailbox was ever created here".
#: `owned_null_mx` is not in it: a Null MX domain has no route at all, which
#: Phase 2 answers without reaching a recipient, so it tests a different layer.
ARRANGED_ABSENT: Final[frozenset[ControlledTruth]] = frozenset({ControlledTruth.OWNED_NONEXISTENT})


@dataclass(frozen=True, slots=True)
class BetaTarget:
    """One address an operator has authorized, and what they arranged for it."""

    #: The submitted form. Validated as an address by `application/beta.py`
    #: through the ordinary Phase 1 parser — this type does not re-implement
    #: parsing, because a second syntax policy is how two of them drift apart.
    address: str
    truth: ControlledTruth
    #: Who authorized this, as something an operator can be held to: a ticket,
    #: a contract reference, a named agreement. Never empty, because an empty
    #: string is the shape "nobody said yes" takes when nobody checked.
    authorization: str

    def __post_init__(self) -> None:
        if not isinstance(self.address, str) or not self.address:
            raise BetaCorpusError("a beta target must carry an address")
        if not isinstance(self.truth, ControlledTruth):
            raise BetaCorpusError("a beta target must name a published truth class")
        reference = self.authorization
        if not isinstance(reference, str):
            raise BetaCorpusError("an authorization reference must be text")
        if not MIN_AUTHORIZATION_LENGTH <= len(reference.strip()) <= MAX_AUTHORIZATION_LENGTH:
            raise BetaCorpusError(
                "an authorization reference must be "
                f"{MIN_AUTHORIZATION_LENGTH}..{MAX_AUTHORIZATION_LENGTH} characters"
            )
        if not reference.isprintable():
            raise BetaCorpusError("an authorization reference carries a control character")


@dataclass(frozen=True, slots=True)
class BetaCorpus:
    """Every address this beta may reach, and nothing else.

    **Membership is the authorization.** `application/beta.py` asks this object
    whether an address is permitted and probes nothing that is not, so an
    operator adding a target has to add it *here* — there is no flag, no
    override, and no "just this once" argument anywhere in the harness.
    """

    targets: tuple[BetaTarget, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.targets, tuple):
            raise BetaCorpusError("a corpus is a fixed tuple of targets")
        if len(self.targets) > MAX_CORPUS_ENTRIES:
            raise BetaCorpusError(
                f"a beta corpus may name at most {MAX_CORPUS_ENTRIES} targets; "
                "a limited beta is not a mass test"
            )
        seen: set[str] = set()
        for target in self.targets:
            if not isinstance(target, BetaTarget):
                raise BetaCorpusError("a corpus holds BetaTarget entries")
            if target.address in seen:
                # Two rows for one address are two authorizations that can
                # disagree about what was arranged, and a run would probe it
                # twice for no reason.
                raise BetaCorpusError("a beta corpus names each address once")
            seen.add(target.address)

    def __len__(self) -> int:
        return len(self.targets)

    @property
    def is_empty(self) -> bool:
        return not self.targets

    def entry_for(self, address: str) -> BetaTarget | None:
        """The authorization record for `address`, or `None`.

        `None` is the answer for everything an operator has not written down,
        and the harness treats it as a refusal rather than as a default.
        """
        for target in self.targets:
            if target.address == address:
                return target
        return None

    def counts_by_truth(self) -> dict[str, int]:
        """How many entries of each class, for a report that names no address."""
        counts: dict[str, int] = {}
        for target in self.targets:
            counts[target.truth.value] = counts.get(target.truth.value, 0) + 1
        return dict(sorted(counts.items()))


@dataclass(frozen=True, slots=True)
class BetaLimits:
    """Hard ceilings on one beta run, validated like every other bound here.

    `docs/beta-report-template.md` forbids mass tests, so these are not tuning
    knobs with generous defaults — they are the thing that makes an operator's
    mistake bounded. Every one is a whole number, not a boolean, positive, and
    under a ceiling, which is the validation style Phases 4, 6, and 7 use.

    **There is no concurrency setting, and its absence is deliberate.** A run is
    sequential: one verification at a time. An earlier build carried a
    `max_concurrency` field that was validated and never read, so an operator
    setting it to four still got one — a knob that lies, which an independent
    review found. Nothing in `docs/beta-report-template.md` asks for configurable
    concurrency, and `docs/requirements.md` section 15's lab-active profile asks
    only for "low concurrency", which one satisfies. Sequential is also what
    makes this report's accounting exact: every target is started, refused,
    timed out, or not run, in corpus order. If a later Phase needs parallel
    beta execution it adds the field *and* the scheduler together.
    """

    #: How many targets one run may probe, whatever the corpus holds.
    max_targets: int = 50
    #: How long the whole run may take, in seconds.
    max_runtime_seconds: float = 900.0

    def __post_init__(self) -> None:
        _whole("max_targets", self.max_targets, MAX_CORPUS_ENTRIES)
        runtime = self.max_runtime_seconds
        if isinstance(runtime, bool) or not isinstance(runtime, int | float):
            raise BetaCorpusError("max_runtime_seconds must be a real number")
        if runtime != runtime or runtime in (float("inf"), float("-inf")):
            raise BetaCorpusError("max_runtime_seconds must be finite")
        if not 0 < runtime <= 6 * 60 * 60:
            raise BetaCorpusError("max_runtime_seconds must be positive and under six hours")


def _whole(name: str, value: int, ceiling: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BetaCorpusError(f"{name} must be a whole number, not a boolean")
    if value <= 0:
        raise BetaCorpusError(f"{name} must be positive")
    if value > ceiling:
        raise BetaCorpusError(f"{name} above {ceiling} is not a bound")


@dataclass(frozen=True, slots=True)
class BetaAuthorization:
    """The whole permission to run a beta, as one operator-supplied value.

    Holding the corpus, the limits, and the explicit opt-in together means the
    harness takes **one** object rather than several arguments that could be
    supplied inconsistently — and it means "is this run authorized" is one
    question with one answer.
    """

    corpus: BetaCorpus = field(default_factory=BetaCorpus)
    limits: BetaLimits = field(default_factory=BetaLimits)
    #: The operator's explicit statement that external probing is permitted.
    #:
    #: **`False` is the default and it is the whole point.**
    #: `docs/beta-report-template.md` requires the harness to be
    #: disabled by default, and its exit criteria require a *human* to verify
    #: every deployment gate in `docs/operations.md` before a beta starts. This
    #: field is where that human decision is recorded; nothing infers it.
    external_probing_authorized: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.external_probing_authorized, bool):
            raise BetaCorpusError("external authorization is a boolean an operator sets")

    @property
    def may_probe(self) -> bool:
        """Whether a run may open a socket at all.

        Both conditions, because either alone is a way to be wrong: an
        authorized run with no corpus has nothing it is allowed to reach, and a
        corpus with no authorization is a list nobody has approved acting on.
        """
        return self.external_probing_authorized and not self.corpus.is_empty
