"""The deployment validation and version reports. Both are reporting only.

`prompts/08-limited-beta.md` work items 1 and 6: *a deployment validation
command* and *ruleset and dataset version reporting*.

**Neither report performs I/O of any kind.** No DNS lookup for a PTR or an SPF
record, no connection to port 25, no external address lookup, no mailbox check.
Every one of those is an outbound operation the beta has not been authorized to
make, and running one from a *validation* command would be the most surprising
place for this project's first unauthorized packet to come from.

**Neither report can satisfy a gate.** The strongest thing
`validate_deployment` says about a gate is `CONFIGURED_IN_PROCESS`, which means
"this deployment holds the setting the gate depends on" — evidence toward the
gate and never the gate. A configured sender identity does not mean the SPF
record exists, and the report says so in as many words.

**And it authorizes nothing.** `prompts/08-limited-beta.md`'s exit criteria give
the verification to a human, and `BetaAuthorization.external_probing_authorized`
is where that human's decision is recorded. Nothing here writes it, returns it,
or is consulted by it; a test asserts this module names it nowhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from emailcheck.classification.repository import PassiveDatasets
from emailcheck.domain.readiness import DEPLOYMENT_GATES, DeploymentGate, GateStatus
from emailcheck.security.identifiers import CANONICAL_INPUT_VERSION

if TYPE_CHECKING:  # pragma: no cover - import cycle only under type checking
    from emailcheck.composition import Deployment

#: The whole public surface of this module, and it is deliberately two reports
#: and the values they are made of.
#:
#: **This list is the barrier, not a convenience.** An independent review showed
#: that forbidding the identifier `external_probing_authorized` here is too
#: narrow: adding
#:
#: ```python
#: def beta_may_start(report: DeploymentReport) -> bool:
#:     return not report.requires_human_verification
#: ```
#:
#: names no beta type, imports nothing from the beta layer, and passed the whole
#: suite — while being exactly the "all thirteen reported clean, so go" shape
#: `prompts/08-limited-beta.md`'s exit criteria give to a human. So the contract
#: is stated the other way round: the public callables of this module are
#: *these*, an inspection test compares the module against this list, and adding
#: any public function at all fails until somebody puts it here on purpose.
#:
#: Private helpers are unrestricted. The thing being prevented is a **public**
#: predicate a caller elsewhere could wire to an authorization.
__all__ = [
    "DATASET_UNAVAILABLE",
    "UNAVAILABLE_DATASETS",
    "DeploymentReport",
    "GateReport",
    "VersionReport",
    "report_versions",
    "validate_deployment",
]

#: What a dataset reports when it is **both** declared unavailable and actually
#: empty.
#:
#: A stable category rather than an empty string: `prompts/08-limited-beta.md`
#: work item 6 asks for dataset *version* reporting, and an operator reading
#: `version=""` cannot tell "unavailable on purpose" from "the loader failed".
#: ADR 0007's Phase 8 deadline resolved these three as declared-unavailable, and
#: this is how that resolution reaches an operator.
DATASET_UNAVAILABLE: Final = "unavailable-by-declaration"

#: The datasets ADR 0007 declares unavailable for the limited beta.
#:
#: **Membership is a declaration, not an answer.** The declaration only applies
#: while the dataset is actually empty: a populated dataset reports its own
#: version whatever this set says. An independent review found the earlier build
#: keying the category on the name alone, which made
#: `src/emailcheck/data/passive/README.md`'s published promise — *populating a dataset later is
#: an ordinary data change, not a code change* — untrue, because the report
#: would have gone on saying "unavailable" over real data.
UNAVAILABLE_DATASETS: Final[frozenset[str]] = frozenset({"disposable", "free_mail", "provider"})


@dataclass(frozen=True, slots=True)
class GateReport:
    """One gate, as the validation command reports it."""

    key: str
    title: str
    status: GateStatus
    #: What an operator does next. Never "nothing"; a satisfied-looking gate
    #: still needs the human verification the exit criteria require.
    operator_action: str
    why: str

    def as_json_object(self) -> dict[str, object]:
        return {
            "gate": self.key,
            "title": self.title,
            "status": self.status.value,
            "operator_action": self.operator_action,
            "why": self.why,
        }


@dataclass(frozen=True, slots=True)
class DeploymentReport:
    """Every gate, and an explicit statement about what this report is not."""

    gates: tuple[GateReport, ...]
    profile: str
    active_probing: bool

    #: Repeated in the object rather than only in the printed output, because a
    #: caller reading the JSON is exactly the caller who might otherwise treat a
    #: clean report as an approval.
    disclaimer: str = (
        "This report is advisory. No gate can be passed by software: each is an "
        "external fact or a human commitment. The beta may start only after a "
        "human verifies every gate in docs/operations.md section 1."
    )

    @property
    def requires_human_verification(self) -> tuple[GateReport, ...]:
        return tuple(
            gate for gate in self.gates if gate.status is GateStatus.REQUIRES_HUMAN_VERIFICATION
        )

    @property
    def not_configured(self) -> tuple[GateReport, ...]:
        return tuple(
            gate for gate in self.gates if gate.status is GateStatus.NOT_CONFIGURED_IN_PROCESS
        )

    def as_json_object(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "active_probing": self.active_probing,
            "gates": [gate.as_json_object() for gate in self.gates],
            "requires_human_verification": len(self.requires_human_verification),
            "not_configured_in_process": len(self.not_configured),
            "disclaimer": self.disclaimer,
        }


def validate_deployment(deployment: Deployment) -> DeploymentReport:
    """Report every gate in `docs/operations.md` section 1, and check none.

    Reads the `Deployment` this process was configured with and nothing else.
    The three gates with in-process evidence are the ones whose *configuration*
    lives here; the other ten can only be verified outside this process, and
    saying so is more useful than a status that looks like an answer.
    """
    return DeploymentReport(
        gates=tuple(_report(gate, deployment) for gate in DEPLOYMENT_GATES),
        profile=deployment.profile.value,
        active_probing=deployment.active_probing,
    )


def _report(gate: DeploymentGate, deployment: Deployment) -> GateReport:
    status = GateStatus.REQUIRES_HUMAN_VERIFICATION
    action = gate.verified_how

    if gate.has_in_process_evidence:
        configured = _in_process_evidence(gate.key, deployment)
        status = (
            GateStatus.CONFIGURED_IN_PROCESS if configured else GateStatus.NOT_CONFIGURED_IN_PROCESS
        )
        action = (
            # Even a configured control is only configured. "Tested" is the word
            # docs/operations.md section 1 uses for all three of these, and a
            # test is an act somebody performs.
            f"Configuration is present in this process. Still required: {gate.verified_how}"
            if configured
            else f"Not configured in this process. Required: {gate.verified_how}"
        )

    return GateReport(
        key=gate.key, title=gate.title, status=status, operator_action=action, why=gate.why
    )


def _in_process_evidence(key: str, deployment: Deployment) -> bool:
    """Whether the configuration a gate depends on is present here.

    Deliberately narrow, and deliberately not clever: each answer is about a
    setting this process holds, never about the outside world.
    """
    if key == "kill_switch_tested":
        # The switch exists as a control and this deployment's starting state is
        # readable. Whether anybody has thrown it is not.
        return deployment.admin_state is not None
    if key == "rate_limits_tested":
        return deployment.rate_limits.global_concurrency > 0
    if key == "retention_deletion_tested":
        return deployment.retention.job_retention_seconds > 0
    return False


@dataclass(frozen=True, slots=True)
class VersionReport:
    """Every version a beta result must be comparable against.

    `prompts/08-limited-beta.md` work item 6. A measurement whose ruleset and
    dataset versions nobody recorded cannot be compared with a later one, and
    the Phase 8 evaluation report carries these forward.

    No secret is here, and none can be: this holds four strings and a mapping of
    dataset names to versions.
    """

    package_version: str
    aggregation_ruleset: str
    canonical_input_version: str
    dataset_versions: dict[str, str]
    #: Which datasets reported `unavailable-by-declaration` — declared *and*
    #: observed empty. A populated dataset never appears here.
    unavailable_datasets: tuple[str, ...]
    #: How many entries each dataset holds. The observation the category above
    #: is derived from, published so an operator can check the derivation
    #: instead of trusting it.
    dataset_entry_counts: dict[str, int]

    def as_json_object(self) -> dict[str, object]:
        return {
            "package_version": self.package_version,
            "aggregation_ruleset": self.aggregation_ruleset,
            "canonical_input_version": self.canonical_input_version,
            "dataset_versions": dict(self.dataset_versions),
            "unavailable_datasets": list(self.unavailable_datasets),
            "dataset_entry_counts": dict(self.dataset_entry_counts),
        }


def report_versions(
    *, package_version: str, aggregation_ruleset: str, datasets: PassiveDatasets
) -> VersionReport:
    """Report the versions **this deployment's datasets actually carry**.

    `datasets` is the deployment's own `PassiveDatasets` — the same object
    `PassiveClassifier` answers from — so the report describes the snapshot that
    produced the results, not a freshly constructed default. An independent
    review measured the earlier build reporting `role = empty` while the shipped
    role list was version `2026-08-07.1`, which is the one thing work item 6
    exists to prevent: a measurement whose recorded versions are not the
    versions it ran under cannot be compared with anything.

    Nothing is re-declared here. Versions come from `PassiveDatasets.versions`,
    the ruleset from a `Verdict`, and the canonical form from
    `security/identifiers`; a second copy of a version is a second thing to
    forget to bump.

    Three states, in this order, and the order is the point:

    | The dataset | Reported as |
    |---|---|
    | holds entries | its own version, whatever any declaration says |
    | is empty **and** declared unavailable | `unavailable-by-declaration` |
    | is empty | its own version — the repository's `empty-…` state |
    """
    versions = datasets.versions
    counts = datasets.entry_counts
    declared: list[str] = []
    reported: dict[str, str] = {}
    for name, version in versions.items():
        # Populated wins over the declaration. A dataset with data in it is
        # available by observation, and nothing here may say otherwise.
        if counts.get(name, 0) == 0 and name in UNAVAILABLE_DATASETS:
            reported[name] = DATASET_UNAVAILABLE
            declared.append(name)
        else:
            reported[name] = version
    return VersionReport(
        package_version=package_version,
        aggregation_ruleset=aggregation_ruleset,
        canonical_input_version=CANONICAL_INPUT_VERSION,
        dataset_versions=reported,
        unavailable_datasets=tuple(sorted(declared)),
        dataset_entry_counts=dict(sorted(counts.items())),
    )
