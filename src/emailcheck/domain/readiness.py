"""The thirteen deployment gates, as one closed vocabulary.

`docs/operations.md` section 1 lists thirteen things that must be true before
service-active is enabled, and `docs/beta-report-template.md`
ask for a validation command and an operational checklist over them. Both, plus
the docs contract test, read **this** table — three hand-maintained copies of a
safety checklist is how one of them quietly loses a row.

**Nothing here checks anything.** This module is data and vocabulary: no DNS
lookup, no socket, no environment read. `application/readiness.py` builds a
report from it and the report is *reporting only*.

**No gate can be marked passed by software.** Every one of the thirteen is
either an external fact — a PTR record, an SPF record, an open port 25 — or a
human commitment such as "the abuse mailbox is monitored" and "an incident owner
is assigned". Neither is something a process can observe about itself, and
`docs/beta-report-template.md`'s exit criteria give the verification to a human on
purpose: *"The beta may start only after a human verifies every deployment gate
in `docs/operations.md`."*

So the strongest thing this vocabulary can say is `CONFIGURED_IN_PROCESS` — "the
configuration this process holds has the corresponding setting" — and that is
deliberately **not** a synonym for the gate being satisfied. A configured sender
identity does not mean the SPF record exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: The whole public surface. Data, a lookup, and nothing that decides anything —
#: see `application/readiness.py`'s `__all__` for why this is stated as a closed
#: list rather than left implicit.
__all__ = [
    "DEPLOYMENT_GATES",
    "GATE_KEYS",
    "DeploymentGate",
    "GateStatus",
    "gate_for",
]


class GateStatus(StrEnum):
    """What this process can honestly say about one gate.

    Three values, and the absence of a fourth is the point: there is no `PASSED`
    here, because nothing in this process can establish one of these gates.
    """

    #: This process holds configuration that the gate depends on. Evidence
    #: *toward* the gate, never the gate itself.
    CONFIGURED_IN_PROCESS = "configured_in_process"
    #: This process holds no such configuration. A definite negative, and the
    #: one status that is genuinely conclusive — an unconfigured sender identity
    #: means this deployment cannot probe at all.
    NOT_CONFIGURED_IN_PROCESS = "not_configured_in_process"
    #: Nothing in this process can observe it. An external fact or a human
    #: commitment; `docs/operations.md` section 1 and a person decide it.
    REQUIRES_HUMAN_VERIFICATION = "requires_human_verification"


@dataclass(frozen=True, slots=True)
class DeploymentGate:
    """One row of `docs/operations.md` section 1.

    `verified_how` is written for the operator who has to do it, because a
    checklist that says "confirm SPF" and stops is one that gets ticked without
    being checked.
    """

    #: A stable machine key. Never rendered as the gate's name to an operator.
    key: str
    #: The gate exactly as `docs/operations.md` section 1 words it.
    title: str
    #: Why it is on the list. One sentence, from the threat model where there is
    #: one, because an operator deciding whether to skip a gate needs the reason.
    why: str
    #: What the operator actually does. External commands are named as things
    #: for a human to run, never as things this project runs.
    verified_how: str
    #: Whether any in-process configuration bears on it at all. `False` means
    #: the validation command can only ever answer
    #: `REQUIRES_HUMAN_VERIFICATION`, and says so rather than staying silent.
    has_in_process_evidence: bool = False


#: The thirteen, in `docs/operations.md` section 1's order.
#:
#: The order is the document's and is preserved so an operator reading both sees
#: the same sequence. A row added here without a row there fails the docs test,
#: and vice versa.
DEPLOYMENT_GATES: Final[tuple[DeploymentGate, ...]] = (
    DeploymentGate(
        key="static_public_ip",
        title="static public IP",
        why=(
            "docs/requirements.md section 9 requires a static IP for active checks: "
            "reputation attaches to an address, and a changing one cannot carry PTR, "
            "SPF, or a complaint history."
        ),
        verified_how=(
            "Confirm with the hosting provider that the egress address is static and "
            "reserved to this deployment. Record the address in the checklist."
        ),
    ),
    DeploymentGate(
        key="outbound_port_25",
        title="outbound port 25 confirmed",
        why=(
            "Port 25 is the only port this project connects to, and many providers "
            "block it silently. Discovering that during a beta makes every result a "
            "connection timeout."
        ),
        verified_how=(
            "From the deployment host, confirm outbound 25 reaches an exchanger you "
            "own. This project does not test it: a probe from here would be an "
            "external connection the beta has not yet been authorized to make."
        ),
    ),
    DeploymentGate(
        key="ptr_configured",
        title="PTR configured",
        why=(
            "docs/requirements.md section 9 requires a PTR aligned with the EHLO host. "
            "Receiving sites treat a missing or generic PTR as a harvesting signal."
        ),
        verified_how=(
            "Look up the PTR for the egress IP from a host outside this deployment and "
            "confirm it names the EHLO FQDN."
        ),
    ),
    DeploymentGate(
        key="ehlo_forward_dns",
        title="EHLO forward DNS aligned",
        why=(
            "Section 9 requires forward DNS that resolves the EHLO host back to the "
            "egress IP. A PTR alone is half of the pair and proves nothing on its own."
        ),
        verified_how=(
            "Resolve the EHLO FQDN from outside this deployment and confirm it answers "
            "with the egress IP."
        ),
    ),
    DeploymentGate(
        key="spf_configured",
        title="SPF configured",
        why=(
            "Section 9 requires SPF authorizing the egress IP for the envelope sender's "
            "domain. Without it the MAIL FROM this project presents is unauthenticated."
        ),
        verified_how=(
            "Retrieve the SPF record for the configured envelope sender's domain and "
            "confirm it authorizes the egress IP."
        ),
    ),
    DeploymentGate(
        key="sender_mailbox_monitored",
        title="sender mailbox monitored",
        why=(
            "Section 9 requires a managed envelope sender. A bounce or a reply that "
            "nobody reads is a complaint this project never learns about."
        ),
        verified_how=(
            "Confirm a named person or rota reads the envelope sender's mailbox, and record who."
        ),
    ),
    DeploymentGate(
        key="abuse_postmaster_monitored",
        title="abuse and postmaster mailboxes monitored",
        why=(
            "Section 9 requires monitored abuse and postmaster channels. "
            "docs/threat-model.md's sender-reputation controls name the abuse mailbox "
            "as the route a receiving operator uses to reach you before blocklisting."
        ),
        verified_how=(
            "Send a test message to each from outside and confirm a monitored human "
            "receives it. Record the rota."
        ),
    ),
    DeploymentGate(
        key="hosting_terms_reviewed",
        title="hosting terms reviewed",
        why=(
            "Section 9 requires a provider and host policy that permits the use. Many "
            "hosting agreements forbid exactly this traffic pattern."
        ),
        verified_how=(
            "Read the acceptable-use policy and record who reviewed it and when. If it "
            "is ambiguous, get written confirmation before the beta."
        ),
    ),
    DeploymentGate(
        key="kill_switch_tested",
        title="global kill switch tested",
        why=(
            "docs/operations.md section 2 makes the global switch the first control. A "
            "switch nobody has thrown is one nobody knows works, and it is needed at "
            "exactly the moment there is no time to find out."
        ),
        verified_how=(
            "Throw the switch on the deployment, confirm a queued job stops and a new "
            "active submission is refused, then restore it. docs/runbooks/stop-active-checks.md."
        ),
        has_in_process_evidence=True,
    ),
    DeploymentGate(
        key="rate_limits_tested",
        title="rate limits tested",
        why=(
            "Destination pacing is what keeps this project from resembling the "
            "harvesting docs/threat-model.md describes. Untested limits are a "
            "configuration nobody has exercised."
        ),
        verified_how=(
            "Exercise the configured limits against an exchanger you own and confirm "
            "pacing and refusals behave as configured."
        ),
        has_in_process_evidence=True,
    ),
    DeploymentGate(
        key="private_egress_blocked",
        title="private-network egress blocked",
        why=(
            "docs/architecture.md section 5 requires worker egress limited to DNS and "
            "allowed SMTP destinations. The destination policy refuses private ranges, "
            "and a network-level block is the second barrier behind it."
        ),
        verified_how=(
            "Confirm at the firewall or security group that the worker cannot reach "
            "internal ranges. The in-process policy is not a substitute."
        ),
    ),
    DeploymentGate(
        key="retention_deletion_tested",
        title="retention deletion tested",
        why=(
            "docs/privacy.md section 7 requires deletion to be implemented and tested. "
            "A retention policy that has never deleted anything is a claim rather than "
            "a control."
        ),
        verified_how=(
            "Run a retention sweep against the deployment store and confirm expired "
            "records are gone and the run is audited. docs/runbooks/privacy-deletion.md."
        ),
        has_in_process_evidence=True,
    ),
    DeploymentGate(
        key="incident_owner_assigned",
        title="incident owner assigned",
        why=(
            "SECURITY.md requires an incident log and owner. Every runbook escalates to "
            "somebody, and an unnamed somebody is nobody."
        ),
        verified_how=("Name the person and the deputy, and record where the incident log lives."),
    ),
)

#: The thirteen keys, for the tests and the checklist.
GATE_KEYS: Final[tuple[str, ...]] = tuple(gate.key for gate in DEPLOYMENT_GATES)

if len(DEPLOYMENT_GATES) != 13:  # pragma: no cover - a definition error
    raise ValueError("docs/operations.md section 1 lists thirteen deployment gates")

if len(set(GATE_KEYS)) != len(GATE_KEYS):  # pragma: no cover - a definition error
    raise ValueError("every deployment gate needs a distinct key")


def gate_for(key: str) -> DeploymentGate:
    """The gate with this key, or a `KeyError` naming what was asked for."""
    for gate in DEPLOYMENT_GATES:
        if gate.key == key:
            return gate
    raise KeyError(f"no deployment gate named {key!r}")
