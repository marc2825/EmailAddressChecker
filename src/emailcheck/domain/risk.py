"""Risk flags, alone in a module because two layers need them.

`docs/requirements.md` section 4: risk is **orthogonal to deliverability**. A
disposable address may be likely deliverable and a role address may be invalid,
so a flag never overwrites a status and nothing here knows what a status is.

**It lives apart from `domain/verdict.py` for an import reason, and the import
reason is the architecture.** `domain/verdict.py` imports `Evidence` — a verdict
is assembled from observations — so `domain/evidence.py` cannot import it back.
Remediation C needed a producer to state a risk flag on one observation
(`Evidence.risk_flags`), which put the flag on both sides of that edge. A leaf
module both may import is the answer that keeps the direction acyclic; making
`Evidence` import `Verdict` would have inverted it.

`domain/verdict.py` re-exports the name, so nothing that already imports
`RiskFlag` from there had to change.
"""

from __future__ import annotations

from enum import StrEnum


class RiskFlag(StrEnum):
    """The published flags. `docs/requirements.md` section 4's list, verbatim."""

    DISPOSABLE = "disposable"
    ROLE_ACCOUNT = "role_account"
    FREE_MAIL = "free_mail"
    ACCEPT_ALL_SUSPECTED = "accept_all_suspected"
    PROVIDER_OPAQUE = "provider_opaque"
    INTERNATIONALIZED_LOCAL_PART = "internationalized_local_part"
    DOMAIN_CONFIGURATION_ANOMALY = "domain_configuration_anomaly"
