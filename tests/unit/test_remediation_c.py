"""Four findings that each let something outlive the thing that produced it.

C7  a cached verdict outlived the passive dataset snapshot that decided it.
C11 an account's data outlived the deletion `docs/privacy.md` promises.
C12 an MX configuration anomaly did not outlive Phase 3 at all.
C13 a port outlived the dependency direction by importing the layer above it.

Every test here drives production code. The cache tests use a real temporary
`SQLiteVerdictStore`, the deletion tests use all three real stores, and the
anomaly tests run the real classifier and the real aggregator. Nothing opens a
socket and nothing sleeps.
"""

from __future__ import annotations

import ast
import asyncio
import sqlite3
import subprocess
import sys
import threading
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from tests.phase6_fixtures import (
    MX_ADDRESS,
    OBSERVED_AT,
    PRINCIPAL,
    FakeClock,
    FakeRandomSource,
    FakeResolver,
    InMemoryVerdictStore,
    RecordingExecutor,
    RecordingOperatorSink,
    ScriptedSMTPVerification,
    build_service,
)
from tests.phase7_fixtures import CORRELATION_KEY, CountingQuotaStore, SteppableClock

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.storage.account_fence import AccountAuthorityError
from emailcheck.adapters.storage.sqlite_account_state import SQLiteAccountStateStore
from emailcheck.adapters.storage.sqlite_batch_store import SQLiteBatchStore
from emailcheck.adapters.storage.sqlite_job_store import SQLiteJobStore
from emailcheck.adapters.storage.sqlite_store import SQLiteVerdictStore
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.account_deletion import AccountDeletionService
from emailcheck.application.admin import AdminControl
from emailcheck.application.jobs import CheckJob, JobService, _stored
from emailcheck.application.public_result import public_result
from emailcheck.application.verdict_cache import VerdictCache
from emailcheck.classification.datasets import DatasetMetadata, LocalPartDataset
from emailcheck.classification.repository import PassiveDatasets, load_shipped_datasets
from emailcheck.domain.batch import BatchRowState
from emailcheck.domain.dns import AddressLookup, MXLookup, MXRecord, apply_ttl_policy
from emailcheck.domain.job import IdempotencyKey, JobError, JobId
from emailcheck.domain.risk import RiskFlag
from emailcheck.domain.verdict import Status
from emailcheck.ports.batch_store import BatchArtifact, StoredBatch, StoredBatchRow
from emailcheck.ports.job_store import StoredJob

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 5.0
NOW: Final = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
DOMAIN: Final = "example.test"
MX_HOST: Final = "mx1.example.test"
ROLE_ADDRESS: Final = f"support@{DOMAIN}"


# --- C7: the passive dataset fingerprint -------------------------------------


def role_dataset(*names: str, version: str) -> PassiveDatasets:
    """A snapshot whose role list is exactly `names`."""
    return PassiveDatasets(
        roles=LocalPartDataset(
            local_parts=frozenset(names),
            metadata=DatasetMetadata(
                name="role",
                source_url="https://example.test/roles",
                license="test",
                version=version,
                retrieved_at="2026-08-17",
                checksum="0" * 64,
                normalization="lowercase",
                update_frequency="never",
                maintainer="tests",
            ),
        )
    )


SNAPSHOT_A: Final = role_dataset(version="role-v1")
SNAPSHOT_B: Final = role_dataset("support", version="role-v2")


def test_the_two_snapshots_really_do_classify_the_same_address_differently() -> None:
    """The premise, checked before anything is concluded from it.

    A cache test whose two configurations produce the same answer proves
    nothing about the key, so this pins that snapshot B flags `support` as a
    role account and snapshot A does not.
    """
    assert SNAPSHOT_A.versions["role"] != SNAPSHOT_B.versions["role"]
    assert SNAPSHOT_A.entry_counts["role"] == 0
    assert SNAPSHOT_B.entry_counts["role"] == 1


def test_the_fingerprint_is_deterministic_and_carries_nothing() -> None:
    """Same snapshot, same fingerprint — across objects and across processes.

    Determinism is the property a cache key needs and the one `hash()` does not
    have: it is salted per process, so a fingerprint built on it would flush the
    cache on every restart. And a digest rather than a path or a version list,
    so nothing about the filesystem reaches a stored row.
    """
    assert SNAPSHOT_A.fingerprint == role_dataset(version="role-v1").fingerprint
    assert PassiveDatasets().fingerprint == PassiveDatasets().fingerprint
    fingerprint = load_shipped_datasets().fingerprint
    assert len(fingerprint) == 32
    assert set(fingerprint) <= set("0123456789abcdef")
    for leak in ("/", "\\", "@", "role", "disposable", ".toml"):
        assert leak not in fingerprint


def test_a_changed_snapshot_changes_the_fingerprint() -> None:
    """Version *and* entry count, so neither an unbumped edit nor a same-size
    replacement can pass as the snapshot it replaced."""
    assert SNAPSHOT_A.fingerprint != SNAPSHOT_B.fingerprint
    same_version_more_entries = role_dataset("support", "sales", version="role-v2")
    assert same_version_more_entries.fingerprint != SNAPSHOT_B.fingerprint
    assert PassiveDatasets().fingerprint != load_shipped_datasets().fingerprint


def cache_for(store: SQLiteVerdictStore, datasets: PassiveDatasets) -> VerdictCache:
    return VerdictCache(
        store=store,
        clock=FakeClock(),
        random=FakeRandomSource(prefix="rec"),
        correlation_key=CORRELATION_KEY,
        passive_dataset_fingerprint=datasets.fingerprint,
    )


async def classify(datasets: PassiveDatasets, address: str = ROLE_ADDRESS) -> object:
    """One whole verification under a given snapshot, with no SMTP answer."""
    ttl = apply_ttl_policy(3600, positive=True)
    resolver = FakeResolver(
        mx={DOMAIN: MXLookup(records=(MXRecord(preference=10, exchange=MX_HOST),), ttl=ttl)},
        a={MX_HOST: AddressLookup(addresses=(MX_ADDRESS,), ttl=ttl)},
    )
    service, _, _ = build_service(
        resolver=resolver, smtp=ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    )
    service = type(service)(
        syntax=service.syntax,
        routes=service.routes,
        passive=type(service.passive)(datasets=datasets, clock=FakeClock()),
        admission=service.admission,
        operator=service.operator,
        smtp=service.smtp,
        limits=service.limits,
        guard=service.guard,
        sender_identity=service.sender_identity,
        destination_allowlist=service.destination_allowlist,
    )
    async with asyncio.timeout(OUTER_BOUND):
        return await service.verify(address, principal=PRINCIPAL, active=True)


@asyncio_test
async def test_a_verdict_cached_under_one_snapshot_is_not_served_under_another(
    tmp_path: Path,
) -> None:
    """The defect, as the behaviour that now holds.

    Everything about the request is identical — account, target, sender
    identity, aggregation ruleset — and only the passive dataset snapshot
    changed. Before Remediation C the old verdict came back, so a caller was
    told `support@example.test` carried no role flag for as long as
    `docs/requirements.md` section 13 priced the row.
    """
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.db")
    store.initialize()
    under_a = await classify(SNAPSHOT_A)
    saved = await cache_for(store, SNAPSHOT_A).save(
        _target(under_a),
        account="acct-1",
        verdict=under_a.verdict,
        route_ttl=3600,
        expected_generation=0,
    )
    assert saved is True
    assert RiskFlag.ROLE_ACCOUNT not in under_a.verdict.risk_flags

    hit_under_b = await cache_for(store, SNAPSHOT_B).find(
        _target(under_a), account="acct-1", ruleset=under_a.verdict.ruleset
    )

    assert hit_under_b is None, "a verdict from the previous dataset snapshot was served"


@asyncio_test
async def test_the_same_snapshot_still_hits_the_cache(tmp_path: Path) -> None:
    """The positive control. An overcorrection that keyed on something unstable
    would disable caching entirely and pass every test above."""
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.db")
    store.initialize()
    outcome = await classify(SNAPSHOT_A)
    await cache_for(store, SNAPSHOT_A).save(
        _target(outcome),
        account="acct-1",
        verdict=outcome.verdict,
        route_ttl=3600,
        expected_generation=0,
    )

    hit = await cache_for(store, SNAPSHOT_A).find(
        _target(outcome), account="acct-1", ruleset=outcome.verdict.ruleset
    )

    assert hit is not None
    assert hit.status == outcome.verdict.status.value


@asyncio_test
async def test_the_fresh_classification_under_the_new_snapshot_carries_the_new_flag(
    tmp_path: Path,
) -> None:
    """A miss is only useful if what replaces it is the current answer."""
    under_b = await classify(SNAPSHOT_B)

    assert RiskFlag.ROLE_ACCOUNT in under_b.verdict.risk_flags
    assert "role_account" in public_result(under_b.verdict).risk_flags


def test_the_stored_row_carries_the_fingerprint_and_the_schema_moved_with_it(
    tmp_path: Path,
) -> None:
    """A version-3 file has no fingerprint column, and the only value a
    migration could assume for it is the one the column exists to stop being
    assumed. Refused by version instead."""
    from emailcheck.adapters.storage.sqlite_store import SCHEMA_VERSION, StoreSchemaError

    assert SCHEMA_VERSION == 5
    path = tmp_path / "old.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            "CREATE TABLE schema_version (version INTEGER NOT NULL);"
            "INSERT INTO schema_version (version) VALUES (3);"
        )
    with pytest.raises(StoreSchemaError):
        SQLiteVerdictStore(path=path).initialize()


def test_the_configured_datasets_report_the_fingerprint_the_cache_uses(tmp_path: Path) -> None:
    """`report_versions`, the classifier, and the cache must describe one
    snapshot. Two readings of the configuration is how they stop agreeing."""
    from emailcheck.composition import Deployment, build_verification_stack

    datasets = load_shipped_datasets()
    stack = build_verification_stack(
        Deployment(
            api_keys={"acct-1": "k" * 40}, correlation_key=b"c" * 32, passive_datasets=datasets
        )
    )

    assert stack.verification.passive.datasets is datasets
    assert stack.cache is None  # no store configured, so no cache to compare
    withstore = build_verification_stack(
        Deployment(
            api_keys={"acct-1": "k" * 40},
            correlation_key=b"c" * 32,
            passive_datasets=datasets,
            store_path=tmp_path / "verdicts.sqlite3",
            account_state_path=tmp_path / "accounts.sqlite3",
        )
    )
    assert withstore.cache is not None
    assert withstore.cache.passive_dataset_fingerprint == datasets.fingerprint
    assert withstore.verification.passive.datasets.fingerprint == datasets.fingerprint


def _target(outcome: object) -> object:
    assert outcome.target is not None  # type: ignore[attr-defined]
    return outcome.target  # type: ignore[attr-defined]


# --- C12: the MX configuration anomaly ---------------------------------------


async def verify_route(*records: MXRecord) -> object:
    ttl = apply_ttl_policy(3600, positive=True)
    resolver = FakeResolver(
        mx={DOMAIN: MXLookup(records=records, ttl=ttl)},
        a={MX_HOST: AddressLookup(addresses=(MX_ADDRESS,), ttl=ttl)},
    )
    service, _, _ = build_service(
        resolver=resolver, smtp=ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    )
    async with asyncio.timeout(OUTER_BOUND):
        return await service.verify(f"user@{DOMAIN}", principal=PRINCIPAL, active=True)


@asyncio_test
async def test_a_usable_route_with_a_null_mx_publishes_the_anomaly_flag() -> None:
    """The exact case the final system audit named.

    A Null MX published alongside real exchangers is
    `RouteAnomaly.NULL_MX_WITH_OTHER_RECORDS`: the route is usable and the
    configuration is wrong. Phase 3 saw it, and the published risk flags were
    empty — the observation stopped at `details["anomaly_count"]`, which nothing
    downstream reads.
    """
    outcome = await verify_route(
        MXRecord(preference=10, exchange=MX_HOST), MXRecord(preference=0, exchange=".")
    )

    assert RiskFlag.DOMAIN_CONFIGURATION_ANOMALY in outcome.verdict.risk_flags
    assert "domain_configuration_anomaly" in public_result(outcome.verdict).risk_flags


@asyncio_test
async def test_the_anomaly_changes_no_status() -> None:
    """`docs/requirements.md` section 4: risk is orthogonal to deliverability.

    This is why the flag rides as a typed signal rather than as
    `ReasonCode.MX_CONFIGURATION_ANOMALY`, which the aggregator places in tier 4
    — correctly, for the route outcome that has nowhere to connect. Publishing
    the flag through the reason would have traded a lost flag for a wrong status.
    """
    anomalous = await verify_route(
        MXRecord(preference=10, exchange=MX_HOST), MXRecord(preference=0, exchange=".")
    )
    normal = await verify_route(MXRecord(preference=10, exchange=MX_HOST))

    assert anomalous.verdict.status is Status.LIKELY_DELIVERABLE
    assert anomalous.verdict.status is normal.verdict.status
    assert anomalous.verdict.primary_reason is normal.verdict.primary_reason
    assert anomalous.verdict.confidence == normal.verdict.confidence


@asyncio_test
async def test_a_normal_route_raises_no_anomaly_flag() -> None:
    """The positive control: not every domain is anomalous."""
    outcome = await verify_route(MXRecord(preference=10, exchange=MX_HOST))

    assert outcome.verdict.risk_flags == frozenset()


@asyncio_test
async def test_a_pure_null_mx_keeps_its_terminal_semantics() -> None:
    """RFC 7505's form is a refusal, not an anomaly, and stays `invalid`."""
    outcome = await verify_route(MXRecord(preference=0, exchange="."))

    assert outcome.verdict.status is Status.INVALID
    assert RiskFlag.DOMAIN_CONFIGURATION_ANOMALY not in outcome.verdict.risk_flags


@asyncio_test
async def test_an_anomaly_bearing_verdict_survives_the_cache(tmp_path: Path) -> None:
    """A flag that disappears on a cache hit is a flag that exists only when the
    caller is unlucky."""
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.db")
    store.initialize()
    outcome = await verify_route(
        MXRecord(preference=10, exchange=MX_HOST), MXRecord(preference=0, exchange=".")
    )
    cache = cache_for(store, SNAPSHOT_A)
    assert await cache.save(
        _target(outcome),
        account="acct-1",
        verdict=outcome.verdict,
        route_ttl=3600,
        expected_generation=0,
    )

    reopened = SQLiteVerdictStore(path=tmp_path / "verdicts.db")
    reopened.initialize()
    hit = await cache_for(reopened, SNAPSHOT_A).find(
        _target(outcome), account="acct-1", ruleset=outcome.verdict.ruleset
    )

    assert hit is not None
    assert "domain_configuration_anomaly" in hit.risk_flags


@asyncio_test
async def test_an_anomaly_bearing_result_survives_the_job_store(tmp_path: Path) -> None:
    """And through the persisted job projection a restarted process reads."""
    from emailcheck.application.jobs import CheckJob, _public, _stored
    from emailcheck.domain.job import JobAdmission, JobState

    outcome = await verify_route(
        MXRecord(preference=10, exchange=MX_HOST), MXRecord(preference=0, exchange=".")
    )
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()
    job = CheckJob(
        id=JobId("anomaly-job-0001xxxxxxx"),
        owner="acct-1",
        state=JobState.COMPLETED,
        created_at=OBSERVED_AT,
        updated_at=OBSERVED_AT,
        result=public_result(outcome.verdict),
    )
    await store.save(
        _stored(job, target_digest=None, idempotency=None, admission=JobAdmission.NOT_REQUIRED),
        expected_generation=0,
    )

    reopened = SQLiteJobStore(path=tmp_path / "jobs.db")
    reopened.initialize()
    row = await reopened.load("anomaly-job-0001xxxxxxx")

    assert row is not None
    rebuilt = _public(row)
    assert rebuilt is not None
    assert "domain_configuration_anomaly" in rebuilt.risk_flags


# --- C13: the dependency direction -------------------------------------------

SOURCE: Final = Path(__file__).resolve().parents[2] / "src" / "emailcheck"


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


@pytest.mark.parametrize("layer", ["domain", "ports"])
def test_no_lower_layer_module_imports_the_application_layer(layer: str) -> None:
    """`docs/architecture.md`'s direction, as a property of the imports.

    `ports/remote_check.py` imported `application/public_job.py` so that it
    could name the type crossing its boundary, which made a port depend on the
    layer above it — the final system audit found it. The contract moved down to
    `ports/public_contract.py` and the projection stayed up.

    Parameterized over the whole of both layers rather than that one file: a
    rule that only holds for the module somebody remembered is not a rule.
    """
    offenders = [
        (path.relative_to(SOURCE).as_posix(), module)
        for path in sorted((SOURCE / layer).rglob("*.py"))
        for module in imported_modules(path)
        if module.startswith("emailcheck.application")
    ]

    assert offenders == [], offenders


def test_the_remote_port_speaks_the_lower_layer_contract() -> None:
    """Named explicitly as well, because the sweep above would also pass if the
    port stopped naming a job type at all."""
    modules = imported_modules(SOURCE / "ports" / "remote_check.py")

    assert "emailcheck.ports.public_contract" in modules
    assert not any(module.startswith("emailcheck.application") for module in modules)


def test_the_remote_adapter_does_not_reach_around_into_application() -> None:
    """An adapter that compensated by importing application would move the
    violation rather than fix it."""
    modules = imported_modules(SOURCE / "adapters" / "http" / "urllib_client.py")

    assert "emailcheck.ports.public_contract" in modules
    assert not any(module.startswith("emailcheck.application") for module in modules)


def test_the_contract_module_imports_only_the_domain() -> None:
    """It is a data contract, so it may know published vocabulary and nothing
    else — no store, no clock, no orchestration."""
    modules = imported_modules(SOURCE / "ports" / "public_contract.py")
    internal = {module for module in modules if module.startswith("emailcheck")}

    assert internal
    assert all(module.startswith("emailcheck.domain") for module in internal), internal


def test_the_published_schema_is_unchanged_by_the_move() -> None:
    """The refactor must be invisible from outside. Field names, order, and
    types are asserted against a literal rather than against the code."""
    from emailcheck.application.public_job import public_job
    from emailcheck.domain.job import JobFailure, JobState

    body = public_job(
        job_id=JobId("schema-job-0001xxxxxxxx"),
        state=JobState.FAILED,
        created_at=OBSERVED_AT,
        updated_at=OBSERVED_AT,
        result=None,
        failure=JobFailure.SERVICE_ERROR,
    ).as_json_object()

    assert body == {
        "id": "schema-job-0001xxxxxxxx",
        "state": "failed",
        "created_at": OBSERVED_AT.isoformat(),
        "updated_at": OBSERVED_AT.isoformat(),
        "result": None,
        "failure": "service_error",
    }


def test_every_legacy_import_path_still_resolves() -> None:
    """Nothing that imported these names had to change."""
    from emailcheck.application.public_job import (
        PublicJob,
        public_job,
        public_job_from_json_object,
    )
    from emailcheck.application.public_result import (
        PublicCheck,
        PublicResult,
        public_result,
        public_result_from_json_object,
    )
    from emailcheck.ports.public_contract import PublicJob as PortJob
    from emailcheck.ports.public_contract import PublicResult as PortResult

    assert PublicJob is PortJob
    assert PublicResult is PortResult
    for name in (
        PublicCheck,
        public_job,
        public_job_from_json_object,
        public_result,
        public_result_from_json_object,
    ):
        assert callable(name)


# --- C11: account-wide deletion ----------------------------------------------


@dataclass(slots=True)
class Stores:
    """All three real stores over one directory, plus the services above them."""

    root: Path
    executor: RecordingExecutor = field(default_factory=RecordingExecutor)
    operator: RecordingOperatorSink = field(default_factory=RecordingOperatorSink)
    jobs: JobService = field(init=False)
    admin: AdminControl = field(init=False)
    cache: VerdictCache = field(init=False)
    deletion: AccountDeletionService = field(init=False)

    def __post_init__(self) -> None:
        self.build()

    @property
    def verdicts(self) -> SQLiteVerdictStore:
        store = SQLiteVerdictStore(path=self.root / "verdicts.db")
        store.initialize()
        return store

    @property
    def job_store(self) -> SQLiteJobStore:
        store = SQLiteJobStore(path=self.root / "jobs.db")
        store.initialize()
        return store

    @property
    def account_state(self) -> SQLiteAccountStateStore:
        store = SQLiteAccountStateStore(path=self.root / "accounts.db")
        store.initialize()
        return store

    @property
    def batch_store(self) -> SQLiteBatchStore:
        store = SQLiteBatchStore(path=self.root / "batches.db")
        store.initialize()
        return store

    def build(self) -> None:
        """Construct fresh services over the same files — a restart."""
        clock = SteppableClock()
        metrics = InMemoryMetrics()
        guard = AbuseGuard(
            quota=CountingQuotaStore(),
            clock=clock,
            metrics=metrics,
            operator=self.operator,
            correlation_key=CORRELATION_KEY,
        )
        self.admin = AdminControl(
            guard=guard, clock=clock, metrics=metrics, correlation_key=CORRELATION_KEY
        )
        service, _, _ = build_service(smtp=ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",)))
        self.cache = VerdictCache(
            store=self.verdicts,
            clock=FakeClock(),
            random=FakeRandomSource(prefix="rec"),
            correlation_key=CORRELATION_KEY,
            passive_dataset_fingerprint=SNAPSHOT_A.fingerprint,
        )
        self.jobs = JobService(
            verification=service,
            executor=self.executor,
            clock=FakeClock(),
            random=FakeRandomSource(prefix="job"),
            operator=self.operator,
            correlation_key=CORRELATION_KEY,
            cache=self.cache,
            store=self.job_store,
            account_state=self.account_state,
        )
        self.deletion = AccountDeletionService(
            admin=self.admin,
            operator=self.operator,
            account_state=self.account_state,
            cache=self.cache,
            jobs=self.jobs,
            job_store=self.job_store,
            batches=self.batch_store,
        )

    async def seed(self, account: str, *, fingerprint: str | None = None) -> None:
        """One record of every kind, for one account."""
        from emailcheck.domain.verdict import Status as S
        from emailcheck.ports.verdict_store import StoredVerdict

        await self.verdicts.save(
            StoredVerdict(
                record_id=f"rec-{account}-{fingerprint or 'a'}",
                account_digest=_digest(account),
                target_digest=_digest(f"target-{account}"),
                sender_identity_digest=_digest("sender"),
                status=S.UNKNOWN,
                confidence="low",
                primary_reason=None,
                reasons=(),
                risk_flags=(),
                checks=(),
                aggregation_ruleset="r1",
                passive_dataset_fingerprint=fingerprint or SNAPSHOT_A.fingerprint,
                created_at=NOW,
                expires_at=NOW + timedelta(hours=1),
            ),
            expected_generation=0,
        )
        await self.batch_store.save_batch(
            StoredBatch(
                batch_id=f"batch-{account}",
                account=account,
                created_at=NOW,
                expires_at=NOW + timedelta(days=1),
                input_rows=1,
                skipped_rows=0,
                rows=(
                    StoredBatchRow(
                        number=1, state=BatchRowState.QUEUED, submitted=f"u@{account}.test"
                    ),
                ),
            )
        )
        await self.batch_store.save_artifact(
            BatchArtifact(
                batch_id=f"batch-{account}",
                account=account,
                created_at=NOW,
                expires_at=NOW + timedelta(days=1),
                media_type="text/csv",
                content="report",
                complete=True,
            )
        )

    def rows(self, table: str, column: str, value: str) -> int:
        database = {"verdicts": "verdicts.db", "jobs": "jobs.db"}.get(table, "batches.db")
        with closing(sqlite3.connect(self.root / database)) as connection, connection:
            return int(
                connection.execute(
                    # Table and column are chosen from this fixture's own
                    # literals, never from data. Parameterized where it matters.
                    f"SELECT count(*) FROM {table} WHERE {column} = ?",  # noqa: S608
                    (value,),
                ).fetchone()[0]
            )


def _digest(value: str) -> str:
    from emailcheck.security.identifiers import correlation_digest

    return correlation_digest(CORRELATION_KEY, value)


@asyncio_test
async def test_deleting_one_account_removes_it_from_every_store(tmp_path: Path) -> None:
    """`docs/privacy.md` section 7's promise, as one operation.

    Before Remediation C the runbook described manual steps and no production
    code performed them, so an account-requested deletion depended entirely on
    an operator remembering five methods.
    """
    stores = Stores(root=tmp_path)
    await stores.seed("acct-a")
    await stores.seed("acct-b")
    key = IdempotencyKey("handle-" + "a" * 20)
    await stores.jobs.submit("user@example.test", principal=PRINCIPAL, idempotency_key=key)
    account = PRINCIPAL.rate_limit_account
    await stores.seed(account)

    report = await stores.deletion.delete(account)

    assert report.complete is True
    assert report.failed_stores == ()
    assert report.total_removed > 0


@asyncio_test
async def test_another_account_survives_untouched(tmp_path: Path) -> None:
    """The isolation property. A deletion that removed both would satisfy every
    "is it gone" assertion in this file."""
    stores = Stores(root=tmp_path)
    await stores.seed("acct-a")
    await stores.seed("acct-b")

    await stores.deletion.delete("acct-a")

    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 0
    assert stores.rows("verdicts", "account_digest", _digest("acct-b")) == 1
    assert stores.rows("batches", "account", "acct-a") == 0
    assert stores.rows("batches", "account", "acct-b") == 1
    assert stores.rows("batch_artifacts", "account", "acct-a") == 0
    assert stores.rows("batch_artifacts", "account", "acct-b") == 1
    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        remaining = [
            row[0]
            for row in connection.execute("SELECT DISTINCT batch_id FROM batch_rows").fetchall()
        ]
    assert remaining == ["batch-acct-b"], "another account's rows went with the deletion"


@asyncio_test
async def test_a_deleted_account_loses_its_jobs_and_its_idempotency_binding(
    tmp_path: Path,
) -> None:
    """A binding that outlived its job would answer a later handle with a job
    that no longer exists."""
    stores = Stores(root=tmp_path)
    key = IdempotencyKey("handle-" + "b" * 20)
    submitted = await stores.jobs.submit(
        "user@example.test", principal=PRINCIPAL, idempotency_key=key
    )
    account = PRINCIPAL.rate_limit_account
    assert stores.rows("jobs", "owner", account) == 1

    await stores.deletion.delete(account)

    assert stores.rows("jobs", "owner", account) == 0
    assert stores.jobs.get(submitted.job.id, principal=PRINCIPAL) is None
    assert await stores.jobs.fetch(submitted.job.id, principal=PRINCIPAL) is None
    assert stores.jobs._by_key == {}


@asyncio_test
async def test_every_cached_verdict_goes_whatever_snapshot_produced_it(
    tmp_path: Path,
) -> None:
    """C7 and C11 together: a deletion scoped to the current fingerprint would
    leave exactly the rows an operator believed were gone."""
    stores = Stores(root=tmp_path)
    await stores.seed("acct-a", fingerprint=SNAPSHOT_A.fingerprint)
    await stores.seed("acct-a", fingerprint=SNAPSHOT_B.fingerprint)
    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 2

    await stores.deletion.delete("acct-a")

    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 0


@asyncio_test
async def test_another_accounts_persisted_jobs_survive_the_deletion(tmp_path: Path) -> None:
    """The job store's own isolation, which needs **two** accounts with jobs.

    Every other deletion test here has one account's jobs in the store, so a
    `DELETE FROM jobs` with no owner predicate would pass all of them. This is
    the one that notices.
    """
    from emailcheck.application.jobs import CheckJob, _stored
    from emailcheck.domain.job import JobAdmission, JobState

    stores = Stores(root=tmp_path)
    store = stores.job_store
    for index, owner in enumerate(("acct-a", "acct-b")):
        await store.save(
            _stored(
                CheckJob(
                    id=JobId(f"isolation-{index}" + "x" * 11),
                    owner=owner,
                    state=JobState.PENDING,
                    created_at=OBSERVED_AT,
                    updated_at=OBSERVED_AT,
                ),
                target_digest=None,
                idempotency=None,
                admission=JobAdmission.CLAIMED,
            ),
            expected_generation=0,
        )
    assert stores.rows("jobs", "owner", "acct-a") == 1
    assert stores.rows("jobs", "owner", "acct-b") == 1

    await stores.deletion.delete("acct-a")

    assert stores.rows("jobs", "owner", "acct-a") == 0
    assert stores.rows("jobs", "owner", "acct-b") == 1, "another account's jobs were deleted"


@asyncio_test
async def test_a_deleted_account_stays_deleted_across_a_restart(tmp_path: Path) -> None:
    """No part of the deletion may rely on in-memory invalidation alone."""
    stores = Stores(root=tmp_path)
    await stores.seed("acct-a")
    await stores.seed("acct-b")
    await stores.deletion.delete("acct-a")

    stores.build()  # fresh services over the same files

    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 0
    assert stores.rows("batches", "account", "acct-a") == 0
    assert stores.rows("verdicts", "account_digest", _digest("acct-b")) == 1
    assert stores.rows("batches", "account", "acct-b") == 1


@asyncio_test
async def test_a_late_worker_cannot_recreate_a_deleted_account(tmp_path: Path) -> None:
    """The adversarial case: a job already running when the deletion happens.

    **Three barriers, and this measures the outcome rather than which one
    fired.** The account is suspended, so no new work is accepted; its registry
    entries are dropped, so a worker that resumes finds no job to settle; and
    `JobService._persist` refuses a write for a deleted account whatever reaches
    it. The first two are what actually stop this scenario — the tombstone is
    defence in depth behind them, and
    `test_the_deletion_tombstone_refuses_a_write_that_reaches_it` pins it
    directly rather than pretending this test does.
    """
    stores = Stores(root=tmp_path)
    account = PRINCIPAL.rate_limit_account
    submitted = await stores.jobs.submit("user@example.test", principal=PRINCIPAL)
    assert stores.rows("jobs", "owner", account) == 1

    await stores.deletion.delete(account)
    assert stores.rows("jobs", "owner", account) == 0

    # The worker the executor still holds now finishes.
    await stores.executor.run_pending()

    assert stores.rows("jobs", "owner", account) == 0, "a late worker recreated a deleted account"
    assert stores.jobs.get(submitted.job.id, principal=PRINCIPAL) is None


@asyncio_test
async def test_the_deletion_tombstone_refuses_a_write_that_reaches_it(tmp_path: Path) -> None:
    """The third barrier, pinned on its own.

    Unreachable through the ordinary path once the registry entry is gone, which
    is why it is reported as defence in depth rather than as an independent
    kill. It is kept because the two barriers in front of it are both about
    *this* process's bookkeeping, and a future caller that persists a job from
    somewhere else would otherwise recreate the account silently.
    """
    from emailcheck.application.jobs import CheckJob
    from emailcheck.domain.job import JobAdmission, JobState

    stores = Stores(root=tmp_path)
    account = PRINCIPAL.rate_limit_account
    await stores.deletion.delete(account)
    job = CheckJob(
        id=JobId("late-job-0001xxxxxxxxxx"),
        owner=account,
        state=JobState.PENDING,
        created_at=OBSERVED_AT,
        updated_at=OBSERVED_AT,
    )
    stores.jobs._admissions[job.id.value] = JobAdmission.CLAIMED

    await stores.jobs._persist(job)

    assert stores.rows("jobs", "owner", account) == 0, "a deleted account was written back"
    details = [event.detail for event in stores.operator.events if event.detail]
    assert "write after account deletion" in details


@asyncio_test
async def test_new_work_is_refused_before_anything_is_removed(tmp_path: Path) -> None:
    """A submission accepted mid-deletion would write the account straight back."""
    from emailcheck.application.abuse import AbuseRefused

    stores = Stores(root=tmp_path)
    account = PRINCIPAL.rate_limit_account

    await stores.deletion.delete(account)

    assert account in stores.admin.state.suspended_accounts
    with pytest.raises(AbuseRefused):
        stores.admin.guard.check_caller(principal=PRINCIPAL, active=True)


@asyncio_test
async def test_one_failing_store_is_named_and_the_others_still_run(tmp_path: Path) -> None:
    """No cross-store transaction exists, so the report says which store held on
    rather than claiming the account is gone."""

    @dataclass
    class BrokenJobStore:
        async def delete_account(self, *, owner: str) -> int:
            raise RuntimeError("the job database is unavailable at /var/db/jobs.sqlite")

    stores = Stores(root=tmp_path)
    await stores.seed("acct-a")
    stores.deletion = AccountDeletionService(
        admin=stores.admin,
        operator=stores.operator,
        account_state=stores.account_state,
        cache=stores.cache,
        jobs=None,
        job_store=BrokenJobStore(),  # type: ignore[arg-type]
        batches=stores.batch_store,
    )

    report = await stores.deletion.delete("acct-a")

    assert report.complete is False
    assert report.failed_stores == ("jobs",)
    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 0
    assert stores.rows("batches", "account", "acct-a") == 0
    assert "/var/db" not in repr(report)


@asyncio_test
async def test_the_report_carries_counts_and_nothing_it_deleted(tmp_path: Path) -> None:
    """A deletion report reaches an operator log and an audit trail."""
    stores = Stores(root=tmp_path)
    await stores.seed("acct-a")
    key = IdempotencyKey("secret-handle-" + "c" * 12)
    await stores.jobs.submit("user@example.test", principal=PRINCIPAL, idempotency_key=key)

    rendered = repr(await stores.deletion.delete("acct-a"))

    for leak in ("@", "example.test", key.value, "/", "acct-a"):
        assert leak not in rendered, leak


def test_deletion_is_not_reachable_as_an_ordinary_request() -> None:
    """Operator-only. `docs/architecture.md` carries "no public administrative
    interface" as a stop condition, and a deletion endpoint would be the most
    destructive thing behind one."""
    from emailcheck.apps.api import PERMITTED_REQUEST_KEYS
    from emailcheck.apps.cli import build_parser

    assert frozenset({"email"}) == PERMITTED_REQUEST_KEYS
    flags = {action.dest for action in build_parser()._actions}
    for forbidden in ("delete", "account", "erase", "purge"):
        assert not any(forbidden in flag for flag in flags), forbidden


def test_the_stack_exposes_the_deletion_operation() -> None:
    """Built and wired, rather than existing in `application/` and reachable
    from no configuration — the mistake Remediation A found for the job store."""
    from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack

    stack = build_verification_stack(
        Deployment(
            api_keys={"acct-1": "k" * 40},
            correlation_key=b"c" * 32,
            profile=DeploymentProfile.LAB_ACTIVE,
            sender_identity={
                "ehlo_hostname": "probe.example.test",
                "envelope_sender": "verify@probe.example.test",
            },
            active_probing=True,
            lab_destination_allowlist=frozenset({"mx.test.example"}),
        )
    )

    assert stack.deletion is not None
    assert stack.deletion.jobs is stack.jobs
    assert stack.deletion.job_store is stack.job_store


# --- C7-R1: the fingerprint is content-derived --------------------------------
#
# The first attempt hashed each dataset's declared *version and entry count*, and
# the focused review broke it in one line: two role lists, one entry each, same
# declared version, different entry — identical fingerprint, and a stale cached
# verdict served with the wrong risk flags. Everything below is that case and the
# controls that stop an overcorrection.


SAME_VERSION: Final = "role-v1"
SALES: Final = role_dataset("sales", version=SAME_VERSION)
SUPPORT: Final = role_dataset("support", version=SAME_VERSION)


def test_same_version_and_count_with_different_contents_are_different_snapshots() -> None:
    """The exact collision the focused review reproduced."""
    assert SALES.versions["role"] == SUPPORT.versions["role"]
    assert SALES.entry_counts["role"] == SUPPORT.entry_counts["role"] == 1
    assert sorted(SALES.roles.local_parts) != sorted(SUPPORT.roles.local_parts)

    assert SALES.fingerprint != SUPPORT.fingerprint, "a same-size replacement kept its identity"


@asyncio_test
async def test_a_same_size_replacement_misses_the_cache_and_reclassifies(
    tmp_path: Path,
) -> None:
    """End to end: the stale HIT the review measured is now a MISS.

    `support@example.test` is not a role account under `SALES` and is one under
    `SUPPORT`. Same account, target, sender, and ruleset; only the dataset
    contents differ, and the declared version does not.
    """
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.db")
    store.initialize()
    under_sales = await classify(SALES)
    assert RiskFlag.ROLE_ACCOUNT not in under_sales.verdict.risk_flags
    assert await cache_for(store, SALES).save(
        _target(under_sales),
        account="acct-1",
        verdict=under_sales.verdict,
        route_ttl=3600,
        expected_generation=0,
    )

    stale = await cache_for(store, SUPPORT).find(
        _target(under_sales), account="acct-1", ruleset=under_sales.verdict.ruleset
    )

    assert stale is None, "a verdict from the replaced dataset was served"
    under_support = await classify(SUPPORT)
    assert RiskFlag.ROLE_ACCOUNT in under_support.verdict.risk_flags


def test_entry_order_is_not_part_of_the_identity() -> None:
    """These datasets are sets. Two files listing the same entries in different
    orders are one snapshot, and a fingerprint that disagreed would flush the
    cache on a cosmetic edit."""
    assert (
        role_dataset("a", "b", "c", version=SAME_VERSION).fingerprint
        == role_dataset("c", "a", "b", version=SAME_VERSION).fingerprint
    )


def test_entries_are_length_framed_so_they_cannot_run_together() -> None:
    """`{"ab", "c"}` and `{"a", "bc"}` share a naive concatenated form.

    Two datasets whose contents differ would then share an identity, which is
    the same defect this fix exists to remove, arrived at a different way. Both
    boundary styles are pinned: the pair that collides under plain
    concatenation, and the pair that collides under a `.`-joined one, because a
    later edit could plausibly introduce either.
    """
    from emailcheck.classification.datasets import DomainDataset

    def domains(*values: str) -> PassiveDatasets:
        return PassiveDatasets(
            disposable=DomainDataset(domains=frozenset(values), metadata=SALES.roles.metadata)
        )

    assert domains("ab", "c").fingerprint != domains("a", "bc").fingerprint
    assert domains("a.b", "c").fingerprint != domains("a", "b.c").fingerprint


def test_a_bumped_version_is_a_new_snapshot_even_with_identical_contents() -> None:
    """Deliberate, and documented rather than incidental: an operator who bumps
    a version is saying something changed, and the conservative reading of that
    is a new cache identity rather than a shared one."""
    assert (
        role_dataset("sales", version="role-v1").fingerprint
        != role_dataset("sales", version="role-v2").fingerprint
    )


def test_the_declared_checksum_does_not_define_identity() -> None:
    """It is a string the file declares and the loader never verifies, so it
    cannot be what the cache trusts. Two snapshots differing only in a declared
    checksum are one snapshot; two differing in contents are two."""
    from dataclasses import replace as replace_dataclass

    from emailcheck.classification.datasets import LocalPartDataset

    honest = SALES
    tampered = PassiveDatasets(
        roles=LocalPartDataset(
            local_parts=frozenset({"support"}),
            metadata=replace_dataclass(SALES.roles.metadata, checksum="f" * 64),
        )
    )
    relabelled = PassiveDatasets(
        roles=LocalPartDataset(
            local_parts=honest.roles.local_parts,
            metadata=replace_dataclass(honest.roles.metadata, checksum="f" * 64),
        )
    )

    assert relabelled.fingerprint == honest.fingerprint, "a declared checksum moved the identity"
    assert tampered.fingerprint != honest.fingerprint, "changed contents kept the identity"


def test_the_reported_versions_and_content_fingerprints_are_both_available() -> None:
    """A declared version is what a human cites; a content fingerprint is what
    the cache compares. Reporting both is useful; conflating them is the bug."""
    shipped = load_shipped_datasets()

    assert set(shipped.versions) == set(shipped.content_fingerprints)
    assert shipped.versions != shipped.content_fingerprints
    for digest in shipped.content_fingerprints.values():
        assert len(digest) == 32
        assert set(digest) <= set("0123456789abcdef")


# --- C11-R1: the durable cross-replica deletion barrier -----------------------


@dataclass(slots=True)
class Replica:
    """One process's `JobService` over shared files. Nothing else is shared."""

    root: Path
    prefix: str
    executor: RecordingExecutor = field(default_factory=RecordingExecutor)
    jobs: JobService = field(init=False)

    def __post_init__(self) -> None:
        from tests.batch_fixtures import build_jobs

        job_store = SQLiteJobStore(path=self.root / "jobs.db")
        job_store.initialize()
        state = SQLiteAccountStateStore(path=self.root / "accounts.db")
        state.initialize()
        self.jobs = build_jobs(
            job_store=job_store,
            verdicts=InMemoryVerdictStore(),
            executor=self.executor,
            random_prefix=self.prefix,
        )[0]
        self.jobs.account_state = state


def deletion_for(root: Path, jobs: JobService | None = None) -> AccountDeletionService:
    """A deletion service over the same files, as a separate operator process."""
    clock = SteppableClock()
    metrics = InMemoryMetrics()
    operator = RecordingOperatorSink()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=clock,
        metrics=metrics,
        operator=operator,
        correlation_key=CORRELATION_KEY,
    )
    admin = AdminControl(guard=guard, clock=clock, metrics=metrics, correlation_key=CORRELATION_KEY)
    job_store = SQLiteJobStore(path=root / "jobs.db")
    job_store.initialize()
    state = SQLiteAccountStateStore(path=root / "accounts.db")
    state.initialize()
    return AccountDeletionService(
        admin=admin,
        operator=operator,
        account_state=state,
        cache=None,
        jobs=jobs,
        job_store=job_store,
        batches=None,
    )


def job_rows(root: Path, account: str) -> int:
    with closing(sqlite3.connect(root / "jobs.db")) as connection, connection:
        return int(
            connection.execute("SELECT count(*) FROM jobs WHERE owner = ?", (account,)).fetchone()[
                0
            ]
        )


@asyncio_test
async def test_a_second_replica_cannot_recreate_a_deleted_account(tmp_path: Path) -> None:
    """The blocker, as the behaviour that now holds.

    Replica B admits the account's work and holds it. A separate operator
    process deletes the account. B's worker then finishes — and before this fix
    wrote the job straight back, after `complete=True` had been reported.

    Nothing in B's memory knows about the deletion. What refuses the write is
    the durable generation B captured at admission no longer matching the one on
    disk.
    """
    b = Replica(root=tmp_path, prefix="B")
    account = PRINCIPAL.rate_limit_account
    await b.jobs.submit("user@example.test", principal=PRINCIPAL)
    assert job_rows(tmp_path, account) == 1

    report = await deletion_for(tmp_path).delete(account)

    assert report.complete is True
    assert job_rows(tmp_path, account) == 0
    assert account not in b.jobs._deleted_accounts, "B must not have been told locally"

    await b.executor.run_pending()

    assert job_rows(tmp_path, account) == 0, "a second replica recreated a deleted account"


@asyncio_test
async def test_a_stale_replica_cannot_write_a_cached_verdict_either(tmp_path: Path) -> None:
    """The other store a late worker reaches.

    A cached verdict recreated after a deletion is the account's data just as
    much as a job row is, and it is written from a different call than the job
    row — so it needs its own barrier and its own test.
    """
    from tests.batch_fixtures import build_jobs

    account = PRINCIPAL.rate_limit_account
    job_store = SQLiteJobStore(path=tmp_path / "jobs.db")
    job_store.initialize()
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    verdicts = SQLiteVerdictStore(path=tmp_path / "verdicts.db")
    verdicts.initialize()
    executor = RecordingExecutor()
    replica = build_jobs(
        job_store=job_store,
        verdicts=InMemoryVerdictStore(),
        executor=executor,
        random_prefix="B",
    )[0]
    replica.account_state = state
    replica.cache = VerdictCache(
        store=verdicts,
        clock=FakeClock(),
        random=FakeRandomSource(prefix="rec"),
        correlation_key=CORRELATION_KEY,
        passive_dataset_fingerprint=SNAPSHOT_A.fingerprint,
    )
    await replica.submit("user@example.test", principal=PRINCIPAL)

    await deletion_for(tmp_path).delete(account)
    await executor.run_pending()

    with closing(sqlite3.connect(tmp_path / "verdicts.db")) as connection, connection:
        cached = connection.execute("SELECT count(*) FROM verdicts").fetchone()[0]
    assert cached == 0, "a stale replica cached a verdict for a deleted account"


@asyncio_test
async def test_several_stale_replicas_are_all_refused(tmp_path: Path) -> None:
    """One deletion, two independent replicas holding work, both released."""
    first = Replica(root=tmp_path, prefix="B")
    second = Replica(root=tmp_path, prefix="C")
    account = PRINCIPAL.rate_limit_account
    await first.jobs.submit("one@example.test", principal=PRINCIPAL)
    await second.jobs.submit("two@example.test", principal=PRINCIPAL)
    assert job_rows(tmp_path, account) == 2

    await deletion_for(tmp_path).delete(account)
    await first.executor.run_pending()
    await second.executor.run_pending()

    assert job_rows(tmp_path, account) == 0


@asyncio_test
async def test_the_barrier_survives_a_restart_of_every_process(tmp_path: Path) -> None:
    """A fresh replica over the same files sees the same deletion state.

    Nothing here relies on the deleting process, which no longer exists.
    """
    b = Replica(root=tmp_path, prefix="B")
    account = PRINCIPAL.rate_limit_account
    await b.jobs.submit("user@example.test", principal=PRINCIPAL)
    await deletion_for(tmp_path).delete(account)

    fresh = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    fresh.initialize()

    assert await fresh.generation(account) == 1
    assert await fresh.permits(account, 0) is False
    assert await fresh.permits(account, 1) is True


@asyncio_test
async def test_work_admitted_after_the_deletion_proceeds_normally(tmp_path: Path) -> None:
    """Deletion erases data; it does not ban the account for ever.

    `docs/privacy.md` section 7 is account-*requested* deletion — a customer
    erasing their data — so a later legitimate request must work. A new
    submission reads the current generation and writes under it. It is refused
    by *this* process only while the local suspension stands, which is the
    operator's switch and is separately reversible.
    """
    account = PRINCIPAL.rate_limit_account
    await deletion_for(tmp_path).delete(account)
    after = Replica(root=tmp_path, prefix="D")

    submitted = await after.jobs.submit("user@example.test", principal=PRINCIPAL)

    assert job_rows(tmp_path, account) == 1
    assert after.jobs._generations[submitted.job.id.value] == 1


@asyncio_test
async def test_a_stale_replica_cannot_reclaim_an_idempotency_binding(
    tmp_path: Path,
) -> None:
    """An in-flight old request must not write its binding back either.

    The binding lives in the same row as the job, so refusing the write refuses
    the reclaim — asserted on the row rather than inferred from that.
    """
    b = Replica(root=tmp_path, prefix="B")
    account = PRINCIPAL.rate_limit_account
    key = IdempotencyKey("stale-handle-" + "z" * 12)
    await b.jobs.submit("user@example.test", principal=PRINCIPAL, idempotency_key=key)

    await deletion_for(tmp_path).delete(account)
    await b.executor.run_pending()

    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        bindings = connection.execute(
            "SELECT count(*) FROM jobs WHERE idempotency_digest IS NOT NULL"
        ).fetchone()[0]
    assert bindings == 0


@asyncio_test
async def test_deletion_refuses_when_the_barrier_cannot_be_raised(tmp_path: Path) -> None:
    """Fail closed **before** anything destructive.

    Emptying the stores and then discovering the barrier is unavailable is the
    worst of both: the data is gone and another replica may put it back while
    the operator is told it succeeded.
    """

    @dataclass
    class BrokenState:
        advanced: int = 0

        async def generation(self, account: str) -> int:
            return 0

        async def advance(self, account: str) -> int:
            self.advanced += 1
            raise RuntimeError("the account state database is unavailable at /var/db/a.sqlite")

        async def permits(self, account: str, generation: int) -> bool:
            return True

    stores = Stores(root=tmp_path)
    await stores.seed("acct-a")
    broken = BrokenState()
    stores.deletion = AccountDeletionService(
        admin=stores.admin,
        operator=stores.operator,
        account_state=broken,  # type: ignore[arg-type]
        cache=stores.cache,
        jobs=stores.jobs,
        job_store=stores.job_store,
        batches=stores.batch_store,
    )

    report = await stores.deletion.delete("acct-a")

    assert broken.advanced == 1
    assert report.complete is False
    assert report.failed_stores == ("account_state",)
    assert report.total_removed == 0
    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 1, "rows were deleted"
    assert stores.rows("batches", "account", "acct-a") == 1
    assert "/var/db" not in repr(report)


@asyncio_test
async def test_a_deployment_with_no_barrier_refuses_to_delete(tmp_path: Path) -> None:
    """No barrier configured is a refusal, not a best effort: without one this
    operation cannot make the promise `report.complete` states."""
    stores = Stores(root=tmp_path)
    await stores.seed("acct-a")
    stores.deletion = AccountDeletionService(
        admin=stores.admin,
        operator=stores.operator,
        account_state=None,
        cache=stores.cache,
        jobs=stores.jobs,
        job_store=stores.job_store,
        batches=stores.batch_store,
    )

    report = await stores.deletion.delete("acct-a")

    assert report.complete is False
    assert report.failed_stores == ("account_state",)
    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 1


@asyncio_test
async def test_two_concurrent_deletions_never_move_the_generation_backwards(
    tmp_path: Path,
) -> None:
    """Two operators, one account. The generation is monotonic and each caller
    gets its own value, because the increment is one SQL statement rather than a
    read and a write another connection can interleave with."""
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()

    async with asyncio.timeout(OUTER_BOUND):
        results = await asyncio.gather(*(state.advance("acct-a") for _ in range(4)))

    assert sorted(results) == [1, 2, 3, 4]
    assert await state.generation("acct-a") == 4
    for stale in range(4):
        assert await state.permits("acct-a", stale) is False
    assert await state.permits("acct-a", 4) is True


@asyncio_test
async def test_the_barrier_moves_one_account_only(tmp_path: Path) -> None:
    """Another account's generation, work, and rows are untouched."""
    b = Replica(root=tmp_path, prefix="B")
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    await b.jobs.submit("user@example.test", principal=PRINCIPAL)

    await deletion_for(tmp_path).delete("acct-other")

    assert await state.generation("acct-other") == 1
    assert await state.generation(PRINCIPAL.rate_limit_account) == 0
    await b.executor.run_pending()
    assert job_rows(tmp_path, PRINCIPAL.rate_limit_account) == 1


@asyncio_test
async def test_a_writer_that_cannot_read_the_barrier_does_not_write(
    tmp_path: Path,
) -> None:
    """There is no safe default for "I could not tell whether this account still
    exists": persisting anyway is how a reported deletion comes undone."""

    @dataclass
    class UnreadableState:
        async def generation(self, account: str) -> int:
            return 0

        async def advance(self, account: str) -> int:
            return 1

        async def permits(self, account: str, generation: int) -> bool:
            raise RuntimeError("the account state database is unavailable")

    b = Replica(root=tmp_path, prefix="B")
    account = PRINCIPAL.rate_limit_account
    await b.jobs.submit("user@example.test", principal=PRINCIPAL)
    before = job_rows(tmp_path, account)
    b.jobs.account_state = UnreadableState()  # type: ignore[assignment]

    await b.executor.run_pending()

    assert job_rows(tmp_path, account) == before, "a write landed with the barrier unreadable"


def test_the_stack_wires_one_barrier_into_both_the_service_and_the_deletion(
    tmp_path: Path,
) -> None:
    """Identity, not existence — the rule Remediation A's job-store wiring set."""
    from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack

    stack = build_verification_stack(
        Deployment(
            api_keys={"acct-1": "k" * 40},
            correlation_key=b"c" * 32,
            profile=DeploymentProfile.LAB_ACTIVE,
            sender_identity={
                "ehlo_hostname": "probe.example.test",
                "envelope_sender": "verify@probe.example.test",
            },
            active_probing=True,
            lab_destination_allowlist=frozenset({"mx.test.example"}),
            job_store_path=tmp_path / "jobs.db",
            account_state_path=tmp_path / "accounts.db",
        )
    )

    assert stack.account_state is not None
    assert stack.jobs is not None and stack.jobs.account_state is stack.account_state
    assert stack.deletion is not None and stack.deletion.account_state is stack.account_state


@asyncio_test
async def test_deleting_an_account_removes_entries_under_every_fingerprint(
    tmp_path: Path,
) -> None:
    """C7 and C11 together: the barrier and the deletion are both
    fingerprint-independent, and a stale worker still cannot resurrect."""
    stores = Stores(root=tmp_path)
    await stores.seed("acct-a", fingerprint=SALES.fingerprint)
    await stores.seed("acct-a", fingerprint=SUPPORT.fingerprint)
    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 2

    report = await stores.deletion.delete("acct-a")

    assert report.complete is True
    assert stores.rows("verdicts", "account_digest", _digest("acct-a")) == 0
    assert await stores.account_state.permits("acct-a", 0) is False


# --- C11-R3/R4/R5: the fence, the composition, and the authority -------------
#
# The previous design checked the deletion generation in `accounts.db` and then
# wrote `jobs.db` in a later transaction. The focused review paused a replica in
# that gap and recreated a job row, a cached verdict, and an idempotency binding
# after the operator had been told the deletion was complete. Every test below
# crosses that boundary on purpose: releasing a worker *after* a deletion proves
# nothing about it, because the check has not happened yet.


def bind(root: Path) -> tuple[SQLiteJobStore, SQLiteAccountStateStore, SQLiteVerdictStore]:
    """The three real stores over real files, bound to one authority."""
    job_store = SQLiteJobStore(path=root / "jobs.db")
    job_store.initialize()
    state = SQLiteAccountStateStore(path=root / "accounts.db")
    state.initialize()
    verdicts = SQLiteVerdictStore(path=root / "verdicts.db")
    verdicts.initialize()
    job_store.bind_authority(state.authority_id())
    verdicts.bind_authority(state.authority_id())
    return job_store, state, verdicts


def fenced_replica(root: Path, *, prefix: str = "B") -> tuple[JobService, RecordingExecutor]:
    from tests.batch_fixtures import build_jobs

    job_store, state, verdicts = bind(root)
    executor = RecordingExecutor()
    service = build_jobs(
        job_store=job_store, verdicts=verdicts, executor=executor, random_prefix=prefix
    )[0]
    service.account_state = state
    service.cache = VerdictCache(
        store=verdicts,
        clock=FakeClock(),
        random=FakeRandomSource(prefix=f"rec-{prefix}"),
        correlation_key=CORRELATION_KEY,
        passive_dataset_fingerprint=SNAPSHOT_A.fingerprint,
    )
    return service, executor


def deletion_with_cache(root: Path) -> AccountDeletionService:
    """A deletion service that also owns the verdict cache, as composition builds it."""
    verdicts = SQLiteVerdictStore(path=root / "verdicts.db")
    verdicts.initialize()
    service = deletion_for(root)
    object.__setattr__(
        service,
        "cache",
        VerdictCache(
            store=verdicts,
            clock=FakeClock(),
            random=FakeRandomSource(prefix="rec-B"),
            correlation_key=CORRELATION_KEY,
            passive_dataset_fingerprint=SNAPSHOT_A.fingerprint,
        ),
    )
    return service


def verdict_rows(root: Path) -> int:
    with closing(sqlite3.connect(root / "verdicts.db")) as connection, connection:
        return int(connection.execute("SELECT count(*) FROM verdicts").fetchone()[0])


def binding_rows(root: Path) -> int:
    with closing(sqlite3.connect(root / "jobs.db")) as connection, connection:
        return int(
            connection.execute(
                "SELECT count(*) FROM jobs WHERE idempotency_digest IS NOT NULL"
            ).fetchone()[0]
        )


async def cross_the_boundary(
    root: Path,
    *,
    paused: type,
    account: str,
) -> None:
    """Run a worker, pause it inside the real store's write call, delete, resume.

    The pause is *after* `JobService` decided the write was permitted and before
    the store's transaction opens, which is exactly the gap the review used.
    """
    original = paused.save
    reached, release = asyncio.Event(), asyncio.Event()

    async def waiting(self: object, *args: object, **kwargs: object) -> object:
        reached.set()
        await release.wait()
        return await original(self, *args, **kwargs)  # type: ignore[operator]

    paused.save = waiting  # type: ignore[attr-defined]
    worker = asyncio.create_task(_settle_pending(root))
    try:
        async with asyncio.timeout(OUTER_BOUND):
            await reached.wait()
        await deletion_for(root).delete(account)
        release.set()
        await worker
    finally:
        paused.save = original  # type: ignore[attr-defined]


async def _settle_pending(root: Path) -> None:  # pragma: no cover - replaced per test
    raise NotImplementedError


@asyncio_test
async def test_a_job_write_that_crossed_the_check_cannot_land_after_the_deletion(
    tmp_path: Path,
) -> None:
    """C11-R3, the JobStore half, as the review reproduced it.

    Replica B validates its generation, is paused before the real SQLite write,
    and replica A completes a deletion in that window. Before the fence the row
    came back and `report.complete` had already said it was gone.
    """
    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit("user@example.test", principal=PRINCIPAL)

    original = SQLiteJobStore.save
    reached, release = asyncio.Event(), asyncio.Event()

    async def waiting(self: SQLiteJobStore, *args: object, **kwargs: object) -> bool:
        reached.set()
        await release.wait()
        return await original(self, *args, **kwargs)  # type: ignore[arg-type]

    SQLiteJobStore.save = waiting  # type: ignore[assignment,method-assign]
    try:
        worker = asyncio.create_task(executor.run_pending())
        async with asyncio.timeout(OUTER_BOUND):
            await reached.wait()
        report = await deletion_for(tmp_path).delete(account)
        assert report.complete is True
        assert job_rows(tmp_path, account) == 0
        release.set()
        await worker
    finally:
        SQLiteJobStore.save = original  # type: ignore[method-assign]

    assert job_rows(tmp_path, account) == 0, "a stale write landed after the deletion completed"


@asyncio_test
async def test_a_verdict_write_that_crossed_the_check_cannot_land_either(
    tmp_path: Path,
) -> None:
    """C11-R3, the VerdictStore half. The same window, the other store."""
    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit("user@example.test", principal=PRINCIPAL)

    original = SQLiteVerdictStore.save
    reached, release = asyncio.Event(), asyncio.Event()

    async def waiting(self: SQLiteVerdictStore, *args: object, **kwargs: object) -> bool:
        reached.set()
        await release.wait()
        return await original(self, *args, **kwargs)  # type: ignore[arg-type]

    SQLiteVerdictStore.save = waiting  # type: ignore[assignment,method-assign]
    try:
        worker = asyncio.create_task(executor.run_pending())
        async with asyncio.timeout(OUTER_BOUND):
            await reached.wait()
        assert (await deletion_with_cache(tmp_path).delete(account)).complete is True
        release.set()
        await worker
    finally:
        SQLiteVerdictStore.save = original  # type: ignore[method-assign]

    assert verdict_rows(tmp_path) == 0, "a stale cache write landed after the deletion completed"


@asyncio_test
async def test_an_idempotency_claim_that_crossed_the_check_cannot_recreate_a_binding(
    tmp_path: Path,
) -> None:
    """C11-R3, the claim. It creates a job row *and* a binding, so it is fenced too."""
    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit(
        "user@example.test", principal=PRINCIPAL, idempotency_key=IdempotencyKey("key-00000001")
    )
    assert binding_rows(tmp_path) == 1

    original = SQLiteJobStore.save
    reached, release = asyncio.Event(), asyncio.Event()

    async def waiting(self: SQLiteJobStore, *args: object, **kwargs: object) -> bool:
        reached.set()
        await release.wait()
        return await original(self, *args, **kwargs)  # type: ignore[arg-type]

    SQLiteJobStore.save = waiting  # type: ignore[assignment,method-assign]
    try:
        worker = asyncio.create_task(executor.run_pending())
        async with asyncio.timeout(OUTER_BOUND):
            await reached.wait()
        assert (await deletion_for(tmp_path).delete(account)).complete is True
        assert binding_rows(tmp_path) == 0
        release.set()
        await worker
    finally:
        SQLiteJobStore.save = original  # type: ignore[method-assign]

    assert binding_rows(tmp_path) == 0, "a deleted idempotency binding was recreated"


@asyncio_test
async def test_a_stale_claim_refuses_the_submission_rather_than_writing_it(
    tmp_path: Path,
) -> None:
    """The claim's own answer, at the port level.

    `ACCOUNT_FENCED` is decided inside the claim's transaction, so it is a
    refusal the store made rather than a check the caller remembered to run.
    """
    from emailcheck.domain.job import JobAdmission, JobState
    from emailcheck.ports.job_store import ClaimStatus

    job_store, state, _ = bind(tmp_path)
    proposed = _stored(
        CheckJob(
            id=JobId("fenced-claim" + "x" * 12),
            owner="acct-a",
            state=JobState.PENDING,
            created_at=OBSERVED_AT,
            updated_at=OBSERVED_AT,
        ),
        target_digest=_digest("target"),
        idempotency=_digest("key"),
        admission=JobAdmission.CLAIMED,
    )
    await job_store.fence(account="acct-a", generation=1)

    result = await job_store.claim_idempotency(proposed, expected_generation=0)

    assert result.status is ClaimStatus.ACCOUNT_FENCED
    assert result.existing is None
    assert job_rows(tmp_path, "acct-a") == 0
    assert (await job_store.claim_idempotency(proposed, expected_generation=1)).status is (
        ClaimStatus.NEW_CLAIM
    )
    assert await state.generation("acct-a") == 0


@asyncio_test
async def test_the_fence_is_held_across_the_write_so_a_deletion_cannot_pass_it(
    tmp_path: Path,
) -> None:
    """§7: the deterministic race, with the fence **held** rather than merely read.

    A writer paused between reading the fence and inserting its row still holds
    the store's write transaction, so the deletion's own fence — a write to the
    same database — cannot be raised until the writer commits. That mutual
    exclusion is the whole mechanism, and it is asserted directly rather than by
    waiting to see who wins: an independent connection cannot take the lock the
    deletion needs while the writer holds it.

    Both serializations are then safe, and both are pinned below: the writer
    commits and the deletion removes what it wrote, or the deletion goes first
    and the writer is refused. What cannot happen is a deletion reporting
    success while an old-generation write is still in flight.
    """
    from emailcheck.adapters.storage import account_fence, sqlite_job_store

    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit("user@example.test", principal=PRINCIPAL)

    original = account_fence.fenced_generation
    held, release = threading.Event(), threading.Event()

    def pausing(connection: sqlite3.Connection, owner: str) -> int:
        value = original(connection, owner)
        if owner == account and not held.is_set():
            held.set()
            release.wait(OUTER_BOUND)
        return value

    sqlite_job_store.fenced_generation = pausing  # type: ignore[assignment]
    try:
        worker = asyncio.create_task(executor.run_pending())
        async with asyncio.timeout(OUTER_BOUND):
            await asyncio.to_thread(held.wait, OUTER_BOUND)
        assert held.is_set()

        # The deletion's fence is a write to this database. While the paused
        # writer holds the transaction, that write cannot begin — no timing
        # assumption, and no sleep: SQLite refuses the lock outright.
        contender = sqlite3.connect(tmp_path / "jobs.db", timeout=0)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                contender.execute("BEGIN IMMEDIATE")
        finally:
            contender.close()

        release.set()
        await worker
    finally:
        sqlite_job_store.fenced_generation = original  # type: ignore[assignment]

    # Serialization A: the writer committed under its still-valid generation,
    # and the deletion removes exactly what it wrote.
    assert job_rows(tmp_path, account) == 1
    report = await deletion_for(tmp_path).delete(account)
    assert report.complete is True
    assert job_rows(tmp_path, account) == 0

    # Serialization B: with the fence already raised, the same write is refused
    # rather than recreating the account.
    job_store = SQLiteJobStore(path=tmp_path / "jobs.db")
    assert await job_store.save(_any_job(account), expected_generation=0) is False
    assert job_rows(tmp_path, account) == 0


def test_a_crashed_writer_does_not_hold_the_fence_forever(tmp_path: Path) -> None:
    """§10: the fence is a transaction, not a durable lock row.

    A separate process opens the write transaction and is killed. SQLite
    releases the lock with the connection, its uncommitted write is rolled back,
    and a later deletion proceeds — so there is nothing for an operator to
    unstick by hand.
    """
    bind(tmp_path)
    script = tmp_path / "holder.py"
    script.write_text(
        "import sqlite3, sys, time\n"
        "connection = sqlite3.connect(sys.argv[1])\n"
        "connection.execute('BEGIN IMMEDIATE')\n"
        "connection.execute(HOLD, ('acct-a', 99))\n"
        "print('held', flush=True)\n"
        "time.sleep(300)\n".replace("HOLD", repr("INSERT INTO account_fence VALUES (?, ?)"))
    )
    with subprocess.Popen(  # noqa: S603 - a literal interpreter and a file this test wrote
        [sys.executable, str(script), str(tmp_path / "jobs.db")],
        stdout=subprocess.PIPE,
        text=True,
    ) as holder:
        try:
            assert holder.stdout is not None
            assert holder.stdout.readline().strip() == "held"
            with (
                closing(sqlite3.connect(tmp_path / "jobs.db", timeout=0.2)) as contender,
                pytest.raises(sqlite3.OperationalError),
            ):
                contender.execute("BEGIN IMMEDIATE")
        finally:
            holder.kill()
            holder.wait()
    assert holder.stdout is not None and holder.stdout.closed

    with (
        closing(sqlite3.connect(tmp_path / "jobs.db", timeout=OUTER_BOUND)) as connection,
        connection,
    ):
        connection.execute("BEGIN IMMEDIATE")
        held = connection.execute(
            "SELECT count(*) FROM account_fence WHERE generation = 99"
        ).fetchone()[0]
    assert held == 0, "a killed writer's uncommitted fence survived"


# --- C11-R4: a persistent deployment without the authority does not start ----


def test_a_job_service_with_a_store_and_no_authority_refuses_to_exist() -> None:
    """The composition object itself, not only the configuration.

    The review built exactly this and every write was permitted, including the
    ones that put a deleted account back.
    """
    from tests.batch_fixtures import build_jobs

    service = build_jobs()[0]
    with pytest.raises(JobError, match="account state"):
        JobService(
            verification=service.verification,
            executor=service.executor,
            clock=service.clock,
            random=service.random,
            operator=service.operator,
            correlation_key=CORRELATION_KEY,
            store=SQLiteJobStore(path=Path("unused.db")),
        )


def test_a_service_that_persists_nothing_still_needs_no_authority() -> None:
    """§12: the requirement is on persistence, not on being a job service.

    A registry-only service holds nothing a deletion could fail to erase, so
    demanding a third database of it would be a start-up failure for no
    guarantee.
    """
    from tests.batch_fixtures import build_jobs

    assert build_jobs()[0].store is None


@pytest.mark.parametrize(
    ("configured", "accepted"),
    [
        ({}, True),
        ({"store_path": True}, False),
        ({"job_store_path": True}, False),
        ({"store_path": True, "account_state_path": True}, True),
        ({"job_store_path": True, "account_state_path": True}, True),
        ({"store_path": True, "job_store_path": True, "account_state_path": True}, True),
    ],
)
def test_the_persistent_profile_matrix(
    tmp_path: Path, configured: dict[str, bool], accepted: bool
) -> None:
    """Which combinations may start, pinned as a table rather than as prose."""
    from emailcheck.composition import Deployment, DeploymentProfile

    paths = {name: tmp_path / f"{name}.db" for name in configured}
    build = lambda: Deployment(  # noqa: E731 - a one-line factory reads better here
        api_keys={"acct-1": "k" * 32},
        correlation_key=CORRELATION_KEY,
        profile=DeploymentProfile.LAB_ACTIVE,
        lab_destination_allowlist=frozenset({"mx.test.example"}),
        **paths,  # type: ignore[arg-type]
    )
    if accepted:
        assert build() is not None
    else:
        with pytest.raises(ValueError, match="account_state_path"):
            build()


# --- C11-R5: one data store, one deletion authority --------------------------


def test_a_job_store_refuses_to_open_under_a_second_authority(tmp_path: Path) -> None:
    """§16: same `jobs.db`, a different `accounts.db`.

    The configuration the review used to make a deletion invisible: replica A
    deletes under one authority while replica B writes trusting another. It is
    refused before the service can write anything.
    """
    job_store, first, _ = bind(tmp_path)
    second = SQLiteAccountStateStore(path=tmp_path / "other-accounts.db")
    second.initialize()
    assert first.authority_id() != second.authority_id()

    assert job_store.bind_authority(first.authority_id()) == first.authority_id()
    with pytest.raises(AccountAuthorityError, match="different account-state authority"):
        job_store.bind_authority(second.authority_id())


def test_a_verdict_store_refuses_a_second_authority_independently(tmp_path: Path) -> None:
    """§17: the cache can recreate account-owned rows, so it is bound too."""
    verdicts = bind(tmp_path)[2]
    second = SQLiteAccountStateStore(path=tmp_path / "other-accounts.db")
    second.initialize()

    with pytest.raises(AccountAuthorityError):
        verdicts.bind_authority(second.authority_id())


@pytest.mark.parametrize("persisted", ["job_store_path", "store_path"])
def test_the_stack_refuses_to_build_two_replicas_on_different_authorities(
    tmp_path: Path, persisted: str
) -> None:
    """The same rule where an operator meets it: composition.

    Both persistent stores, each on its own, because each can hold
    account-owned rows and a deployment may configure either without the other.
    """
    from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack

    def stack(state: str) -> object:
        return build_verification_stack(
            Deployment(
                api_keys={"acct-1": "k" * 32},
                correlation_key=CORRELATION_KEY,
                profile=DeploymentProfile.LAB_ACTIVE,
                lab_destination_allowlist=frozenset({"mx.test.example"}),
                account_state_path=tmp_path / state,
                **{persisted: tmp_path / "data.db"},  # type: ignore[arg-type]
            )
        )

    assert stack("accounts.db") is not None
    with pytest.raises(AccountAuthorityError):
        stack("other-accounts.db")


def test_two_replicas_on_one_authority_both_start(tmp_path: Path) -> None:
    """§20, the positive control: the safe configuration is not merely tolerated."""
    from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack

    def stack(prefix: str) -> object:
        return build_verification_stack(
            Deployment(
                api_keys={f"acct-{prefix}": "k" * 32},
                correlation_key=CORRELATION_KEY,
                profile=DeploymentProfile.LAB_ACTIVE,
                lab_destination_allowlist=frozenset({"mx.test.example"}),
                store_path=tmp_path / "verdicts.db",
                job_store_path=tmp_path / "jobs.db",
                account_state_path=tmp_path / "accounts.db",
            )
        )

    assert stack("a") is not None
    assert stack("b") is not None


def test_a_store_written_before_the_fence_is_refused_by_version(tmp_path: Path) -> None:
    """§19: an older file is refused, not adopted.

    The migration policy, as behaviour: a file from a build with no authority
    binding carries no record of which deletion authority it belongs to, and
    "whichever one is configured now" is precisely the mistake the binding
    exists to catch. Every schema in this package refuses an older version
    loudly, and that is the deliberate migration point.
    """
    from emailcheck.adapters.storage.sqlite_job_store import JobStoreSchemaError

    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        connection.execute("CREATE TABLE job_schema_version (version INTEGER NOT NULL)")
        connection.execute("INSERT INTO job_schema_version (version) VALUES (4)")

    with pytest.raises(JobStoreSchemaError, match="schema version 4"):
        SQLiteJobStore(path=tmp_path / "jobs.db").initialize()


def test_a_missing_binding_is_never_adopted_silently(tmp_path: Path) -> None:
    """The other half of §19, at the primitive.

    A store carrying the current schema but no authority row cannot have been
    written by this build, so the first `bind_authority` records one rather than
    inheriting whatever is configured — and any later mismatch is refused.
    """
    job_store, state, _ = bind(tmp_path)
    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        connection.execute("DELETE FROM store_authority")

    other = SQLiteAccountStateStore(path=tmp_path / "other-accounts.db")
    other.initialize()
    assert job_store.bind_authority(other.authority_id()) == other.authority_id()
    with pytest.raises(AccountAuthorityError):
        job_store.bind_authority(state.authority_id())


# --- the generation properties that must not regress -------------------------


@asyncio_test
async def test_a_partial_cleanup_failure_leaves_the_fence_up(tmp_path: Path) -> None:
    """§22: a failed deletion is retryable, and stale writes stay refused.

    The fence is raised in its own transaction before the rows are removed, so a
    cleanup that fails afterwards does not lower it. The account's data is still
    there — truthfully reported — and no old-generation write can add to it.
    """
    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit("user@example.test", principal=PRINCIPAL)
    await executor.run_pending()
    assert job_rows(tmp_path, account) == 1

    deletion = deletion_for(tmp_path)
    job_store = deletion.job_store
    assert job_store is not None

    async def failing(*, owner: str) -> int:
        raise RuntimeError("the store is unavailable")

    object.__setattr__(deletion, "job_store", _FailingDelete(inner=job_store, fail=failing))
    report = await deletion.delete(account)

    assert report.complete is False
    assert "jobs" in report.failed_stores
    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        fence = connection.execute(
            "SELECT generation FROM account_fence WHERE account = ?", (account,)
        ).fetchone()
    assert fence == (1,), "the fence fell when the cleanup behind it failed"
    assert await job_store.save(_any_job(account), expected_generation=0) is False


@dataclass(frozen=True, slots=True)
class _FailingDelete:
    """A job store whose account deletion fails and whose fence works."""

    inner: SQLiteJobStore
    fail: object

    async def fence(self, *, account: str, generation: int) -> int:
        return await self.inner.fence(account=account, generation=generation)

    async def delete_account(self, *, owner: str) -> int:
        raise RuntimeError("the store is unavailable")


def _any_job(owner: str) -> StoredJob:
    from emailcheck.domain.job import JobAdmission, JobState

    return _stored(
        CheckJob(
            id=JobId("late-write" + "x" * 14),
            owner=owner,
            state=JobState.PENDING,
            created_at=OBSERVED_AT,
            updated_at=OBSERVED_AT,
        ),
        target_digest=None,
        idempotency=None,
        admission=JobAdmission.CLAIMED,
    )


@asyncio_test
async def test_two_concurrent_deletions_leave_one_fence_and_no_rows(tmp_path: Path) -> None:
    """§23: independent replicas, independent connections, one truthful outcome."""
    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit("user@example.test", principal=PRINCIPAL)
    await executor.run_pending()

    reports = await asyncio.gather(
        deletion_for(tmp_path).delete(account), deletion_for(tmp_path).delete(account)
    )

    assert all(report.complete for report in reports)
    assert job_rows(tmp_path, account) == 0
    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        fence = connection.execute(
            "SELECT generation FROM account_fence WHERE account = ?", (account,)
        ).fetchone()[0]
    assert fence >= 1
    assert await SQLiteAccountStateStore(path=tmp_path / "accounts.db").permits(account, 0) is False


@asyncio_test
async def test_work_admitted_after_both_fences_moved_persists_normally(tmp_path: Path) -> None:
    """§21/§27: deletion is not an accidental permanent ban.

    A later legitimate request reads the new generation, and both the authority
    and the store fences agree on it, so the account works again.
    """
    account = PRINCIPAL.rate_limit_account
    first, first_executor = fenced_replica(tmp_path)
    await first.submit("user@example.test", principal=PRINCIPAL)
    await first_executor.run_pending()
    assert (await deletion_for(tmp_path).delete(account)).complete is True

    later, later_executor = fenced_replica(tmp_path, prefix="C")
    await later.submit("new@example.test", principal=PRINCIPAL)
    await later_executor.run_pending()

    assert job_rows(tmp_path, account) == 1


@asyncio_test
async def test_the_store_fence_moves_one_account_only(tmp_path: Path) -> None:
    """§30, in the store rather than only in the authority."""
    job_store, _, _ = bind(tmp_path)
    await job_store.fence(account="acct-a", generation=4)

    assert await job_store.save(_any_job("acct-b"), expected_generation=0) is True
    assert await job_store.save(_any_job("acct-a"), expected_generation=0) is False


@asyncio_test
async def test_a_store_fence_never_falls(tmp_path: Path) -> None:
    """A fence that could be lowered would re-authorize work whose data is gone."""
    job_store, _, _ = bind(tmp_path)

    assert await job_store.fence(account="acct-a", generation=5) == 5
    assert await job_store.fence(account="acct-a", generation=2) == 5
    assert await job_store.save(_any_job("acct-a"), expected_generation=2) is False


# --- C11-R6/R7: the two stated contracts nothing was holding ------------------
#
# Both behaviours were already correct in production; neither was pinned, and
# the focused review demonstrated that by mutating each one green. These tests
# exist so the contracts stay true rather than stay accidental.


@dataclass(frozen=True, slots=True)
class UnreadableAccountState:
    """An `AccountStateStore` whose every operation fails.

    A store that is present and configured but cannot answer — an unreachable
    file, a corrupt page, a full disk. Distinct from `None`, which is a
    deployment that never had one and which composition now refuses outright.
    """

    async def generation(self, account: str) -> int:
        raise RuntimeError("the account state is unavailable")

    async def advance(self, account: str) -> int:
        raise RuntimeError("the account state is unavailable")

    async def permits(self, account: str, generation: int) -> bool:
        raise RuntimeError("the account state is unavailable")


def stored_state(root: Path, account: str) -> str | None:
    with closing(sqlite3.connect(root / "jobs.db")) as connection, connection:
        row = connection.execute("SELECT state FROM jobs WHERE owner = ?", (account,)).fetchone()
    return None if row is None else str(row[0])


def fence_rows(root: Path, database: str) -> list[tuple[str, int]]:
    with closing(sqlite3.connect(root / database)) as connection, connection:
        return [
            (str(account), int(generation))
            for account, generation in connection.execute(
                "SELECT account, generation FROM account_fence"
            )
        ]


@asyncio_test
async def test_a_persistent_write_is_refused_while_the_authority_is_unreadable(
    tmp_path: Path,
) -> None:
    """C11-R6: "I could not tell" is not permission.

    **This is the policy layer, not the fence.** No deletion has happened here,
    so every store-local fence still reads the generation this work was admitted
    under and would happily accept the write — the transactional fence has
    nothing to refuse with. What refuses is `JobService._may_write`, which fails
    closed when the authority cannot answer at all, because a store that cannot
    say whether an account still exists cannot be read as saying it does.

    Asserted through the application: work is admitted normally, the authority
    then becomes unreadable, and the job's own later state writes are the thing
    that must not land.
    """
    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit("user@example.test", principal=PRINCIPAL)
    admitted_state = stored_state(tmp_path, account)
    assert admitted_state is not None
    assert fence_rows(tmp_path, "jobs.db") == [], "no deletion happened, so no fence is raised"

    service.account_state = UnreadableAccountState()  # type: ignore[assignment]
    await executor.run_pending()

    assert stored_state(tmp_path, account) == admitted_state, (
        "a job state advanced on disk while the deletion authority was unreadable"
    )
    assert job_rows(tmp_path, account) == 1, "the outage created or removed a row"
    assert verdict_rows(tmp_path) == 0, "a verdict was cached while the authority was unreadable"
    assert binding_rows(tmp_path) == 0
    sink = service.operator
    assert isinstance(sink, RecordingOperatorSink)
    assert any(event.detail == "account state unavailable" for event in sink.events), (
        "the refusal was silent; an operator has no way to see the outage"
    )
    # The outage is operational and says nothing about the mailbox: no status,
    # no confidence, and no reason code reached the stored row.
    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        published = connection.execute(
            "SELECT status, confidence, primary_reason FROM jobs WHERE owner = ?", (account,)
        ).fetchone()
    assert published == (None, None, None)


@asyncio_test
async def test_the_same_write_lands_when_the_authority_can_answer(tmp_path: Path) -> None:
    """C11-R6's positive control: the refusal is the outage, not the path.

    Identical work, identical stores, and the only difference is an authority
    that answers. Without this, a change that refused *every* persistent write
    would satisfy the test above.
    """
    account = PRINCIPAL.rate_limit_account
    service, executor = fenced_replica(tmp_path)
    await service.submit("user@example.test", principal=PRINCIPAL)
    admitted_state = stored_state(tmp_path, account)

    await executor.run_pending()

    assert stored_state(tmp_path, account) != admitted_state, "the job never advanced at all"
    assert stored_state(tmp_path, account) == "completed"
    assert job_rows(tmp_path, account) == 1
    sink = service.operator
    assert isinstance(sink, RecordingOperatorSink)
    assert not [event for event in sink.events if event.detail == "account state unavailable"]


@asyncio_test
async def test_an_unreadable_authority_refuses_a_claim_too(tmp_path: Path) -> None:
    """The other write a submission makes. Same policy, different entry point."""
    service, _ = fenced_replica(tmp_path)
    service.account_state = UnreadableAccountState()  # type: ignore[assignment]

    with pytest.raises(Exception):  # noqa: B017 - the type is the store's, not this layer's
        await service.submit(
            "user@example.test",
            principal=PRINCIPAL,
            idempotency_key=IdempotencyKey("key-00000002"),
        )

    assert binding_rows(tmp_path) == 0
    assert job_rows(tmp_path, PRINCIPAL.rate_limit_account) == 0


def write_legacy_account_state(path: Path) -> None:
    """The schema this adapter wrote at version 1, and nothing newer.

    Version 1 had the generation table and no authority table — which is exactly
    why it cannot be adopted: there is no record of which deletion authority the
    stores beside it were bound to, and inventing one is the configuration
    mistake the binding exists to catch.
    """
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE account_state_schema_version (version INTEGER NOT NULL)")
        connection.execute("INSERT INTO account_state_schema_version (version) VALUES (1)")
        connection.execute(
            "CREATE TABLE account_state (account TEXT PRIMARY KEY, generation INTEGER NOT NULL)"
        )
        connection.execute("INSERT INTO account_state (account, generation) VALUES ('acct-a', 3)")


def test_legacy_fixture_closes_database_after_committing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A SQLite transaction context commits but does not close its connection."""
    real_connect = sqlite3.connect
    connections: list[sqlite3.Connection] = []

    def recording_connect(path: Path) -> sqlite3.Connection:
        connection = real_connect(path)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", recording_connect)
    path = tmp_path / "legacy.db"
    write_legacy_account_state(path)
    (connection,) = connections
    try:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
    finally:
        connection.close()

    reader = real_connect(path)
    try:
        assert reader.execute("SELECT version FROM account_state_schema_version").fetchone() == (1,)
    finally:
        reader.close()


def test_a_version_one_account_state_is_refused_rather_than_adopted(tmp_path: Path) -> None:
    """C11-R7: the legacy file is refused, and the refusal is typed.

    Behaviour rather than a constant: the test writes a real version-1 database,
    opens it with the current adapter, and requires this package's own schema
    error naming both versions. A file that opened here would silently acquire a
    fresh authority identity, and every store bound to its predecessor would
    then be locked out — or, worse, an unbound one would adopt it.
    """
    from emailcheck.adapters.storage.sqlite_account_state import AccountStateSchemaError

    legacy = tmp_path / "accounts.db"
    write_legacy_account_state(legacy)

    with pytest.raises(AccountStateSchemaError, match="schema version 1"):
        SQLiteAccountStateStore(path=legacy).initialize()

    # Refused *before* anything was written to it: no authority row was minted
    # for a file this build cannot read.
    with closing(sqlite3.connect(legacy)) as connection, connection:
        tables = {name for (name,) in connection.execute("SELECT name FROM sqlite_master")}
    assert "account_authority" not in tables


def test_a_version_one_account_state_cannot_reach_a_deployment(tmp_path: Path) -> None:
    """The same refusal where an operator meets it, rather than only at the adapter."""
    from emailcheck.adapters.storage.sqlite_account_state import AccountStateSchemaError
    from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack

    write_legacy_account_state(tmp_path / "accounts.db")

    with pytest.raises(AccountStateSchemaError):
        build_verification_stack(
            Deployment(
                api_keys={"acct-1": "k" * 32},
                correlation_key=CORRELATION_KEY,
                profile=DeploymentProfile.LAB_ACTIVE,
                lab_destination_allowlist=frozenset({"mx.test.example"}),
                job_store_path=tmp_path / "jobs.db",
                account_state_path=tmp_path / "accounts.db",
            )
        )


@asyncio_test
async def test_a_current_account_state_opens_and_works(tmp_path: Path) -> None:
    """C11-R7's positive control: the refusal is the version, not the file.

    A store this build wrote opens, keeps one stable authority identity across
    reopens, and still advances generations — so a change that refused every
    account-state database would not satisfy the test above.
    """
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    identity = state.authority_id()

    reopened = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    reopened.initialize()

    assert reopened.authority_id() == identity
    assert len(identity) == 32
    assert await reopened.generation("acct-a") == 0
    assert await reopened.advance("acct-a") == 1
    assert await state.permits("acct-a", 0) is False
    assert await state.permits("acct-a", 1) is True
