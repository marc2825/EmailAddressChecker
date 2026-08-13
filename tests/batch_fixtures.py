"""Fakes and builders for the batch subsystem. No socket, no clock, no sleep.

`InMemoryBatchStore` is to `BatchStore` what `InMemoryVerdictStore` is to
`VerdictStore`: the same contract in dictionaries, so a scenario test does not
pay for a file. The persistence, restart, expiry, and deletion tests use the
**real** `SQLiteBatchStore` instead — a fake cannot show that a restart works.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from tests.phase6_fixtures import (
    MX_ADDRESS,
    FakeClock,
    FakeRandomSource,
    FakeResolver,
    InMemoryVerdictStore,
    RecordingExecutor,
    ScriptedSMTPVerification,
    build_service,
    resolver_with_route,
)
from tests.phase7_fixtures import ACCOUNT, CORRELATION_KEY, PRINCIPAL

from emailcheck.application.batch import BatchService
from emailcheck.application.jobs import JobService
from emailcheck.application.verdict_cache import VerdictCache
from emailcheck.domain.batch import BatchApproval, BatchLimits, BatchSettings
from emailcheck.domain.dns import AddressLookup, MXLookup, MXRecord, apply_ttl_policy
from emailcheck.ports.batch_store import (
    BatchArtifact,
    BatchStoreFull,
    StoredBatch,
    StoredBatchRow,
)

__all__ = [
    "ACCOUNT",
    "CORRELATION_KEY",
    "PRINCIPAL",
    "InMemoryBatchStore",
    "MovableClock",
    "approved",
    "build_batch",
    "csv_for",
]


def approved(**kwargs: object) -> BatchSettings:
    kwargs.setdefault("approval", BatchApproval(accounts=frozenset({ACCOUNT})))
    return BatchSettings(enabled=True, **kwargs)  # type: ignore[arg-type]


def csv_for(*addresses: str, header: str = "email") -> bytes:
    body = "\n".join([header, *addresses])
    return (body + "\n").encode("utf-8")


@dataclass(slots=True)
class MovableClock:
    """A clock a test advances by hand. `FakeClock` never moves."""

    moment: datetime = datetime(2026, 8, 12, tzinfo=UTC)

    def now(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


@dataclass(slots=True)
class InMemoryBatchStore:
    """The `BatchStore` contract in dictionaries. Owner and expiry are predicates."""

    max_batches: int = 256
    batches: dict[str, StoredBatch] = field(default_factory=dict)
    artifacts: dict[str, BatchArtifact] = field(default_factory=dict)
    #: Every `update_rows` call, so a test can read the write-ahead ordering
    #: rather than infer it.
    writes: list[tuple[str, int, str]] = field(default_factory=list)

    async def save_batch(self, record: StoredBatch) -> None:
        if record.batch_id not in self.batches and len(self.batches) >= self.max_batches:
            expired = [
                key for key, held in self.batches.items() if held.expires_at <= record.created_at
            ]
            for key in expired:
                del self.batches[key]
                self.artifacts.pop(key, None)
            if len(self.batches) >= self.max_batches:
                raise BatchStoreFull("the batch store is at capacity")
        self.batches[record.batch_id] = record

    async def update_rows(self, batch_id: str, rows: tuple[StoredBatchRow, ...]) -> None:
        held = self.batches.get(batch_id)
        if held is None:
            return
        by_number = {row.number: row for row in held.rows}
        for row in rows:
            by_number[row.number] = row
            self.writes.append((batch_id, row.number, row.state.value))
        self.batches[batch_id] = StoredBatch(
            batch_id=held.batch_id,
            account=held.account,
            created_at=held.created_at,
            expires_at=held.expires_at,
            input_rows=held.input_rows,
            skipped_rows=held.skipped_rows,
            cancelled=held.cancelled,
            rows=tuple(by_number[number] for number in sorted(by_number)),
        )

    async def set_cancelled(self, batch_id: str) -> None:
        held = self.batches.get(batch_id)
        if held is None:
            return
        self.batches[batch_id] = StoredBatch(
            batch_id=held.batch_id,
            account=held.account,
            created_at=held.created_at,
            expires_at=held.expires_at,
            input_rows=held.input_rows,
            skipped_rows=held.skipped_rows,
            cancelled=True,
            rows=held.rows,
        )

    async def load_batch(self, batch_id: str, *, account: str, now: datetime) -> StoredBatch | None:
        held = self.batches.get(batch_id)
        if held is None or held.account != account or not held.live_at(now):
            return None
        return held

    async def save_artifact(self, artifact: BatchArtifact) -> None:
        self.artifacts[artifact.batch_id] = artifact

    async def load_artifact(
        self, batch_id: str, *, account: str, now: datetime
    ) -> BatchArtifact | None:
        held = self.artifacts.get(batch_id)
        if held is None or held.account != account or now >= held.expires_at:
            return None
        return held

    async def delete_batch(self, batch_id: str, *, account: str) -> bool:
        held = self.batches.get(batch_id)
        if held is None or held.account != account:
            return False
        del self.batches[batch_id]
        self.artifacts.pop(batch_id, None)
        return True

    async def forget_inputs(self, *, before: datetime, limit: int) -> int:
        cleared = 0
        for batch_id, held in list(self.batches.items()):
            if cleared >= limit or held.created_at > before:
                continue
            self.batches[batch_id] = StoredBatch(
                batch_id=held.batch_id,
                account=held.account,
                created_at=held.created_at,
                expires_at=held.expires_at,
                input_rows=held.input_rows,
                skipped_rows=held.skipped_rows,
                cancelled=held.cancelled,
                rows=tuple(
                    StoredBatchRow(
                        number=row.number,
                        state=row.state,
                        target_digest=row.target_digest,
                        job_id=row.job_id,
                        idempotency=row.idempotency,
                    )
                    for row in held.rows
                ),
            )
            cleared += 1
        return cleared

    async def purge_expired(self, *, now: datetime, limit: int = 100) -> int:
        removed = 0
        for batch_id, held in list(self.batches.items()):
            if removed >= limit or held.live_at(now):
                continue
            del self.batches[batch_id]
            self.artifacts.pop(batch_id, None)
            removed += 1
        return removed


def resolver_for(routes: dict[str, str]) -> FakeResolver:
    """One exchanger per domain, so several domains can share one.

    The scenario `prompts/10-batch.md`'s MX fairness needs and a single-domain
    fixture cannot express: two domains behind one destination are two domain
    queues and one place the packets go.
    """
    ttl = apply_ttl_policy(3600, positive=True)
    return FakeResolver(
        mx={
            domain: MXLookup(records=(MXRecord(preference=10, exchange=host),), ttl=ttl)
            for domain, host in routes.items()
        },
        a={host: AddressLookup(addresses=(MX_ADDRESS,), ttl=ttl) for host in set(routes.values())},
    )


def build_jobs(
    *,
    smtp: ScriptedSMTPVerification | None = None,
    routes: dict[str, str] | None = None,
    job_store: object | None = None,
    verdicts: object | None = None,
    executor: RecordingExecutor | None = None,
    random_prefix: str = "job",
) -> tuple[JobService, RecordingExecutor, ScriptedSMTPVerification]:
    """The whole graph a batch row touches, from the Phase 6 fixtures.

    `job_store`, `verdicts`, and `executor` are parameters so a test can build a
    **second** `JobService` sharing only what a restarted process would share:
    the files. Everything else is fresh, which is what makes a restart test a
    restart test rather than a rename.
    """
    probe = smtp if smtp is not None else ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    resolver = resolver_with_route() if routes is None else resolver_for(routes)
    service, _, sink = build_service(smtp=probe, resolver=resolver)
    used_executor = executor if executor is not None else RecordingExecutor()
    jobs = JobService(
        verification=service,
        executor=used_executor,
        clock=FakeClock(),
        random=FakeRandomSource(prefix=random_prefix),
        operator=sink,
        correlation_key=CORRELATION_KEY,
        store=job_store,  # type: ignore[arg-type]
        cache=VerdictCache(
            store=verdicts if verdicts is not None else InMemoryVerdictStore(),  # type: ignore[arg-type]
            clock=FakeClock(),
            random=FakeRandomSource(prefix="rec"),
            correlation_key=CORRELATION_KEY,
        ),
    )
    return jobs, used_executor, probe


def build_batch(
    *,
    settings: BatchSettings | None = None,
    smtp: ScriptedSMTPVerification | None = None,
    store: object | None = None,
    clock: object | None = None,
    routes: dict[str, str] | None = None,
) -> tuple[BatchService, RecordingExecutor, ScriptedSMTPVerification]:
    jobs, executor, probe = build_jobs(smtp=smtp, routes=routes)
    batch = BatchService(
        jobs=jobs,
        store=store if store is not None else InMemoryBatchStore(),  # type: ignore[arg-type]
        clock=clock if clock is not None else MovableClock(),  # type: ignore[arg-type]
        random_source=FakeRandomSource(prefix="batch"),
        settings=settings if settings is not None else approved(),
        correlation_key=CORRELATION_KEY,
    )
    return batch, executor, probe


DEFAULT_LIMITS = BatchLimits()
