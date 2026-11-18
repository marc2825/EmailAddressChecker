"""The batch subsystem, against fake adapters only.

ADR 0018's Tests section names ten scenarios and this file
covers
each: thousands of rows against fake adapters, one domain not monopolizing
workers, cancellation, restart/resume, duplicate rows, malformed CSV, output
formula injection, retention expiry, account isolation, and batch disabled for
an unapproved account.

Nothing here opens a socket, and nothing sleeps. The suite-wide guard in
`tests/conftest.py` fails any test that tries, so every count of zero is a
measurement rather than an assumption.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

import pytest
from tests.batch_fixtures import (
    ACCOUNT,
    CORRELATION_KEY,
    PRINCIPAL,
    InMemoryBatchStore,
    MovableClock,
    approved,
    build_batch,
    csv_for,
)
from tests.phase6_fixtures import FakeRandomSource
from tests.phase7_fixtures import OTHER_PRINCIPAL as OTHER

from emailcheck.application.batch import (
    BatchRefused,
    BatchReport,
    BatchService,
    FairRotation,
    _Pending,
)
from emailcheck.application.batch_csv import (
    FORMULA_PREFIXES,
    REPORT_COLUMNS,
    BatchReportRow,
    csv_cell,
    parse_batch_csv,
    render_batch_csv,
)
from emailcheck.application.jobs import JobService
from emailcheck.domain.batch import (
    ADDRESS_COLUMN,
    MAX_INPUT_RETENTION,
    MAX_ROWS,
    RESULT_MEDIA_TYPE,
    BatchApproval,
    BatchError,
    BatchId,
    BatchLimits,
    BatchRowState,
    BatchSettings,
)
from emailcheck.domain.principal import Principal

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 10.0


async def run(batch: BatchService, content: bytes, *, principal: Principal = PRINCIPAL):  # type: ignore[no-untyped-def]
    async with asyncio.timeout(OUTER_BOUND):
        return await batch.submit(content, principal=principal)


def pending(number: int, domain: str) -> _Pending:
    return _Pending(
        number=number,
        domain=domain,
        target_digest=f"digest-{number}",
        idempotency=f"handle-{number}",
        submitted=f"user{number}@{domain}",
    )


# --- batch is an operational permission -------------------------------------


def test_the_feature_is_disabled_by_default() -> None:
    assert BatchSettings().enabled is False
    assert BatchSettings().approval.accounts == frozenset()


def test_enabling_the_feature_does_not_approve_an_account() -> None:
    """`docs/requirements.md` section 15: an operational permission, not a toggle."""
    assert BatchSettings(enabled=True).permits(ACCOUNT) is False
    assert (
        BatchSettings(approval=BatchApproval(accounts=frozenset({ACCOUNT}))).permits(ACCOUNT)
        is False
    )
    assert approved().permits(ACCOUNT) is True


@asyncio_test
async def test_an_unapproved_account_submits_nothing_and_parses_nothing() -> None:
    """The prompt's last test, and the gate is **before the file is read**.

    Parsing is work a caller can ask for — decoding, a CSV reader, a parse per
    row — and an account that may not run a batch must not be able to ask for
    it. The input here is deliberately unparseable: if the parser ran at all,
    the refusal would be a `BatchError` about the header rather than a
    `BatchRefused` about the account.
    """
    batch, executor, probe = build_batch(settings=BatchSettings(enabled=True))

    with pytest.raises(BatchRefused):
        await run(batch, b"\xff\xfe not a csv at all")

    assert executor.submitted == []
    assert probe.calls == []


@asyncio_test
async def test_another_approved_accounts_batch_is_still_refused() -> None:
    batch, executor, _ = build_batch()

    with pytest.raises(BatchRefused):
        await run(batch, csv_for("user@example.test"), principal=OTHER)

    assert executor.submitted == []


# --- input ------------------------------------------------------------------


def test_a_malformed_input_is_refused_without_naming_its_contents() -> None:
    """An error message about somebody's file is a place an address ends up."""
    for content, reason in (
        (b"\xff\xfe not utf-8", "UTF-8"),
        (b"name,phone\nx,y\n", "email"),
        (b"", "header"),
        (b"email\nuser@example.test\x00\n", "NUL"),
    ):
        with pytest.raises(BatchError) as raised:
            parse_batch_csv(content)
        assert reason in str(raised.value)
        assert "user@example.test" not in str(raised.value)


#: The UTF-8 encoding of U+FEFF, which spreadsheet "CSV UTF-8" exports put first.
UTF8_BOM: Final = b"\xef\xbb\xbf"


def test_a_leading_byte_order_mark_is_accepted() -> None:
    """Issue #2: a spreadsheet export starts with a BOM and must still be read.

    `docs/usage-ja.md` documents CSV input as UTF-8 with an optional BOM, and the
    local CLI path already accepted one. The service path decoded with plain
    `utf-8`, so the BOM became part of the first header name and the file was
    refused for lacking an `email` column. The fixture here is the exact shape
    such an export has: BOM, CRLF line endings, more than one column.
    """
    content = UTF8_BOM + b"email,name\r\nuser@example.test,A\r\nother@example.test,B\r\n"

    parsed = parse_batch_csv(content)

    assert [row.submitted for row in parsed.rows] == ["user@example.test", "other@example.test"]
    assert all(row.parsed for row in parsed.rows)


def test_only_a_leading_byte_order_mark_is_removed() -> None:
    """A U+FEFF anywhere else is the submitter's data, and the parser judges it.

    Stripping it from a cell would be rewriting an address. U+FEFF is a format
    character, which Phase 1 rejects in a local part, so the row is reported
    rather than silently cleaned.
    """
    parsed = parse_batch_csv(b"email\n" + UTF8_BOM + b"user@example.test\n")

    assert len(parsed) == 1
    assert parsed.rows[0].parsed is False
    assert parsed.rows[0].rejection is not None


def test_a_byte_order_mark_counts_against_the_byte_limit() -> None:
    """The bound is on what was uploaded, checked before decoding, BOM included."""
    content = UTF8_BOM + csv_for("user@example.test")

    parse_batch_csv(content, limits=BatchLimits(max_input_bytes=len(content)))
    with pytest.raises(BatchError):
        parse_batch_csv(content, limits=BatchLimits(max_input_bytes=len(content) - 1))


def test_the_row_and_byte_limits_are_both_enforced() -> None:
    """Either alone is bypassable: many tiny rows, or one enormous one."""
    limits = BatchLimits(max_rows=2, max_input_bytes=4 * 1024 * 1024)

    parse_batch_csv(csv_for("a@example.test", "b@example.test"), limits=limits)
    with pytest.raises(BatchError):
        parse_batch_csv(
            csv_for("a@example.test", "b@example.test", "c@example.test"), limits=limits
        )

    tiny = BatchLimits(max_rows=10, max_input_bytes=32)
    with pytest.raises(BatchError):
        parse_batch_csv(csv_for("a-very-long-local-part@example.test"), limits=tiny)


def test_the_limits_refuse_a_boolean_and_a_ceiling() -> None:
    for kwargs in (
        {"max_rows": True},
        {"max_rows": 0},
        {"max_rows": MAX_ROWS + 1},
        {"max_in_flight": True},
        {"max_in_flight": 0},
        {"max_in_flight_per_domain": 0},
        {"max_in_flight_per_mx": True},
    ):
        with pytest.raises(BatchError):
            BatchLimits(**kwargs)  # type: ignore[arg-type]

    # A bound above the one it sits inside bounds nothing.
    with pytest.raises(BatchError):
        BatchLimits(max_in_flight=2, max_in_flight_per_domain=4, max_in_flight_per_mx=4)
    with pytest.raises(BatchError):
        BatchLimits(max_in_flight=8, max_in_flight_per_mx=2, max_in_flight_per_domain=4)


def test_an_unparseable_row_does_not_fail_the_file() -> None:
    """ADR 0018's scheduler asks for partial failure."""
    parsed = parse_batch_csv(csv_for("good@example.test", "not-an-address", "also@example.test"))

    assert len(parsed) == 3
    assert [row.parsed for row in parsed.rows] == [True, False, True]
    assert parsed.rows[1].rejection is not None


def test_a_whitespace_row_is_counted_and_a_blank_line_is_rejected() -> None:
    """An address cell holding only spaces is skipped and counted.

    A blank line has no fields at all, so its field count differs from the
    header and it is a rejected row, as in the local CLI. Nothing is dropped
    silently, so the report balances against the file.
    """
    parsed = parse_batch_csv(b"email\nuser@example.test\n\n   \n")

    assert [(row.number, row.parsed, row.malformed) for row in parsed.rows] == [
        (1, True, False),
        (2, False, True),
    ]
    assert parsed.skipped == 1


# --- one reading rule for the service and the local CLI (audit 2026-11-17) ---


@pytest.mark.parametrize(
    "header",
    [b"email,email", b"Email, email ", b"email,name,name"],
    ids=["duplicate-email", "duplicate-after-normalization", "duplicate-other"],
)
def test_a_repeated_column_name_is_refused(header: bytes) -> None:
    """A dict-based reader kept the last `email` cell; both paths now refuse."""
    content = header + b"\nalice@example.test,bob@example.test,x\n"

    with pytest.raises(BatchError, match="repeat"):
        parse_batch_csv(content)


@pytest.mark.parametrize(
    "line",
    [b"short@example.test", b"long@example.test,A,extra"],
    ids=["too-few-fields", "too-many-fields"],
)
def test_a_row_with_the_wrong_field_count_is_rejected(line: bytes) -> None:
    parsed = parse_batch_csv(b"email,name\n" + line + b"\nok@example.test,B\n")

    assert parsed.rows[0].malformed is True
    assert parsed.rows[0].parsed is False
    assert parsed.rows[0].submitted == ""
    assert parsed.rows[1].parsed is True


def test_broken_csv_syntax_refuses_the_file() -> None:
    """A strict reader, as in the local CLI; the error names no content."""
    with pytest.raises(BatchError, match="well-formed CSV") as raised:
        parse_batch_csv(b'email\n"user@example.test\n')

    assert "user@example.test" not in str(raised.value)


def test_only_ascii_whitespace_is_trimmed_as_in_the_parser() -> None:
    """`str.strip()` removed U+00A0 too, so the CSV accepted what the parser refuses."""
    nbsp = b"\xc2\xa0user@example.test\xc2\xa0"  # U+00A0 on both sides
    parsed = parse_batch_csv(b"email\n \tuser@example.test \n" + nbsp + b"\n\xc2\xa0\n")

    assert parsed.rows[0].parsed is True
    assert parsed.rows[0].submitted == "user@example.test"
    assert [row.parsed for row in parsed.rows[1:]] == [False, False]
    assert parsed.skipped == 0


def test_a_domain_literal_reaches_phase_ones_rejection_through_the_csv() -> None:
    """`docs/requirements.md` section 6's "unsupported, not automatically invalid"."""
    parsed = parse_batch_csv(csv_for("user@[192.0.2.1]"))

    assert parsed.rows[0].parsed is False
    assert parsed.rows[0].rejection is not None


# --- output -----------------------------------------------------------------


def test_the_guarded_prefixes_are_exactly_these_characters() -> None:
    """The list is pinned by **literal**, not by reading the constant back.

    A mutation removing `=` and `@` from `FORMULA_PREFIXES` survived the whole
    suite, because the only test of the prefixes parametrized over the constant
    itself: deleting an entry deleted its own test case. That is the tautology
    this repository has met in several shapes, and the fix is the same one every
    time — write the characters down here, where a change has to be made twice
    and read once.
    """
    assert set(FORMULA_PREFIXES) == {"=", "+", "-", "@", "\t", "\r"}


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_every_formula_prefix_is_neutralised(prefix: str) -> None:
    """
    ADR 0018 Output: cells protected against formula injection.
    """
    rendered = csv_cell(f"{prefix}cmd|'/c calc'!A0")

    assert rendered.startswith("'")
    assert not rendered.startswith(prefix)
    # The value is preserved rather than stripped: an investigator needs to see
    # what the submitter actually sent.
    assert prefix in rendered


def test_a_leading_at_sign_is_guarded_even_though_every_address_holds_one() -> None:
    """`@` is Excel's function reference *and* the character in every address.

    Named separately because it is the prefix somebody removes while reasoning
    that addresses contain `@` anyway — which is true of the middle of the cell
    and irrelevant to its first character.
    """
    assert csv_cell("@SUM(1+1)*cmd|'/c calc'!A0").startswith("'@")
    assert csv_cell("=1+1").startswith("'=")


def test_an_ordinary_cell_is_untouched() -> None:
    assert csv_cell("likely_deliverable") == "likely_deliverable"
    assert csv_cell("row_state") == "row_state"


def test_a_hostile_value_survives_into_the_report_as_text() -> None:
    """Every cell, not the ones that look risky.

    No submitter-controlled text reaches the renderer any more — the address
    column was removed because it was always empty — so this drives a hostile
    value through a *published-vocabulary* field instead. The point is the
    renderer's rule rather than the field: a column added later must arrive
    escaped, and this is what fails if `render_batch_csv` starts trusting one.
    """
    rendered = render_batch_csv(
        (
            BatchReportRow(
                number=1,
                row_state=BatchRowState.REJECTED,
                primary_reason='=HYPERLINK("http://evil.test","click")',
            ),
        )
    )

    import csv as csv_module
    import io

    cell = list(csv_module.reader(io.StringIO(rendered)))[1][REPORT_COLUMNS.index("primary_reason")]
    # Read back through a reader, because the writer quotes a cell holding a
    # comma and asserting on the raw text would pass on the quoting rather than
    # on the guard.
    assert cell.startswith("'=HYPERLINK")


def test_the_report_carries_no_field_a_raw_reply_could_occupy() -> None:
    """ADR 0018 Output: *no raw SMTP replies*. Structural.

    Every column is either an integer, a published row state, a published job
    state, or vocabulary `application/public_result.py` already allows out.
    There is no diagnostic column, so the question of sanitizing one never
    arises.
    """
    import dataclasses

    fields = {field.name for field in dataclasses.fields(BatchReportRow)}

    assert fields == {
        "number",
        "row_state",
        "job_state",
        "status",
        "confidence",
        "primary_reason",
        "reason_codes",
        "risk_flags",
        "job_id",
    }
    for forbidden in ("diagnostic", "reply", "banner", "peer", "transcript", "error"):
        assert not any(forbidden in name for name in REPORT_COLUMNS), forbidden

    # **And no address column at all.** It was always empty, because the
    # submitted text is retained only while a row may still need submitting.
    assert ADDRESS_COLUMN not in REPORT_COLUMNS
    assert REPORT_COLUMNS == (
        "row",
        "row_state",
        "job_state",
        "status",
        "confidence",
        "primary_reason",
        "reason_codes",
        "risk_flags",
    )


# --- fairness ---------------------------------------------------------------


def test_a_busy_domain_does_not_make_a_quiet_one_wait() -> None:
    """ADR 0018: one domain cannot monopolize workers."""
    rotation = FairRotation()
    for number in range(9):
        rotation.add(pending(number + 1, "busy.test"))
    rotation.add(pending(100, "quiet.test"))

    order: list[str] = []
    limits = BatchLimits(max_in_flight=4, max_in_flight_per_domain=4, max_in_flight_per_mx=4)
    while True:
        taken = rotation.take(limits=limits)
        if taken is None:
            break
        order.append(taken.domain)
        rotation.release(taken, group=rotation.group_for(taken.domain))

    # Second, not tenth. Ordering by row number would put it last.
    assert order[1] == "quiet.test"
    assert order.count("busy.test") == 9


def test_one_exchanger_cannot_monopolize_workers_across_several_domains() -> None:
    """ADR 0018: fair scheduling by target domain **and MX**.

    Domain rotation alone satisfies every per-domain rule and still lets one
    provider take everything: two busy domains behind one exchanger get two
    thirds of a three-way rotation. Grouping by the exchanger the pipeline
    reported makes it a half.
    """
    rotation = FairRotation()
    for number in range(9):
        rotation.add(pending(number + 1, "a.test"))
        rotation.add(pending(number + 20, "b.test"))
    rotation.add(pending(50, "c.test"))
    rotation.add(pending(51, "c.test"))
    # What the ordinary pipeline reported for a row of each domain.
    rotation.learn("a.test", "mx.shared.test")
    rotation.learn("b.test", "mx.shared.test")
    rotation.learn("c.test", "mx.quiet.test")

    order: list[str] = []
    limits = BatchLimits(max_in_flight=8, max_in_flight_per_domain=8, max_in_flight_per_mx=8)
    while True:
        taken = rotation.take(limits=limits)
        if taken is None:
            break
        order.append(taken.domain)
        rotation.release(taken, group=rotation.group_for(taken.domain))

    served = [index for index, domain in enumerate(order) if domain == "c.test"]
    # The quiet exchanger takes every other opportunity, so both of its rows are
    # served in the first four — where a three-way domain rotation would put the
    # second at position five.
    assert served == [1, 3]
    assert len(order) == 20


def test_a_domain_behind_a_shared_exchanger_still_rotates_with_its_neighbour() -> None:
    """MX fairness must not swallow domain fairness. Both, or neither is kept."""
    rotation = FairRotation()
    for number in range(4):
        rotation.add(pending(number + 1, "a.test"))
    rotation.add(pending(20, "b.test"))
    rotation.learn("a.test", "mx.shared.test")
    rotation.learn("b.test", "mx.shared.test")

    order: list[str] = []
    limits = BatchLimits(max_in_flight=8, max_in_flight_per_domain=8, max_in_flight_per_mx=8)
    while True:
        taken = rotation.take(limits=limits)
        if taken is None:
            break
        order.append(taken.domain)
        rotation.release(taken, group=rotation.group_for(taken.domain))

    assert order[1] == "b.test"


def test_the_per_domain_cap_holds_when_there_is_nothing_to_rotate_to() -> None:
    rotation = FairRotation()
    for number in range(5):
        rotation.add(pending(number + 1, "only.test"))
    limits = BatchLimits(max_in_flight=8, max_in_flight_per_domain=2, max_in_flight_per_mx=4)

    first = rotation.take(limits=limits)
    second = rotation.take(limits=limits)

    assert first is not None and second is not None
    # Capped, and **not** empty. The two are different answers.
    assert rotation.take(limits=limits) is None
    assert len(rotation) == 3
    rotation.release(first, group=rotation.group_for("only.test"))
    assert rotation.take(limits=limits) is not None


def test_the_per_exchanger_cap_holds_across_domains_that_share_one() -> None:
    """The bound the per-domain cap cannot express: many domains, one destination."""
    rotation = FairRotation()
    for index, domain in enumerate(("a.test", "b.test", "c.test", "d.test")):
        rotation.add(pending(index + 1, domain))
        rotation.learn(domain, "mx.shared.test")
    limits = BatchLimits(max_in_flight=8, max_in_flight_per_domain=1, max_in_flight_per_mx=2)

    taken = [rotation.take(limits=limits) for _ in range(3)]

    assert taken[0] is not None and taken[1] is not None
    assert taken[2] is None, "a third row reached one exchanger"
    assert len(rotation) == 2


def test_learning_an_exchanger_never_lets_a_domain_jump_the_queue() -> None:
    rotation = FairRotation()
    rotation.add(pending(1, "first.test"))
    rotation.add(pending(2, "second.test"))
    rotation.learn("second.test", "mx.late.test")
    limits = BatchLimits(max_in_flight=8, max_in_flight_per_domain=8, max_in_flight_per_mx=8)

    taken = rotation.take(limits=limits)

    assert taken is not None
    assert taken.domain == "first.test"


# --- running a batch ---------------------------------------------------------


@asyncio_test
async def test_every_row_reaches_the_ordinary_job_service() -> None:
    batch, executor, _ = build_batch()

    report = await run(batch, csv_for("a@example.test", "b@example.test", "c@example.test"))

    assert report.state_summary[BatchRowState.SUBMITTED.value] == 3
    assert len(executor.submitted) == 3


@asyncio_test
async def test_a_file_with_a_byte_order_mark_runs_like_one_without() -> None:
    """Issue #2, end to end: the service accepts what the local CLI accepts."""
    batch, executor, _ = build_batch()

    report = await run(batch, UTF8_BOM + csv_for("a@example.test", "b@example.test"))

    assert report.state_summary[BatchRowState.SUBMITTED.value] == 2
    assert len(executor.submitted) == 2


@asyncio_test
async def test_duplicate_rows_are_detected_by_digest_and_submitted_once() -> None:
    """ADR 0018 Input: duplicate detection by HMAC."""
    batch, executor, _ = build_batch()

    report = await run(batch, csv_for("a@example.test", "a@example.test", "b@example.test"))

    assert report.state_summary[BatchRowState.DUPLICATE.value] == 1
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 2
    assert len(executor.submitted) == 2
    # The duplicate keeps its own position, so the report lines up with the file.
    assert report.rows[1].row_state is BatchRowState.DUPLICATE
    assert report.rows[1].number == 2


@asyncio_test
async def test_an_unparseable_row_is_reported_without_reaching_a_job() -> None:
    batch, executor, _ = build_batch()

    report = await run(batch, csv_for("good@example.test", "not-an-address"))

    assert report.state_summary[BatchRowState.REJECTED.value] == 1
    assert len(executor.submitted) == 1
    assert report.rows[1].status is None


@asyncio_test
async def test_a_refused_row_is_operational_and_never_a_verdict() -> None:
    """A full executor is not a fact about an address. ADR 0013."""
    batch, executor, _ = build_batch()
    executor.full = True

    report = await run(batch, csv_for("a@example.test", "b@example.test"))

    assert report.state_summary[BatchRowState.REFUSED.value] == 2
    for row in report.rows:
        assert row.status is None
        assert row.row_state is BatchRowState.REFUSED


@asyncio_test
async def test_the_report_is_in_input_order_and_accounts_for_every_row() -> None:
    batch, _, _ = build_batch()

    report = await run(
        batch, csv_for("a@example.test", "not-an-address", "a@example.test", "b@other.test")
    )

    assert [row.number for row in report.rows] == [1, 2, 3, 4]
    assert sum(report.state_summary.values()) == report.input_rows == 4


def test_a_report_refuses_to_lose_a_row() -> None:
    """Phase 8's accounting invariant, applied to a batch."""
    moment = datetime(2026, 8, 12, tzinfo=UTC)

    with pytest.raises(BatchError):
        BatchReport(
            batch_id=BatchId("a" * 22),
            account=ACCOUNT,
            submitted_at=moment,
            finished_at=moment,
            input_rows=3,
            skipped_rows=0,
            rows=(),
        )


@dataclass
class _ConcurrencyProbe:
    """A `JobService` stand-in that records how many rows are in flight at once.

    The bound is unobservable from a report — every row finishes either way —
    so it is measured at the seam instead. Deterministic and sleepless: the
    delegate yields to the event loop, which is what lets several workers
    overlap at all.
    """

    inner: JobService
    peak: int = 0
    _live: int = 0

    def get(self, *args: object, **kwargs: object) -> object:
        return self.inner.get(*args, **kwargs)  # type: ignore[arg-type]

    async def fetch(self, *args: object, **kwargs: object) -> object:
        return await self.inner.fetch(*args, **kwargs)  # type: ignore[arg-type]

    async def submit(self, raw: str, **kwargs: object):  # type: ignore[no-untyped-def]
        self._live += 1
        self.peak = max(self.peak, self._live)
        try:
            await asyncio.sleep(0)
            outcome = await self.inner.submit(raw, **kwargs)  # type: ignore[arg-type]
            await asyncio.sleep(0)
            return outcome
        finally:
            self._live -= 1


@asyncio_test
async def test_the_global_worker_bound_holds_across_many_domains() -> None:
    """ADR 0018: *bounded global workers*.

    Neither narrower cap bounds the batch: eight domains at two each is sixteen,
    and several exchangers at four each is more. Dropping the `max_in_flight`
    term from the worker count survived the whole suite until this test existed,
    because every row still completed and the report still balanced. A bound
    nobody measures is a comment.
    """
    limits = BatchLimits(
        max_rows=200, max_in_flight=3, max_in_flight_per_domain=3, max_in_flight_per_mx=3
    )
    batch, _, _ = build_batch(settings=approved(limits=limits))
    probe = _ConcurrencyProbe(inner=batch.jobs)
    batch.jobs = probe  # type: ignore[assignment]
    addresses = tuple(f"user{index}@domain{index % 8}.test" for index in range(40))

    report = await run(batch, csv_for(*addresses))

    assert sum(report.state_summary.values()) == 40
    assert probe.peak > 1, "the workers never overlapped, so the bound is untested"
    assert probe.peak <= limits.max_in_flight


@asyncio_test
async def test_a_thousand_rows_run_against_fakes_within_the_worker_bound() -> None:
    """ADR 0018: thousands of rows against fake adapters.

    Structural, not timed: the assertion is that every row is accounted for and
    that the work went through the ordinary executor, never that it was fast.
    """
    batch, executor, _ = build_batch(settings=approved(limits=BatchLimits(max_rows=2000)))
    addresses = tuple(f"user{index}@example.test" for index in range(1000))

    report = await run(batch, csv_for(*addresses))

    summary = report.state_summary
    assert report.input_rows == 1000
    assert sum(summary.values()) == 1000, "a row was lost"

    # The Phase 6 registry holds 512 jobs, so a thousand-row batch submits what
    # fits and **refuses the rest explicitly**. That is the property worth
    # asserting: a batch may not assume the executor's refusal is harmless, and
    # no row disappears because the registry was full.
    submitted = summary[BatchRowState.SUBMITTED.value]
    refused = summary[BatchRowState.REFUSED.value]
    assert submitted == len(executor.submitted) == 512
    assert refused == 488
    assert submitted + refused == 1000
    assert all(
        row.job_id is not None for row in report.rows if row.row_state is BatchRowState.SUBMITTED
    )


def test_the_plaintext_retention_ceiling_is_twenty_four_hours_by_literal() -> None:
    """`docs/privacy.md` section 3's window, pinned by **number**.

    Written as `86_400` rather than as `MAX_INPUT_RETENTION`, because a test
    phrased in terms of the constant moves with it: raising the ceiling to a
    year survived the whole suite until this row existed, which is the same
    tautology the formula-prefix list had. The ceiling is a policy, and a policy
    that can be relaxed by editing the thing that states it is not one.
    """
    day = 86_400

    assert day == MAX_INPUT_RETENTION
    # Under the ceiling, and exactly at it.
    assert BatchSettings(input_retention_seconds=60).input_retention_seconds == 60
    assert BatchSettings(input_retention_seconds=day).input_retention_seconds == day
    # One second over, and every other shape a bound must refuse.
    for value in (day + 1, 7 * day, 365 * day, 0, -1, True):
        with pytest.raises(BatchError):
            BatchSettings(input_retention_seconds=value)  # type: ignore[arg-type]


def test_the_batch_identifier_is_unguessable_by_construction() -> None:
    """ADR 0014's rule: ownership is the second barrier, entropy is the first.

    A short identifier would let one account enumerate another's batches, and
    the ownership check would then be the only thing between them.
    """
    for value in ("short", "", "a" * 15, "a" * 65, "not/url-safe!!!!!!!!!"):
        with pytest.raises(BatchError):
            BatchId(value)
    assert BatchId("a" * 16).value == "a" * 16
    assert BatchId("Ab-9_" + "x" * 12).value.startswith("Ab-9_")


def test_a_stored_batch_refuses_a_naive_timestamp_and_a_mailbox_account() -> None:
    """The store's record type fixes what may be kept; the adapter adds nothing.

    Both refusals are the ones `ports/verdict_store.py` already makes, and
    neither is exercised by an ordinary run — which is exactly why they need a
    test of their own rather than being inferred from one.
    """
    from datetime import datetime as raw_datetime

    from emailcheck.ports.batch_store import BatchArtifact, StoredBatch

    moment = raw_datetime(2026, 8, 12, tzinfo=UTC)
    naive = raw_datetime(2026, 8, 12)

    with pytest.raises(BatchError):
        StoredBatch(
            batch_id="b" * 16,
            account=ACCOUNT,
            created_at=naive,
            expires_at=moment,
            input_rows=1,
            skipped_rows=0,
        )
    with pytest.raises(BatchError):
        StoredBatch(
            batch_id="b" * 16,
            account="someone@example.test",
            created_at=moment,
            expires_at=moment.replace(hour=1),
            input_rows=1,
            skipped_rows=0,
        )
    with pytest.raises(BatchError):
        BatchArtifact(
            batch_id="b" * 16,
            account=ACCOUNT,
            created_at=naive,
            expires_at=moment,
            media_type=RESULT_MEDIA_TYPE,
            content="",
        )
    with pytest.raises(BatchError):
        BatchArtifact(
            batch_id="b" * 16,
            account="someone@example.test",
            created_at=moment,
            expires_at=moment.replace(hour=1),
            media_type=RESULT_MEDIA_TYPE,
            content="",
        )


# --- the exchanger comes from the pipeline -----------------------------------


@asyncio_test
async def test_an_ordinary_submission_reports_the_exchanger_it_would_reach() -> None:
    """The seam MX fairness rests on, pinned where it is produced.

    The rotation tests hand `learn` a literal key, so they cannot notice a
    pipeline that reports nothing — and a scheduler that learns nothing silently
    degrades to domain-only fairness, which is the half of the requirement that
    was already there. This asserts the value actually arrives.
    """
    from tests.phase6_fixtures import MX_HOST

    batch, _, _ = build_batch()

    outcome = await batch.jobs.submit("user@example.test", principal=PRINCIPAL)

    assert outcome.scheduling_key == MX_HOST


@asyncio_test
async def test_a_target_with_nowhere_to_connect_reports_no_exchanger() -> None:
    """`None` is correct rather than missing: it shares no destination.

    Read from `connectable_candidates`, so a Null MX answers `None` because
    Phase 2 already decided there is nowhere to connect — nothing here
    re-interprets a DNS answer.
    """
    from tests.phase6_fixtures import build_service, resolver_with_null_mx

    service, _, _ = build_service(resolver=resolver_with_null_mx())

    outcome = await service.verify("user@example.test", principal=PRINCIPAL, active=False)

    assert outcome.scheduling_key is None


# --- the one shared cache ----------------------------------------------------


@asyncio_test
async def test_a_batch_row_is_served_by_the_cache_a_single_check_filled() -> None:
    """ADR 0018: *one active result cache shared with single
    checks*.

    Proved by measurement at the executor rather than by reading the wiring: a
    single check populates the ordinary `VerdictCache`, and the batch row for
    the same target then enqueues nothing. A batch-private cache would miss.
    """
    batch, executor, probe = build_batch()
    probe.reply_lines = ("250 2.1.5 ok",)

    single = await batch.jobs.submit("shared@example.test", principal=PRINCIPAL)
    await executor.run_pending()
    assert single.enqueued is True
    before = len(executor.submitted)

    report = await run(batch, csv_for("shared@example.test", "other@example.test"))

    # Two rows, one of which the cache already had: exactly one new enqueue.
    assert len(executor.submitted) == before + 1
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 2


# --- cancellation ------------------------------------------------------------


@asyncio_test
async def test_cancelling_leaves_every_unsubmitted_row_visible() -> None:
    """No disappeared rows: cancellation is a state, not an absence."""
    store = InMemoryBatchStore()
    batch, _, _ = build_batch(
        store=store,
        settings=approved(
            limits=BatchLimits(max_in_flight=1, max_in_flight_per_domain=1, max_in_flight_per_mx=1)
        ),
    )
    batch.random_source = FakeRandomSource(prefix="cancelled")  # type: ignore[assignment]
    batch._cancelled.add("cancelled-0001xxxxxxxxxx")

    report = await run(batch, csv_for(*(f"u{index}@example.test" for index in range(20))))

    assert report.cancelled is True
    assert report.state_summary[BatchRowState.CANCELLED.value] == 20
    assert sum(report.state_summary.values()) == 20


@asyncio_test
async def test_cancelling_a_stored_batch_marks_its_pending_rows_and_persists_it() -> None:
    store = InMemoryBatchStore()
    batch, executor, _ = build_batch(store=store)
    executor.full = True
    report = await run(batch, csv_for("a@example.test"))

    assert await batch.cancel(report.batch_id, principal=PRINCIPAL) is True

    held = store.batches[report.batch_id.value]
    assert held.cancelled is True


@asyncio_test
async def test_another_account_cannot_cancel_read_or_delete_a_batch() -> None:
    """ADR 0018 Tests: account isolation."""
    batch, _, _ = build_batch()
    report = await run(batch, csv_for("a@example.test"))

    assert await batch.cancel(report.batch_id, principal=OTHER) is False
    assert await batch.report(report.batch_id, principal=OTHER) is None
    assert await batch.result(report.batch_id, principal=OTHER) is None
    assert await batch.delete(report.batch_id, principal=OTHER) is False
    # And the owner's batch is untouched by the attempt.
    assert await batch.report(report.batch_id, principal=PRINCIPAL) is not None


@asyncio_test
async def test_an_unknown_identifier_answers_what_another_accounts_does() -> None:
    batch, _, _ = build_batch()
    report = await run(batch, csv_for("a@example.test"))
    unknown = BatchId("unknown" + "x" * 15)

    assert await batch.report(unknown, principal=PRINCIPAL) is None
    assert await batch.report(report.batch_id, principal=OTHER) is None


# --- the expiring downloadable result ---------------------------------------


@asyncio_test
async def test_a_result_is_downloadable_by_its_owner_until_it_expires() -> None:
    """
    ADR 0018 Output: *expiring downloadable result*. Fake
    clock.
    """
    clock = MovableClock()
    batch, _, _ = build_batch(clock=clock, settings=approved(result_retention_seconds=3600))
    report = await run(batch, csv_for("a@example.test"))

    artifact = await batch.result(report.batch_id, principal=PRINCIPAL)
    assert artifact is not None
    assert artifact.media_type == RESULT_MEDIA_TYPE
    assert artifact.content.startswith("row,row_state,job_state,status")

    clock.advance(3600)
    assert await batch.result(report.batch_id, principal=PRINCIPAL) is None


@asyncio_test
async def test_an_expired_batch_answers_nothing_and_cannot_be_resumed() -> None:
    clock = MovableClock()
    batch, _, _ = build_batch(clock=clock, settings=approved(result_retention_seconds=60))
    report = await run(batch, csv_for("a@example.test"))

    clock.advance(120)

    assert await batch.report(report.batch_id, principal=PRINCIPAL) is None
    assert await batch.result(report.batch_id, principal=PRINCIPAL) is None
    assert await batch.resume(report.batch_id, principal=PRINCIPAL) is None


@asyncio_test
async def test_a_result_is_a_submission_report_until_its_jobs_finish() -> None:
    """ADR 0018 Output is a deliverability report, so it must
    say so.

    A batch stops submitting long before its verifications stop running.
    Exporting a `submitted` row with a status column filled in from the passive
    half would present a partial answer as the final one — the failure mode no
    amount of CSV escaping catches.
    """
    batch, executor, _ = build_batch()
    report = await run(batch, csv_for("a@example.test"))

    assert report.complete is False
    assert report.rows[0].status is None
    assert report.rows[0].job_state == "pending"

    await executor.run_pending()
    final = await batch.report(report.batch_id, principal=PRINCIPAL)

    assert final is not None
    assert final.complete is True
    assert final.rows[0].job_state == "completed"
    assert final.rows[0].status is not None
    artifact = await batch.result(report.batch_id, principal=PRINCIPAL)
    assert artifact is not None and artifact.complete is True


# --- deletion ----------------------------------------------------------------


@asyncio_test
async def test_deleting_removes_the_result_the_state_and_the_retained_plaintext() -> None:
    store = InMemoryBatchStore()
    batch, executor, _ = build_batch(store=store)
    executor.full = True
    report = await run(batch, csv_for("a@example.test", "b@example.test"))

    assert await batch.delete(report.batch_id, principal=PRINCIPAL) is True

    assert store.batches == {}
    assert store.artifacts == {}
    assert await batch.report(report.batch_id, principal=PRINCIPAL) is None
    assert await batch.result(report.batch_id, principal=PRINCIPAL) is None
    assert await batch.resume(report.batch_id, principal=PRINCIPAL) is None


@asyncio_test
async def test_another_accounts_delete_removes_nothing() -> None:
    store = InMemoryBatchStore()
    batch, _, _ = build_batch(store=store)
    report = await run(batch, csv_for("a@example.test"))

    assert await batch.delete(report.batch_id, principal=OTHER) is False

    assert report.batch_id.value in store.batches
    assert await batch.result(report.batch_id, principal=PRINCIPAL) is not None


# --- privacy -----------------------------------------------------------------


@asyncio_test
async def test_no_submitted_address_survives_a_terminal_row_or_a_repr() -> None:
    """The persistent store is the new privacy surface; this is its audit."""
    store = InMemoryBatchStore()
    batch, _, _ = build_batch(store=store)

    report = await run(batch, csv_for("very.secret.localpart+tag@example.test"))

    held = store.batches[report.batch_id.value]
    assert held.rows[0].submitted is None, "a submitted row kept its plaintext"
    for text in (
        repr(batch),
        repr(held),
        repr(held.rows[0]),
        repr(report),
        repr(await batch.result(report.batch_id, principal=PRINCIPAL)),
    ):
        assert "very.secret.localpart" not in text
    # The digest is what survives, and it is not the address.
    assert held.rows[0].target_digest is not None
    assert "@" not in held.rows[0].target_digest


@asyncio_test
async def test_the_idempotency_handle_is_deterministic_and_carries_no_address() -> None:
    """ADR 0018 has no idempotency of its own; Phase 6's is
    reused.

    Derived from the batch, the row's position, the account, and the target
    digest — so the same row of the same batch always presents the same handle,
    which is what makes a resume recover rather than duplicate.
    """
    store = InMemoryBatchStore()
    batch, executor, _ = build_batch(store=store)
    executor.full = True
    report = await run(batch, csv_for("secret@example.test"))

    row = store.batches[report.batch_id.value].rows[0]
    handle = row.idempotency
    digest = row.target_digest or ""
    assert handle is not None
    assert handle.startswith("b10-")
    assert "secret" not in handle and "@" not in handle

    # **Recomputed by a different service**, not by the one that made it. A
    # handle derived from anything belonging to the instance would match itself
    # and nothing else, which is a tautology rather than determinism — and a
    # mutation adding `id(self)` to the material survived until this said
    # `other` instead of `batch`.
    other, _, _ = build_batch(store=InMemoryBatchStore())
    assert other is not batch
    assert other._handle(report.batch_id, 1, ACCOUNT, digest) == handle
    # And it is per row, per batch, and per account.
    assert other._handle(report.batch_id, 2, ACCOUNT, digest) != handle
    assert other._handle(BatchId("z" * 22), 1, ACCOUNT, digest) != handle
    assert other._handle(report.batch_id, 1, "another", digest) != handle


@asyncio_test
async def test_the_claim_is_written_before_the_row_is_submitted() -> None:
    """The crash boundary, read off the write log rather than reasoned about.

    Recording after the call would leave a row that looks untouched and a
    verification that is already running — the case ADR 0018's
    restart/resume test exists to make safe.
    """
    store = InMemoryBatchStore()
    batch, _, _ = build_batch(store=store)

    await run(batch, csv_for("a@example.test"))

    states = [state for _, _, state in store.writes]
    assert states[0] == BatchRowState.CLAIMED.value
    assert states[1] == BatchRowState.SUBMITTED.value


# --- capacity ----------------------------------------------------------------


@asyncio_test
async def test_a_full_store_refuses_rather_than_evicting_a_live_batch() -> None:
    store = InMemoryBatchStore(max_batches=1)
    batch, _, _ = build_batch(store=store)
    first = await run(batch, csv_for("a@example.test"))

    with pytest.raises(Exception) as raised:
        await run(batch, csv_for("b@example.test"))

    assert "capacity" in str(raised.value)
    assert first.batch_id.value in store.batches, "a live batch was evicted to admit another"


def test_submitting_takes_bytes_and_a_principal_and_nothing_else() -> None:
    import inspect

    assert set(inspect.signature(BatchService.submit).parameters) == {
        "self",
        "content",
        "principal",
    }


def test_the_correlation_key_is_hidden_from_the_repr() -> None:
    import dataclasses

    hidden = {field.name for field in dataclasses.fields(BatchService) if not field.repr}

    assert {"correlation_key", "_cancelled"} <= hidden
    assert CORRELATION_KEY not in repr(build_batch()[0]).encode()
