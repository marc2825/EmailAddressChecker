"""The CSV boundary: what may come in, and what may go out.

ADR 0018 Input and Output. Two pure functions and their values
—
no clock, no store, no network — so the whole surface is testable against text.

**Reading is refusing.** A CSV arrives as bytes somebody uploaded, and every
decision here is about what *not* to accept: not more than the row and byte
limits, not a file that is not UTF-8, not a header without the address column,
not a row whose address does not parse. `docs/requirements.md` section 6's
grammar is the only grammar — `parse_address` is called, and no second parser
exists.

**Writing is escaping.** ADR 0018 Output: *CSV cells protected
against spreadsheet formula injection*. A cell beginning `=`, `+`, `-`, `@`, or
a control character is executed by every major spreadsheet when the file is
opened, and this project's output is a file somebody opens in a spreadsheet
about addresses they were told were invalid. That is the whole attack: the
payload arrives in the input the submitter chose, survives as data, and runs on
the desk of whoever reads the report.

**No raw SMTP reply leaves here**, which the prompt states and which this
enforces by construction: a row carries a status, published reason codes, risk
flags, and counts. There is no field a diagnostic could occupy.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Final

from emailcheck.domain.address import (
    AddressAccepted,
    AddressRejected,
    RawAddressInput,
    parse_address,
    strip_interface_whitespace,
)
from emailcheck.domain.batch import (
    BatchError,
    BatchLimits,
    BatchRowState,
    address_column_index,
)

__all__ = [
    "FORMULA_PREFIXES",
    "BatchInput",
    "BatchInputRow",
    "BatchReportRow",
    "csv_cell",
    "parse_batch_csv",
    "render_batch_csv",
]

#: The characters a spreadsheet treats as the start of a formula.
#:
#: `=` and `+` are the obvious two; `-` starts a negative-number formula; `@`
#: begins a function reference in Excel and is *also* the character every
#: address in this file contains, which is why the guard cannot be "does it look
#: like an address". Tab and carriage return are here because a leading one lets
#: the next character start the cell after the spreadsheet trims it.
FORMULA_PREFIXES: Final = ("=", "+", "-", "@", "\t", "\r")

#: What a rendered cell is prefixed with when it starts with one of those.
#:
#: A single quote is the convention every major spreadsheet reads as "the rest
#: is text". Deliberately **not** stripping the character: the value a submitter
#: put in their file is what a reader needs to see when investigating, and
#: silently deleting part of it is its own kind of wrong answer.
FORMULA_GUARD: Final = "'"

#: The report's columns, in order. Every one is safe by construction: a status,
#: a job state, and reason codes are published vocabulary, and the row number is
#: an integer.
#:
#: **The submitted address is deliberately not a column.** It was one, and it
#: was always empty: the address is retained only while a row may still need
#: submitting, so a report rendered after `forget_inputs` would carry it for
#: some rows and not others, and a column that is sometimes an address and
#: sometimes blank is worse than no column. The 1-based `row` is the handle a
#: submitter matches against the file they still have, and it costs no
#: retention.
REPORT_COLUMNS: Final = (
    "row",
    "row_state",
    "job_state",
    "status",
    "confidence",
    "primary_reason",
    "reason_codes",
    "risk_flags",
)


def csv_cell(value: str) -> str:
    """One cell, safe to open in a spreadsheet.

    Pure and total: it takes text and returns text, so a test can enumerate the
    dangerous prefixes rather than infer the behaviour from a rendered file.
    """
    if not isinstance(value, str):
        raise BatchError("a CSV cell is text")
    if value.startswith(FORMULA_PREFIXES):
        return FORMULA_GUARD + value
    return value


@dataclass(frozen=True, slots=True)
class BatchInputRow:
    """One row of the submitted file, as this project understood it."""

    #: The 1-based position in the input, so a report can be matched against the
    #: file the submitter still has. ADR 0018's output is
    #: row-level.
    number: int
    #: The cell with surrounding ASCII whitespace removed, as the address
    #: parser removes it. Never used as an address unless `address` is set.
    submitted: str
    #: The normalized address, when the row parsed. `None` when it did not.
    address: AddressAccepted | None = None
    #: Phase 1's rejection, when it did not. Carried rather than re-derived.
    rejection: AddressRejected | None = None
    #: The row had a different number of fields from the header, so no cell
    #: was read as an address. Reported as `rejected`, like the local CLI does.
    malformed: bool = False

    @property
    def parsed(self) -> bool:
        return self.address is not None


@dataclass(frozen=True, slots=True)
class BatchInput:
    """A parsed input file, and what was wrong with it.

    Malformed rows do not fail the whole file: ADR 0018's
    scheduler
    asks for *partial failure*, and a batch of ten thousand rows refused for one
    unparseable address would be refused for ever. The row is reported as
    `invalid` and the rest proceeds.
    """

    rows: tuple[BatchInputRow, ...]
    #: Well-formed rows whose address cell was empty after the parser's own
    #: whitespace trimming. Counted so the report balances against the file.
    skipped: int = 0

    def __len__(self) -> int:
        return len(self.rows)


def parse_batch_csv(content: bytes, *, limits: BatchLimits | None = None) -> BatchInput:
    """Read an uploaded file into rows, refusing what may not be read.

    ADR 0018 Input: *documented UTF-8 CSV schema; file size and
    row
    limits; one address column*. A single leading byte order mark is accepted,
    as it is by the local CLI.

    The byte limit is checked **before decoding**, because decoding is the first
    thing that costs memory proportional to a caller's input. The row limit is
    checked as rows are read rather than after, for the same reason.

    Every refusal is a `BatchError` naming a bound, and none of them names the
    content: an error message about somebody's file is a place an address ends
    up in a log.
    """
    bounds = limits if limits is not None else BatchLimits()
    if not isinstance(content, bytes | bytearray):
        raise BatchError("a batch input is bytes")
    if len(content) > bounds.max_input_bytes:
        raise BatchError(f"a batch input may be at most {bounds.max_input_bytes} bytes")

    try:
        # `utf-8-sig` removes one *leading* byte order mark and nothing else.
        # Spreadsheet "CSV UTF-8" exports begin with one, and the local CLI
        # (`apps/local_io.py`) already accepts it; with plain `utf-8` it became
        # part of the first header name and the file was refused for lacking
        # an address column. A U+FEFF anywhere later is left for the address
        # parser to judge, so no cell is rewritten.
        text = bytes(content).decode("utf-8-sig")
    except UnicodeDecodeError:
        # The message is ours, not the decoder's: a codec error carries the
        # offending bytes, and those bytes are the submitter's data.
        raise BatchError("a batch input must be UTF-8") from None
    if "\x00" in text:
        raise BatchError("a batch input carries a NUL")

    # The same reading rules as the local CLI (`apps/local_io.py`): a strict
    # reader, one shared header check, and a row whose field count differs
    # from the header is rejected rather than read by column name.
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader, None)
        if header is None:
            raise BatchError("a batch input needs a header row")
        index = address_column_index(header)

        rows: list[BatchInputRow] = []
        skipped = 0
        for number, record in enumerate(reader, start=1):
            if len(rows) >= bounds.max_rows:
                raise BatchError(f"a batch input may hold at most {bounds.max_rows} rows")
            if len(record) != len(header):
                rows.append(BatchInputRow(number=number, submitted="", malformed=True))
                continue
            cell = strip_interface_whitespace(record[index])
            if not cell:
                skipped += 1
                continue
            rows.append(_row(number, cell))
    except csv.Error:
        raise BatchError("a batch input must be well-formed CSV") from None
    return BatchInput(rows=tuple(rows), skipped=skipped)


def _row(number: int, cell: str) -> BatchInputRow:
    """One row, through the ordinary Phase 1 parser.

    `RawAddressInput` is the only door — it holds the submitted text and its
    redacted display form, and it has no SMTP target, so nothing here can hand
    raw input to an I/O port. `cell` is already trimmed exactly as the parser
    trims, so other Unicode spaces reach the parser and are judged by it.
    """
    parsed = parse_address(RawAddressInput(cell))
    if isinstance(parsed, AddressAccepted):
        return BatchInputRow(number=number, submitted=cell, address=parsed)
    return BatchInputRow(number=number, submitted=cell, rejection=parsed)


@dataclass(frozen=True, slots=True)
class BatchReportRow:
    """One row of the output. Every field is publishable.

    Assembled from `application/public_result.py`'s allowlist rather than from a
    `Verdict` directly, so the report cannot carry a field the API would not —
    there is one allowlist in this project and this is not a second one.
    """

    number: int
    row_state: BatchRowState
    #: The child job's own state, when this row became one and the job is still
    #: known. `domain/job.py`'s published vocabulary, read rather than
    #: re-derived — a row is `submitted` long before its verification finishes,
    #: and a reader who cannot tell the two apart will read a blank status as an
    #: answer.
    job_state: str | None = None
    status: str | None = None
    confidence: str | None = None
    primary_reason: str | None = None
    reason_codes: tuple[str, ...] = ()
    risk_flags: tuple[str, ...] = ()
    #: The job this row became, when it became one. Present so an operator can
    #: follow a row to its verification; never a target digest and never an
    #: address.
    job_id: str | None = field(default=None, repr=False)


def render_batch_csv(rows: tuple[BatchReportRow, ...]) -> str:
    """Render the report, with every cell escaped.

    ADR 0018 Output. The escaping is applied to **every** cell
    rather than to the ones that look risky. No submitter-controlled text
    reaches this renderer any more — every column is published vocabulary or an
    integer — so formula injection is now structurally impossible rather than
    merely guarded. The guard stays: a column added later would otherwise
    arrive unescaped, and `csv_cell` is the thing that has to be true then.
    """
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(REPORT_COLUMNS)
    for row in rows:
        writer.writerow(
            [
                csv_cell(str(row.number)),
                csv_cell(row.row_state.value),
                csv_cell(row.job_state or ""),
                csv_cell(row.status or ""),
                csv_cell(row.confidence or ""),
                csv_cell(row.primary_reason or ""),
                csv_cell(" ".join(row.reason_codes)),
                csv_cell(" ".join(row.risk_flags)),
            ]
        )
    return buffer.getvalue()
