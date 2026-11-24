"""Bounded local input and atomic private output, independent of verification."""

from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from emailcheck.application.local_batch import InputRow
from emailcheck.domain.batch import (
    BatchError,
    BatchLimits,
    CsvRecordKind,
    address_column_index,
    classify_csv_record,
)


class InputRefused(ValueError):
    """The whole input is refused. `key` names the message the CLI shows."""

    def __init__(self, message: str, key: str, **values: object) -> None:
        super().__init__(message)
        self.key = key
        self.values = values


def read_rows(path: Path, format: str, limits: BatchLimits) -> Generator[InputRow]:
    """CSV logical row numbers exclude the header; TXT includes blank lines."""

    def lines() -> Generator[str]:
        total = 0
        with path.open("rb") as handle:
            while raw := handle.readline(limits.max_input_bytes + 1):
                total += len(raw)
                if total > limits.max_input_bytes:
                    raise InputRefused(
                        "input exceeds the file size limit",
                        "error.size_limit",
                        limit=f"{limits.max_input_bytes:,}",
                    )
                line = raw.decode("utf-8-sig" if total == len(raw) else "utf-8")
                if "\x00" in line:
                    # The service batch parser refuses a NUL too.
                    raise InputRefused("input carries a NUL", "error.nul")
                yield line

    source = lines()
    try:
        if format == "txt":
            for number, line in enumerate(source, 1):
                if number > limits.max_rows:
                    raise _row_limit(limits)
                yield InputRow(number, line.rstrip("\r\n"))
        else:
            reader = csv.reader(source, strict=True)
            header = next(reader, [])
            # Shared with the service batch parser, so both accept and refuse
            # the same headers.
            try:
                index = address_column_index(header)
            except BatchError as refusal:
                names = [name.strip().lower() for name in header]
                key = (
                    "error.header_repeat" if len(set(names)) != len(names) else "error.header_email"
                )
                raise InputRefused(str(refusal), key) from None
            for number, row in enumerate(reader, 1):
                if number > limits.max_rows:
                    raise _row_limit(limits)
                kind = classify_csv_record(row, len(header))
                if kind is CsvRecordKind.BLANK:
                    continue
                if kind is CsvRecordKind.MALFORMED:
                    yield InputRow(number, "", "malformed_row")
                else:
                    yield InputRow(number, row[index])
    except (UnicodeError, csv.Error):
        raise InputRefused("input must be well-formed UTF-8 text/CSV", "error.encoding") from None
    finally:
        source.close()


def _row_limit(limits: BatchLimits) -> InputRefused:
    return InputRefused(
        "input exceeds the row limit", "error.row_limit", limit=f"{limits.max_rows:,}"
    )


def csv_cell(value: object) -> str:
    text = str(value)
    # Leading whitespace can hide a spreadsheet formula. Keep it inert even
    # when an address was explicitly requested in the local result artifact.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


@contextmanager
def output_file(path: Path | None) -> Iterator[TextIO]:
    if path is None:
        yield sys.stdout
        return
    fd, temporary = tempfile.mkstemp(prefix=".emailcheck-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


RESULT_COLUMNS = (
    "row",
    "state",
    "status",
    "confidence",
    "primary_reason",
    "reasons",
    "risk_flags",
    "checks",
    "smtp_executed",
    "dns_cache_used",
    "verdict_cache_used",
    "ruleset",
    "dataset_versions",
    "error",
    "duplicate_of",
)


class ResultWriter:
    def __init__(self, handle: TextIO, format: str, include_address: bool) -> None:
        self.handle = handle
        self.format = format
        self.first = True
        self.columns = (*RESULT_COLUMNS, "email") if include_address else RESULT_COLUMNS
        self.csv = csv.writer(handle, lineterminator="\n")
        if format == "csv":
            self.csv.writerow(self.columns)
        else:
            handle.write("[\n")

    def write(self, row: dict[str, object]) -> None:
        if self.format == "csv":
            self.csv.writerow(
                csv_cell(_csv_value(value))
                for value in (row.get(name, "") for name in self.columns)
            )
        else:
            self.handle.write(("" if self.first else ",\n") + json.dumps(row, ensure_ascii=False))
        self.first = False

    def finish(self) -> None:
        if self.format == "json":
            self.handle.write("\n]\n")


def _csv_value(value: object) -> object:
    """JSON spellings for the values JSON has: `true`, `false`, and nested JSON.

    Python's `str(True)` is `True`, which no JSON or spreadsheet reader expects
    and which differed from the JSON output of the same result.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict | list | tuple):
        return json.dumps(value, ensure_ascii=False)
    return value
