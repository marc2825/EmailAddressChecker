"""The human views: the evidence ladder for one address, one line per row for many.

Both read a `PublicResult` or a published row and decide nothing. A status is
printed as the aggregator produced it; the marks beside the evidence steps come
from `apps/vocabulary.py` and are always printed next to words.

**Addresses.** A view shows the redaction this project already uses in logs
(`a***@example.com`), and only for an address that parsed. The complete address
appears only when the user passes `--include-address`, and then with every
non-printable character escaped, so a crafted input cannot move the cursor,
change colours, or reorder text in the terminal.

**Colour** is used only on a terminal, never with `NO_COLOR` set or with
`TERM=dumb`, and it repeats what the words already say.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, TextIO

from emailcheck.apps.messages import Lang, number, printable, text
from emailcheck.apps.vocabulary import CONFIDENCE, REASONS, RISK_FLAGS, ROW_ERRORS, STATUSES
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.ports.public_contract import PublicResult

_ANSI: Final[dict[str, str]] = {
    "invalid": "1;31",
    "temporary_unknown": "1;33",
    "unknown": "1",
    "likely_deliverable": "1;32",
    "ok": "32",
    "fail": "31",
    "warn": "33",
    "risk": "35",
    "dim": "2",
}

_UNICODE_MARKS: Final[dict[str, str]] = {"ok": "✓", "fail": "✗", "warn": "!", "none": chr(0x2013)}
_ASCII_MARKS: Final[dict[str, str]] = {"ok": "+", "fail": "x", "warn": "!", "none": "-"}


@dataclass(frozen=True, slots=True)
class Style:
    """How a stream can show emphasis: colour or not, Unicode marks or ASCII."""

    color: bool = False
    unicode: bool = True

    @classmethod
    def for_stream(cls, stream: TextIO, environ: Mapping[str, str]) -> Style:
        try:
            interactive = stream.isatty()
        except (AttributeError, ValueError):
            interactive = False
        color = interactive and not environ.get("NO_COLOR") and environ.get("TERM", "") != "dumb"
        encoding = getattr(stream, "encoding", None) or "ascii"
        try:
            "".join(_UNICODE_MARKS.values()).encode(encoding)
            unicode = True
        except (LookupError, UnicodeEncodeError):
            unicode = False
        return cls(color=color, unicode=unicode)

    def paint(self, value: str, tone: str) -> str:
        code = _ANSI.get(tone)
        if not self.color or code is None:
            return value
        return f"\x1b[{code}m{value}\x1b[0m"

    def mark(self, kind: str) -> str:
        marks = _UNICODE_MARKS if self.unicode else _ASCII_MARKS
        return self.paint(marks[kind], kind if kind != "none" else "dim")


def display_target(raw: str, *, include_address: bool) -> str | None:
    """What a view may show for one input, or None for nothing."""
    if include_address:
        return printable(raw)
    parsed = parse_address(RawAddressInput(raw))
    if isinstance(parsed, AddressAccepted):
        return parsed.address.redacted
    return None


def width(value: str) -> int:
    """Terminal cells: two for wide East Asian characters, none for combining marks."""
    cells = 0
    for char in value:
        if unicodedata.combining(char):
            continue
        cells += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return cells


def pad(value: str, cells: int) -> str:
    return value + " " * max(0, cells - width(value))


def footer(lang: Lang, *, no_message_data_sent: bool) -> list[str]:
    """The caveat every view ends with. The second line states only what is true."""
    second = "footer.no_message" if no_message_data_sent else "footer.warning"
    return [text("footer.estimate", lang), text(second, lang)]


# --- one address ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Step:
    mark: str
    layer: str
    summary: str
    code: str = ""


def _reason_step(layer: str, code: str, lang: Lang) -> _Step:
    term = REASONS.get(code)
    if term is None:
        # A `--remote` server chooses these strings and the public contract
        # does not validate them, so they are escaped and never explained.
        return _Step("warn", layer, text("step.unrecognised", lang), printable(code))
    return _Step(term.mark, layer, term.label(lang), code)


def _steps(result: PublicResult, lang: Lang, *, local: bool) -> list[_Step]:
    checks = result.checks
    syntax_label = text("layer.syntax", lang)
    dns_label = text("layer.dns", lang)
    mailbox_label = text("layer.mailbox", lang)
    steps: list[_Step] = []

    if "syntax" in checks:
        steps.append(_reason_step(syntax_label, checks["syntax"].result, lang))
    elif checks:
        steps.append(_Step("ok", syntax_label, text("step.syntax_ok", lang)))
    else:
        steps.append(_Step("none", syntax_label, text("step.no_result", lang)))
    stopped = steps[-1].mark in {"fail", "warn"} and "syntax" in checks

    if "dns" in checks:
        steps.append(_reason_step(dns_label, checks["dns"].result, lang))
    else:
        key = "step.not_reached" if stopped else "step.no_result"
        steps.append(_Step("none", dns_label, text(key, lang)))
    stopped = stopped or steps[-1].mark == "fail"

    if "smtp" in checks:
        steps.append(_reason_step(mailbox_label, checks["smtp"].result, lang))
    elif stopped:
        steps.append(_Step("none", mailbox_label, text("step.not_reached", lang)))
    else:
        key = "step.no_smtp" if local else "step.no_result"
        steps.append(_Step("none", mailbox_label, text(key, lang)))
    return steps


def ladder(
    result: PublicResult,
    *,
    lang: Lang,
    style: Style,
    target: str | None = None,
    local: bool = True,
    verbose: bool = False,
) -> str:
    """The evidence ladder: what was found at each step, and where it stopped."""
    lines: list[str] = []
    if target:
        lines.append(target)
    status = STATUSES[result.status]
    confidence = text("confidence", lang, level=CONFIDENCE[result.confidence].label(lang))
    lines.append(
        text(
            "headline",
            lang,
            code=style.paint(result.status, result.status),
            label=status.label(lang),
            confidence=confidence,
        )
    )
    primary = REASONS.get(result.primary_reason or "")
    lines.append(primary.meaning(lang) if primary else status.meaning(lang))
    lines.append("")

    steps = _steps(result, lang, local=local)
    layer_cells = max(width(step.layer) for step in steps) + 2
    coded = [width(step.summary) for step in steps if step.code]
    summary_cells = max(coded, default=0) + 2
    for step in steps:
        row = f"  {style.mark(step.mark)} {pad(step.layer, layer_cells)}"
        if step.code:
            row += pad(step.summary, summary_cells) + style.paint(step.code, "dim")
        else:
            row += step.summary
        lines.append(row.rstrip())

    if result.risk_flags:
        lines.append("")
        for flag in result.risk_flags:
            term = RISK_FLAGS.get(flag)
            lines.append(
                "  "
                + text(
                    "risk.line",
                    lang,
                    note=style.paint(text("risk.note", lang), "risk"),
                    code=flag,
                    label=term.label(lang) if term else flag,
                    separate=text("risk.separate", lang),
                )
            )

    if verbose:
        lines.append("")
        others = [reason for reason in result.reasons if reason != result.primary_reason]
        if others:
            lines.append(f"  {text('more_reasons', lang)}: {', '.join(others)}")
        lines.append(f"  {text('ruleset', lang)}: {printable(result.ruleset)}")

    lines.append("")
    lines.extend(footer(lang, no_message_data_sent=result.no_message_data_sent))
    return "\n".join(lines)


def row_problem(record: Mapping[str, object], lang: Lang) -> str:
    """Why a row has no status, in words."""
    if record.get("state") == "duplicate":
        return text("duplicate_of", lang, row=record.get("duplicate_of"))
    error = str(record.get("error") or "")
    term = ROW_ERRORS.get(error)
    return term.label(lang) if term else error


# --- many rows ------------------------------------------------------------------

_STATUS_CELLS: Final = max(len(code) for code in STATUSES)
#: Wide enough for every reason a local check produces except the rare
#: `unsupported_quoted_local_part`, which overflows by three cells.
_REASON_CELLS: Final = 26


@dataclass(slots=True)
class Tally:
    """Counts for the closing summary, in the order statuses are published."""

    statuses: dict[str, int] = field(default_factory=lambda: dict.fromkeys(STATUSES, 0))
    duplicates: int = 0
    not_checked: int = 0
    total: int = 0
    all_without_message: bool = True

    def add(self, record: Mapping[str, object]) -> None:
        self.total += 1
        state = record.get("state")
        if state == "completed":
            self.statuses[str(record.get("status"))] += 1
            if record.get("no_message_data_sent") is not True:
                self.all_without_message = False
        elif state == "duplicate":
            self.duplicates += 1
        else:
            self.not_checked += 1

    def counts(self, lang: Lang, style: Style) -> str:
        parts = [
            f"{style.paint(code, code)} {number(count)}"
            for code, count in self.statuses.items()
            if count
        ]
        if self.duplicates:
            parts.append(f"{text('summary.duplicate', lang)} {number(self.duplicates)}")
        if self.not_checked:
            parts.append(
                style.paint(f"{text('not_checked', lang)} {number(self.not_checked)}", "warn")
            )
        return " / ".join(parts)


@dataclass(frozen=True, slots=True)
class RowLayout:
    """Column widths fixed before the first row, so rows can stream."""

    last_row: int
    lang: Lang

    @property
    def row_cells(self) -> int:
        return max(width(str(self.last_row)), width(self.heading()[0]))

    @property
    def confidence_cells(self) -> int:
        labels = [term.label(self.lang) for term in CONFIDENCE.values()]
        heading = self.heading()[2]
        return max(max(width(label) for label in labels), width(heading))

    def heading(self) -> list[str]:
        return text("rows.header", self.lang).split("|")

    def header_line(self, style: Style) -> str:
        row, status, confidence, reason, address = self.heading()
        line = (
            f"  {pad(row, self.row_cells)}  {pad(status, _STATUS_CELLS)}  "
            f"{pad(confidence, self.confidence_cells)}  {pad(reason, _REASON_CELLS)}  {address}"
        )
        return style.paint(line.rstrip(), "dim")


def row_line(
    record: Mapping[str, object],
    *,
    layout: RowLayout,
    style: Style,
    target: str | None,
) -> str:
    """One row: number, status, confidence, reason, address, then any flags."""
    lang = layout.lang
    number_cell = str(record.get("row", "")).rjust(layout.row_cells)
    shown = target or "-"
    if record.get("state") == "completed":
        status = str(record.get("status"))
        confidence = CONFIDENCE[str(record.get("confidence"))].label(lang)
        reason = str(record.get("primary_reason") or "-")
        line = (
            f"  {number_cell}  {style.paint(pad(status, _STATUS_CELLS), status)}  "
            f"{pad(confidence, layout.confidence_cells)}  {pad(reason, _REASON_CELLS)}  {shown}"
        )
        flags = record.get("risk_flags")
        if isinstance(flags, list | tuple) and flags:
            line += "  " + style.paint(", ".join(str(flag) for flag in flags), "risk")
        return line
    state = str(record.get("state"))
    detail = row_problem(record, lang)
    code = str(record.get("error") or "")
    line = (
        f"  {number_cell}  {style.paint(pad(state, _STATUS_CELLS), 'warn')}  "
        f"{pad('', layout.confidence_cells)}  {pad(code or '-', _REASON_CELLS)}  {shown}  {detail}"
    )
    return line


def rows_footer(tally: Tally, *, lang: Lang, style: Style) -> list[str]:
    lines = [
        "",
        f"  {text('summary.rows', lang, count=number(tally.total))}: {tally.counts(lang, style)}",
        "  " + style.paint(text("summary.explain", lang), "dim"),
    ]
    if tally.not_checked:
        lines.append("  " + text("summary.exit3", lang))
    lines.append("")
    lines.extend(
        "  " + line for line in footer(lang, no_message_data_sent=tally.all_without_message)
    )
    return lines


def batch_summary(tally: Tally, *, lang: Lang, style: Style, saved_to: str | None) -> list[str]:
    """What a person sees after machine output went to a file or a pipe."""
    count = number(tally.total)
    first = (
        text("summary.saved", lang, count=count, path=printable(saved_to))
        if saved_to
        else text("summary.checked", lang, count=count)
    )
    lines = [first]
    if tally.total:
        lines.append(tally.counts(lang, style))
    if tally.not_checked:
        lines.append(text("summary.exit3", lang))
    return lines
