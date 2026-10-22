"""Local-only check, batch, expansion and configuration commands."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import string
import sys
from collections.abc import Sequence
from contextlib import aclosing
from pathlib import Path

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.expansion import MAX_POOL_BYTES, plan_expansion
from emailcheck.application.local_batch import InputRow, passive_rows
from emailcheck.application.readiness import report_versions
from emailcheck.apps.local_io import ResultWriter, csv_cell, output_file, read_rows
from emailcheck.composition import build_verification_stack
from emailcheck.settings import Settings, load_settings


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="emailcheck")
    commands = root.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check addresses without SMTP")
    check.add_argument("addresses", nargs="+")
    batch = commands.add_parser("batch", help="check a UTF-8 CSV/TXT file without SMTP")
    batch.add_argument("input", type=Path)
    batch.add_argument("--format", choices=("csv", "txt"))
    batch.add_argument("--start-row", type=int, default=1)
    for command in (check, batch):
        command.add_argument("--mode", choices=("passive",), default="passive")
        command.add_argument("--output-format", choices=("json", "csv"))
        command.add_argument("--json", action="store_true")
        command.add_argument("--include-address", action="store_true")
        command.add_argument("--duplicates", choices=("keep", "skip"), default="keep")
    expand = commands.add_parser("expand", help="generate candidates offline")
    expand.add_argument("pattern")
    choices = expand.add_mutually_exclusive_group()
    choices.add_argument("--chars")
    choices.add_argument("--charset", choices=("lower", "upper", "digits", "alnum"))
    choices.add_argument("--candidate", action="append")
    choices.add_argument("--candidates-file", type=Path)
    positions = expand.add_mutually_exclusive_group()
    positions.add_argument("--slot", action="append", help="JSON string array, repeated per star")
    positions.add_argument("--slot-file", action="append", type=Path)
    expand.add_argument("--max-candidates", type=int)
    expand.add_argument("--dry-run", action="store_true")
    expand.add_argument("--output-format", choices=("csv", "txt"), default="csv")
    config = commands.add_parser("config", help="show validated effective budgets")
    config.add_argument("action", choices=("show",))
    for command in (check, batch, expand, config):
        command.add_argument("--config", type=Path)
    for command in (check, batch, expand):
        command.add_argument("--output", type=Path)
        command.add_argument("--progress", action="store_true")
    return root


def run(argv: Sequence[str]) -> int:
    args = parser().parse_args(argv)
    try:
        settings = load_settings(args.config)
        if args.command == "config":
            print(json.dumps(settings.as_json_object(), indent=2, sort_keys=True))
            return 0
        if args.command == "expand":
            return expand(args, settings)
        return asyncio.run(check(args, settings))
    except KeyboardInterrupt:
        print("emailcheck: cancelled; destination file unchanged", file=sys.stderr)
        return 130
    except (OSError, ValueError):
        print(
            "emailcheck: input/configuration/output refused; check syntax and limits",
            file=sys.stderr,
        )
        return 2


def _pool_file(path: Path) -> list[str]:
    with path.open("rb") as handle:
        raw = handle.read(MAX_POOL_BYTES + 1)
    if len(raw) > MAX_POOL_BYTES:
        raise ValueError("candidate file too large")
    return raw.decode("utf-8-sig").splitlines()


def expand(args: argparse.Namespace, settings: Settings) -> int:
    candidates = list(string.ascii_lowercase)
    if args.chars is not None:
        candidates = list(args.chars)
    elif args.charset:
        candidates = list(
            {
                "lower": string.ascii_lowercase,
                "upper": string.ascii_uppercase,
                "digits": string.digits,
                "alnum": string.ascii_letters + string.digits,
            }[args.charset]
        )
    elif args.candidate is not None:
        candidates = args.candidate
    elif args.candidates_file:
        candidates = _pool_file(args.candidates_file)
    positions = None
    if args.slot or args.slot_file:
        if any((args.chars is not None, args.charset, args.candidate, args.candidates_file)):
            raise ValueError("global and per-slot choices are exclusive")
        positions = (
            [_pool_file(path) for path in args.slot_file]
            if args.slot_file
            else [json.loads(value) for value in args.slot]
        )
        if any(
            not isinstance(pool, list) or any(not isinstance(v, str) for v in pool)
            for pool in positions
        ):
            raise ValueError("slots must be arrays of strings")
    maximum = args.max_candidates if args.max_candidates is not None else settings.batch.max_rows
    if maximum > settings.batch.max_rows:
        raise ValueError("candidate limit exceeds batch row limit")
    plan = plan_expansion(
        args.pattern, candidates=candidates, positions=positions, max_candidates=maximum
    )
    if args.dry_run:
        print(json.dumps({"candidate_count_upper_bound": plan.count, "max_candidates": maximum}))
        return 0
    count = 0
    with output_file(args.output) as handle:
        writer = csv.writer(handle, lineterminator="\n")
        if args.output_format == "csv":
            writer.writerow(["email"])
        for count, address in enumerate(plan, 1):
            if args.output_format == "csv":
                if csv_cell(address) != address:
                    raise ValueError("formula-like address requires TXT output")
                writer.writerow([address])
            else:
                handle.write(address + "\n")
            if args.progress and count % 100 == 0:
                print(f"generated={count} upper_bound={plan.count}", file=sys.stderr)
    if args.progress:
        print(f"generated={count} complete", file=sys.stderr)
    return 0


async def check(args: argparse.Namespace, settings: Settings) -> int:
    from emailcheck import __version__
    from emailcheck.apps.cli import _LOCAL_KEY, _local_deployment

    if args.command == "batch":
        if args.start_row < 1:
            raise ValueError("starting row must be positive")
        if args.output and args.input.resolve() == args.output.resolve():
            raise ValueError("input and output must differ")
        format = args.format or ("txt" if args.input.suffix.lower() == ".txt" else "csv")
        for _ in read_rows(args.input, format, settings.batch):
            pass
        rows = read_rows(args.input, format, settings.batch)
    else:
        if len(args.addresses) > settings.batch.max_rows:
            raise ValueError("too many addresses")
        rows = (InputRow(i, value) for i, value in enumerate(args.addresses, 1))
    deployment = settings.apply(_local_deployment())
    versions = report_versions(
        package_version=__version__,
        aggregation_ruleset=aggregate_evidence(()).ruleset,
        datasets=deployment.passive_datasets,
    ).dataset_versions
    stack = build_verification_stack(deployment)
    principal = stack.authenticator.authenticate(_LOCAL_KEY)
    assert principal is not None
    format = args.output_format or (
        "csv" if args.output and args.output.suffix.lower() == ".csv" else "json"
    )
    if args.json:
        format = "json"
    total = 0
    refused = 0

    def progress(count: int) -> None:
        if args.progress and count % 100 == 0:
            print(f"completed={count}", file=sys.stderr)

    try:
        with output_file(args.output) as handle:
            writer = ResultWriter(handle, format, args.include_address)
            stream = passive_rows(
                rows,
                service=stack.verification,
                principal=principal,
                limits=settings.batch,
                duplicates=args.duplicates,
                start_row=getattr(args, "start_row", 1),
                include_address=args.include_address,
                progress=progress,
            )
            async with aclosing(stream):
                async for result in stream:
                    result["dataset_versions"] = dict(versions)
                    writer.write(result)
                    total += 1
                    refused += result["state"] in {"failed", "refused", "rejected"}
            writer.finish()
    finally:
        rows.close()
        await stack.aclose()
    if args.progress:
        print(f"completed={total} operational_errors={refused} complete", file=sys.stderr)
    return 3 if refused else 0
