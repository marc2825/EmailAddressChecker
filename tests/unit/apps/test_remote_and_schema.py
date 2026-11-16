"""`--remote`, the endpoint policy behind it, and the published schema.

`docs/requirements.md` section 12 requires a remote active mode;
`docs/architecture.md` requires that the CLI handle pending, completed, and
failed, and that the schema state the limitations explicitly.

**No test here opens a socket.** The transport is a port and every test uses a
fake, which is also what makes the polling policy assertable: the loop's bounds
are measured rather than waited out.
"""

from __future__ import annotations

import ast
import asyncio
import io
import json
import pathlib
import urllib.request

import pytest
from tests.phase6_fixtures import (
    AdvancingSleeper,
    FakeMonotonicClock,
    FakeRemoteClient,
    empty_result,
    job_view,
)

from emailcheck.adapters.http import urllib_client
from emailcheck.apps import api as api_module
from emailcheck.apps.cli import (
    EXIT_INCOMPLETE,
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_REFUSED,
    MAX_REMOTE_KEY_BYTES,
    RemoteKeyError,
    build_parser,
    main,
    poll_until_finished,
    read_key_file,
    run_remote_check,
)
from emailcheck.apps.schema import NO_GUARANTEE, api_schema
from emailcheck.domain.job import JobFailure, JobState
from emailcheck.ports.remote_check import RemoteCheckError
from emailcheck.security.remote_url import (
    MAX_URL_LENGTH,
    RemoteUrlError,
    join_api_path,
    normalize_base_url,
)

ADDRESS = "user@example.test"
SECRET_KEY = "operator-secret-api-key-value-0001"

#: Every polling test carries its own bound, so a loop that should have
#: stopped fails rather than hanging the suite.
OUTER_BOUND = 5.0


def sleeper() -> AdvancingSleeper:
    return AdvancingSleeper(clock=FakeMonotonicClock())


# --- which endpoints --remote will talk to ----------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://validator.example",
        "http://127.0.0.1:8080",
        "https://validator.example/api/",
        "https://validator.example:8443/prefix",
    ],
)
def test_an_ordinary_endpoint_is_accepted(url: str) -> None:
    assert normalize_base_url(url).startswith(("http://", "https://"))


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "data:text/plain,hello",
        "ftp://validator.example",
        "gopher://validator.example",
        "javascript:alert(1)",
        "//validator.example",
        "validator.example",
        "",
        "https://",
        "https://user:secret@validator.example",
        "https://validator.example?query=1",
        "https://validator.example#fragment",
        "https://validator.example/\rHost: evil",
        "https://validator.example/\npath",
        "https://validator.example/\0",
        "https://validator.example/ space",
    ],
)
def test_a_dangerous_or_malformed_endpoint_is_refused(url: str) -> None:
    """An allowlist of two schemes rather than a deny list of the bad ones, so
    a scheme nobody thought of is refused too. Credentials are refused rather
    than stripped: silently discarding them would hide that a secret typed on a
    command line was never sent."""
    with pytest.raises(RemoteUrlError):
        normalize_base_url(url)


def test_an_over_long_endpoint_is_refused() -> None:
    with pytest.raises(RemoteUrlError):
        normalize_base_url("https://validator.example/" + "a" * MAX_URL_LENGTH)


def test_the_api_path_is_appended_and_the_host_cannot_be_replaced() -> None:
    """`urljoin` with an absolute-looking input replaces the host, which is the
    one thing this function exists to keep fixed."""
    assert (
        join_api_path("https://validator.example/", "/v1/checks")
        == "https://validator.example/v1/checks"
    )
    for path in ("v1/checks", "//evil.example/v1/checks", "/v1/../../etc"):
        with pytest.raises(RemoteUrlError):
            join_api_path("https://validator.example", path)


def test_the_client_uses_the_same_paths_the_api_publishes() -> None:
    """The adapter copies them rather than importing from `apps/`, because
    `docs/architecture.md` section 1 puts `apps/` above `adapters/`. This is
    what stops the copy drifting."""
    assert urllib_client.ACTIVE_PATH == api_module.ACTIVE_PATH
    assert urllib_client.JOB_PATH_PREFIX == api_module.JOB_PATH_PREFIX


# --- the CLI's remote flags -------------------------------------------------


def test_remote_needs_a_key_file(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([ADDRESS, "--remote", "https://validator.example"])
    assert code == EXIT_INVALID_INPUT
    assert "remote-key-file" in capsys.readouterr().err


def test_a_dangerous_remote_url_never_reaches_a_client(
    capsys: pytest.CaptureFixture[str], tmp_path: object
) -> None:
    code = main([ADDRESS, "--remote", "file:///etc/passwd", "--remote-key-file", "/nonexistent"])
    assert code == EXIT_INVALID_INPUT
    assert "http or https" in capsys.readouterr().err


def test_an_unreadable_key_file_is_refused_without_naming_its_contents(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(
        [ADDRESS, "--remote", "https://validator.example", "--remote-key-file", "/no/such/file"]
    )
    assert code == EXIT_INVALID_INPUT
    assert "could not be read" in capsys.readouterr().err


def test_wait_without_remote_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([ADDRESS, "--wait"]) == EXIT_INVALID_INPUT


def test_the_key_never_appears_on_the_command_line() -> None:
    """`--remote-key` would put a secret in `ps` output and the shell history."""
    options = {action.dest for action in build_parser()._actions}
    assert "remote_key" not in options
    assert "remote_key_file" in options


# --- the job lifecycle, through the CLI -------------------------------------


@pytest.mark.asyncio
async def test_submitting_without_wait_prints_the_pending_job(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Nothing is printed as a result before a verdict exists."""
    client = FakeRemoteClient(submit_result=job_view(JobState.PENDING))
    code = await run_remote_check(
        client, sleeper(), address=ADDRESS, wait=False, as_json=False, verbose=False
    )

    out = capsys.readouterr().out
    assert code == EXIT_INCOMPLETE
    assert JobState.PENDING.value in out
    assert "No result yet" in out
    assert client.fetches == []
    for status in ("likely_deliverable", "invalid", "temporary_unknown"):
        assert status not in out


@pytest.mark.asyncio
async def test_polling_stops_when_the_job_completes(capsys: pytest.CaptureFixture[str]) -> None:
    client = FakeRemoteClient(
        submit_result=job_view(JobState.PENDING),
        sequence=[
            job_view(JobState.PENDING),
            job_view(JobState.RUNNING),
            job_view(JobState.COMPLETED, result=empty_result()),
        ],
    )
    code = await run_remote_check(
        client, sleeper(), address=ADDRESS, wait=True, as_json=False, verbose=False
    )

    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert JobState.COMPLETED.value in out
    assert "does not prove that a mailbox exists" in out
    assert len(client.fetches) == 3


@pytest.mark.asyncio
async def test_a_failed_job_is_reported_as_a_failure_and_not_as_a_verdict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = FakeRemoteClient(
        submit_result=job_view(JobState.PENDING),
        sequence=[job_view(JobState.FAILED, failure=JobFailure.SERVICE_ERROR)],
    )
    code = await run_remote_check(
        client, sleeper(), address=ADDRESS, wait=True, as_json=False, verbose=False
    )

    out = capsys.readouterr().out
    assert code == EXIT_INCOMPLETE
    assert JobFailure.SERVICE_ERROR.value in out
    assert "No result yet" in out


@pytest.mark.asyncio
async def test_a_cancelled_job_is_reported_as_cancelled(
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = FakeRemoteClient(
        submit_result=job_view(JobState.PENDING), sequence=[job_view(JobState.CANCELLED)]
    )
    code = await run_remote_check(
        client, sleeper(), address=ADDRESS, wait=True, as_json=False, verbose=False
    )
    assert code == EXIT_INCOMPLETE
    assert JobState.CANCELLED.value in capsys.readouterr().out


@pytest.mark.asyncio
async def test_the_poll_loop_is_bounded_rather_than_endless() -> None:
    """A remote that never finishes ends the loop, not the terminal session.

    The test carries its own outer bound, on the discipline gate 4C established:
    an unbounded loop must *fail* here rather than hang, because a hanging test
    stops a suite instead of reporting a defect. A mutation removing the attempt
    cap proved that the hard way.
    """
    client = FakeRemoteClient(
        submit_result=job_view(JobState.PENDING), sequence=[job_view(JobState.RUNNING)]
    )
    paced = sleeper()

    async with asyncio.timeout(OUTER_BOUND):
        job = await poll_until_finished(
            client, paced, job_id="x" * 24, wait_seconds=20.0, interval_seconds=2.0
        )

    assert job.state == JobState.RUNNING.value
    assert len(paced.slept) == 10
    assert paced.slept == [2.0] * 10


@pytest.mark.asyncio
async def test_a_remote_failure_is_a_category_rather_than_a_library_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = FakeRemoteClient(raises=RemoteCheckError("the remote validator answered 502"))
    code = await run_remote_check(
        client, sleeper(), address=ADDRESS, wait=True, as_json=False, verbose=False
    )
    captured = capsys.readouterr()
    assert code == EXIT_REFUSED
    assert "502" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.asyncio
async def test_a_remote_answer_in_unknown_vocabulary_is_refused_rather_than_printed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A remote server is not a trusted source of vocabulary.

    `application/public_job.py` and `application/public_result.py` both refuse a
    status this build does not publish, so a compromised or simply newer
    validator cannot put a word into a user's terminal that this project would
    never have said.
    """
    client = FakeRemoteClient(raises=ValueError("unpublished status"))
    code = await run_remote_check(
        client, sleeper(), address=ADDRESS, wait=False, as_json=False, verbose=False
    )
    assert code == EXIT_REFUSED
    assert "unknown vocabulary" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_the_json_form_is_the_published_job_object(
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = FakeRemoteClient(
        submit_result=job_view(JobState.COMPLETED, result=empty_result()),
    )
    await run_remote_check(
        client, sleeper(), address=ADDRESS, wait=False, as_json=True, verbose=False
    )
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {"id", "state", "created_at", "updated_at", "result", "failure"}
    assert "@" not in json.dumps(payload)


# --- the published schema ---------------------------------------------------


def test_the_schema_states_that_nothing_is_guaranteed() -> None:
    """`docs/architecture.md`'s acceptance criterion, as a test.

    "API examples state explicitly that no existence or delivery guarantee is
    made." A CLI caveat is not that: a caller reading only the schema must be
    told too.
    """
    document = json.dumps(api_schema())
    assert NO_GUARANTEE in document
    assert "does not prove mailbox existence" in document
    assert "does not guarantee" in document


def test_the_schema_documents_every_published_value_by_iterating_the_enum() -> None:
    limitations = api_schema()["limitations"]
    assert isinstance(limitations, dict)
    for name in (
        "statuses",
        "confidence_levels",
        "risk_flags",
        "reason_codes",
        "job_states",
        "job_failures",
        "check_layers",
    ):
        assert limitations[name], name
    assert limitations["job_states"] == [member.value for member in JobState]


def test_the_schema_carries_an_example_for_every_job_state() -> None:
    """`docs/architecture.md` requires the CLI to handle pending, completed,
    and failed; a schema that documented only the happy one would leave a
    client guessing at the others."""
    endpoints = api_schema()["endpoints"]
    assert isinstance(endpoints, list)
    reads = next(
        endpoint
        for endpoint in endpoints
        if isinstance(endpoint, dict) and endpoint["method"] == "GET" and "{id}" in endpoint["path"]
    )
    examples = reads["example_responses"]
    assert isinstance(examples, dict)
    assert set(examples) == {member.value for member in JobState}


def test_the_schema_covers_every_published_route() -> None:
    endpoints = api_schema()["endpoints"]
    assert isinstance(endpoints, list)
    routed = {
        (endpoint["method"], endpoint["path"])
        for endpoint in endpoints
        if isinstance(endpoint, dict)
    }
    assert ("POST", api_module.PASSIVE_PATH) in routed
    assert ("POST", api_module.ACTIVE_PATH) in routed
    assert ("GET", f"{api_module.JOB_PATH_PREFIX}{{id}}") in routed
    assert ("DELETE", f"{api_module.JOB_PATH_PREFIX}{{id}}") in routed
    assert ("GET", api_module.HEALTH_PATH) in routed


def test_the_schema_examples_are_produced_by_the_real_projection() -> None:
    """Generated rather than transcribed: a hand-written second copy of the
    response contract is a copy that drifts."""
    document = api_schema()
    endpoints = document["endpoints"]
    assert isinstance(endpoints, list)
    passive = next(
        endpoint
        for endpoint in endpoints
        if isinstance(endpoint, dict) and endpoint["path"] == api_module.PASSIVE_PATH
    )
    body = passive["example_response"]["body"]
    assert set(body) == set(empty_result().as_json_object())


def test_the_schema_is_json_safe_and_carries_no_number_in_a_result() -> None:
    document = api_schema()
    rendered = json.dumps(document)
    assert (
        "confidence_score" not in json.loads(rendered)["endpoints"][0]["example_response"]["body"]
    )
    for forbidden in ("Traceback", "sqlite", "correlation_key", "api_key"):
        assert forbidden not in rendered


def test_the_schema_is_stable_between_calls() -> None:
    """A document that changed on every call is one nobody could diff."""
    assert json.dumps(api_schema(), sort_keys=True) == json.dumps(api_schema(), sort_keys=True)


# --- the redirect policy, which is a credential control ---------------------
#
# The final independent review found that `urllib`'s default opener copies every
# header except `content-length` and `content-type` onto a redirected request,
# so `Authorization: Bearer <key>` was forwarded to whatever host a `302` named
# -- cross-origin, and over plaintext `http` if the redirect said so.
# `security/remote_url.py` validates only the *first* URL, so after one hop
# nothing was checking anything.
#
# These drive the handler and the opener directly. No socket is opened, and no
# redirect is followed anywhere in this file.


REDIRECT_TARGETS = [
    ("cross-origin https", "https://evil.example/v1/checks"),
    ("tls downgrade, same host", "http://validator.example/v1/checks"),
    ("cross-origin downgrade", "http://evil.example/collect"),
    ("another scheme entirely", "ftp://evil.example/v1/checks"),
    ("same origin", "https://validator.example/v2/checks"),
]

REDIRECT_CODES = [301, 302, 303, 307, 308]


def _authenticated_request() -> urllib.request.Request:
    """Exactly the request the adapter builds, key and all."""
    return urllib.request.Request(  # noqa: S310 - built, inspected, never opened
        join_api_path("https://validator.example", urllib_client.ACTIVE_PATH),
        data=b'{"email":"user@example.test"}',
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {SECRET_KEY}",
        },
    )


@pytest.mark.parametrize(
    ("label", "target"), REDIRECT_TARGETS, ids=[row[0] for row in REDIRECT_TARGETS]
)
@pytest.mark.parametrize("code", REDIRECT_CODES)
def test_remote_client_never_forwards_authorization_to_a_redirect_target(
    label: str, target: str, code: int
) -> None:
    """The security regression, named so the reason survives the code.

    `redirect_request` is the method that *builds* the follow-up request and
    copies the headers onto it. Raising there means no redirected request object
    exists at all, which is a stronger statement than stripping a header from
    one that was about to be sent. If the default `HTTPRedirectHandler`
    behaviour is ever restored, this fails.
    """
    handler = urllib_client._RefuseRedirects()

    with pytest.raises(RemoteCheckError) as refusal:
        handler.redirect_request(
            _authenticated_request(), io.BytesIO(b""), code, "Found", {}, target
        )

    message = str(refusal.value)
    assert str(code) in message
    # The remote chose the target; it is not repeated back to the operator.
    assert "evil.example" not in message
    assert SECRET_KEY not in message


def test_the_default_redirect_handler_would_have_carried_the_key() -> None:
    """Why the handler above exists, asserted rather than asserted-about.

    This is the stdlib's behaviour, pinned so that "we refuse redirects" is
    visibly a decision about a real hazard rather than caution about a
    hypothetical one. It builds a `Request` and inspects it; nothing is sent.
    """
    followed = urllib.request.HTTPRedirectHandler().redirect_request(
        _authenticated_request(), io.BytesIO(b""), 302, "Found", {}, "https://evil.example/x"
    )
    assert followed is not None
    carried = {name.lower() for name in followed.headers}
    assert "authorization" in carried, "the stdlib no longer carries it; revisit this policy"


def test_the_client_opener_has_no_following_redirect_handler() -> None:
    """The policy is the opener's, so a caller cannot get the default one back."""
    handlers = urllib_client._OPENER.handlers
    assert any(isinstance(h, urllib_client._RefuseRedirects) for h in handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in handlers)


@pytest.mark.inspection
def test_the_client_never_calls_the_module_level_urlopen() -> None:
    """`urllib.request.urlopen` uses the *default* global opener, which follows
    redirects. The adapter must go through its own."""
    source = pathlib.Path(urllib_client.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr != "urlopen", "the adapter calls urlopen rather than its opener"
    assert "_OPENER.open" in ast.unparse(tree)


def test_an_ordinary_answer_is_unaffected_by_the_redirect_policy() -> None:
    """The opener still carries the ordinary handlers a request needs."""
    kinds = {type(handler).__name__ for handler in urllib_client._OPENER.handlers}
    assert "HTTPSHandler" in kinds
    assert "HTTPDefaultErrorHandler" in kinds
    assert "HTTPErrorProcessor" in kinds


# --- the key file ----------------------------------------------------------


def test_a_key_file_is_read_under_a_hard_bound(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"k" * (MAX_REMOTE_KEY_BYTES + 1))
    with pytest.raises(RemoteKeyError, match="larger than"):
        read_key_file(path)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("plain", b"k" * 40),
        ("one LF", b"k" * 40 + b"\n"),
        ("one CRLF", b"k" * 40 + b"\r\n"),
    ],
)
def test_exactly_one_conventional_line_ending_is_removed(
    tmp_path: pathlib.Path, name: str, content: bytes
) -> None:
    """A bare `.strip()` would rewrite a credential whose first or last
    character is a space, and `adapters/auth/api_keys.py` hashes what it is
    given — so a quietly altered key is one that never authenticates."""
    path = tmp_path / "key"
    path.write_bytes(content)
    assert read_key_file(path) == "k" * 40


def test_surrounding_spaces_in_a_key_are_significant(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "key"
    path.write_bytes(b" " + b"k" * 39 + b"\n")
    assert read_key_file(path) == " " + "k" * 39


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("empty", b""),
        ("only a newline", b"\n"),
        ("embedded NUL", b"k" * 39 + b"\x00"),
        ("two line endings", b"k" * 40 + b"\n\n"),
        ("not utf-8", b"\xff\xfe" + b"k" * 38),
    ],
)
def test_an_unusable_key_file_is_refused(tmp_path: pathlib.Path, name: str, content: bytes) -> None:
    path = tmp_path / "key"
    path.write_bytes(content)
    with pytest.raises(RemoteKeyError):
        read_key_file(path)


def test_a_directory_is_refused_without_naming_what_was_wrong(tmp_path: pathlib.Path) -> None:
    with pytest.raises(RemoteKeyError) as refusal:
        read_key_file(tmp_path)
    assert str(tmp_path) not in str(refusal.value)


def test_a_key_file_refusal_never_repeats_the_key(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"s3cret-operator-key" + b"\x00")
    with pytest.raises(RemoteKeyError) as refusal:
        read_key_file(path)
    assert "s3cret" not in str(refusal.value)


class _RecordingFile:
    """A stand-in that records how many bytes the reader asked for.

    Needed because asserting the *refusal* of an over-large file does not pin
    the *bound on the read*: `Path.read_bytes()` also refuses afterwards, having
    already pulled the whole file into memory. A mutation swapping the bounded
    read for an unbounded one escaped the suite until this existed.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.requested: list[int] = []

    def open(self, mode: str) -> object:
        recorder = self

        class _Handle:
            def __enter__(self) -> _Handle:
                return self

            def __exit__(self, *exc: object) -> bool:
                return False

            def read(self, size: int = -1) -> bytes:
                recorder.requested.append(size)
                return recorder.data if size < 0 else recorder.data[:size]

        return _Handle()


def test_the_key_file_read_is_bounded_rather_than_checked_afterwards() -> None:
    """`--remote-key-file /dev/zero` must cost a bounded read, not the file."""
    handle = _RecordingFile(b"k" * 40 + b"\n")
    assert read_key_file(handle) == "k" * 40  # type: ignore[arg-type]
    assert handle.requested == [MAX_REMOTE_KEY_BYTES + 1]
    assert -1 not in handle.requested


def test_an_enormous_file_is_still_only_read_up_to_the_bound() -> None:
    handle = _RecordingFile(b"k" * (MAX_REMOTE_KEY_BYTES * 100))
    with pytest.raises(RemoteKeyError, match="larger than"):
        read_key_file(handle)  # type: ignore[arg-type]
    assert handle.requested == [MAX_REMOTE_KEY_BYTES + 1]
