"""Credential-bearing remote requests must validate before opening a connection."""

from __future__ import annotations

import io
import math
import urllib.request
import urllib.response
from email.message import Message
from pathlib import Path

import pytest

from emailcheck.adapters.http import urllib_client
from emailcheck.adapters.http.urllib_client import UrllibRemoteCheckClient
from emailcheck.application.smtp_dialogue import DialogueSettings
from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.ports.remote_check import RemoteCheckError
from emailcheck.security.remote_url import RemoteUrlError, normalize_base_url


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8080", "http://[::1]:8080", "https://validator.example/prefix"]
)
def test_permitted_transport(url: str) -> None:
    assert normalize_base_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://validator.example",
        "http://localhost",
        "http://localhost.localdomain",
        "http://127.1",
        "http://2130706433",
        "http://0x7f000001",
        "http://0177.0.0.1",
        "http://127.0.0.2",
        "http://127.0.0.1.evil.example",
        "http://[::ffff:127.0.0.1]",
        "http://[::1%25lo]",
        "http://127.0.0.1.",
        "https://host:bad",
        "https://host:65536",
        "https://host:0",
        "https://host:",
        "https://[::1",
        "https://host\\evil",
        "https://%31%32%37.0.0.1",
        "https://user:key@host",
        "https://host/\x7f",
        "https://host/\x1f",
        "https://host/\u0085",
        "https://host/%0d%0aevil",
        "http://[::1]evil.example",
        "http://[::1]:80:90",
        "https://host..",
    ],
)
def test_invalid_endpoint_is_refused_without_echo(url: str) -> None:
    with pytest.raises(RemoteUrlError) as error:
        normalize_base_url(url)
    assert url not in str(error.value)


def test_environment_proxies_are_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("http_proxy", "http://attacker.example:8080")
    monkeypatch.setenv("https_proxy", "http://attacker.example:8080")
    # Inspect a freshly constructed opener too: proxies must be explicitly disabled
    # even when the module was first imported under a different environment.
    import importlib

    importlib.reload(urllib_client)
    assert not any(
        isinstance(h, urllib.request.ProxyHandler) for h in urllib_client._OPENER.handlers
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "job_id", ["x?token=secret", "x#fragment", "x/other", "%2fother", "..", "x\r\n", ""]
)
async def test_untrusted_job_id_cannot_change_request(
    job_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid request reached the opener")

    monkeypatch.setattr(urllib_client._OPENER, "open", forbidden)
    with pytest.raises(RemoteCheckError):
        await UrllibRemoteCheckClient("https://validator.example", "secret-key").fetch(job_id)


@pytest.mark.parametrize("timeout", [0, -1, math.inf, math.nan, True])
def test_remote_timeout_is_bounded(timeout: float) -> None:
    with pytest.raises(ValueError):
        UrllibRemoteCheckClient("https://validator.example", "secret-key", timeout)


def test_remote_client_repr_hides_credentials_and_url() -> None:
    client = UrllibRemoteCheckClient("https://validator.example/private-prefix", "secret-key")
    assert "secret-key" not in repr(client)
    assert "private-prefix" not in repr(client)


@pytest.mark.parametrize(
    "url", ["http://external.example", "https://[::1]evil", "https://host:secret"]
)
def test_bad_endpoint_is_rejected_before_opener(
    url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid endpoint reached the opener")

    monkeypatch.setattr(urllib_client._OPENER, "open", forbidden)
    with pytest.raises(RemoteUrlError):
        UrllibRemoteCheckClient(url, "test-secret")


def test_cli_invalid_authority_does_not_echo_secrets_or_target(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from emailcheck.apps.cli import EXIT_INVALID_INPUT, main

    target = "sensitive.target@example.test"
    key = "private-api-key-sentinel"
    code = main([target, "--remote", f"https://{key}@host"])
    output = capsys.readouterr()
    assert code == EXIT_INVALID_INPUT
    assert target not in output.out + output.err
    assert key not in output.out + output.err


def test_cli_nonascii_key_is_refused_without_a_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from emailcheck.apps.cli import EXIT_INVALID_INPUT, main

    key = "secret-sentinel-鍵"
    path = tmp_path / "key"
    path.write_text(key, encoding="utf-8")
    code = main(
        [
            "sensitive.target@example.test",
            "--remote",
            "https://validator.example",
            "--remote-key-file",
            str(path),
        ]
    )
    output = capsys.readouterr()
    assert code == EXIT_INVALID_INPUT
    assert key not in output.out + output.err
    assert "Traceback" not in output.out + output.err


def test_plaintext_smtp_policy_is_not_available() -> None:
    with pytest.raises((ValueError, SMTPContractError)):
        DialogueSettings(tls_policy="opportunistic")  # type: ignore[arg-type]
    from emailcheck.domain.smtp_tls import TLSPolicy

    assert [policy.value for policy in TLSPolicy] == ["required"]


@pytest.mark.parametrize("status", [200, 301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "origin,target",
    [
        ("http://127.0.0.1", "https://validator.example/next"),
        ("https://validator.example", "http://127.0.0.1/next"),
        ("https://validator.example", "https://elsewhere.example/next"),
        ("https://validator.example", "https://validator.example/next"),
    ],
)
def test_redirect_response_cannot_forward_key_and_is_closed(
    status: int,
    origin: str,
    target: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run real urllib response/error dispatch over a socket-free HTTP handler."""
    requests: list[urllib.request.Request] = []
    responses: list[io.BytesIO] = []

    class ScriptedHTTP(urllib.request.HTTPHandler, urllib.request.HTTPSHandler):
        def http_open(self, request: urllib.request.Request):  # type: ignore[no-untyped-def]
            requests.append(request)
            headers = Message()
            headers["Location"] = target
            headers["Content-Type"] = "application/json"
            body = io.BytesIO(b"{}")
            responses.append(body)
            response = urllib.response.addinfourl(body, headers, request.full_url, status)
            response.msg = "test redirect"
            return response

        https_open = http_open

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        ScriptedHTTP(),
        urllib_client._RefuseRedirects(),
    )
    monkeypatch.setattr(urllib_client, "_OPENER", opener)
    client = UrllibRemoteCheckClient(origin, "test-bearer-secret")
    if status == 200:
        assert client._request("/v1/checks", "GET", None) == {}
    else:
        with pytest.raises(RemoteCheckError) as failure:
            client._request("/v1/checks", "GET", None)
        assert "test-bearer-secret" not in str(failure.value)
        assert target not in str(failure.value)
    assert len(requests) == 1
    assert requests[0].get_header("Authorization") == "Bearer test-bearer-secret"
    assert all(response.closed for response in responses)
