"""Talking to a remote validator over HTTP, using only the standard library.

`docs/requirements.md` section 12 requires `--remote`. The transport is the
standard library's `urllib.request`; no extra HTTP dependency is needed.
URLs are validated before use. Environment proxies are explicitly disabled so
ambient configuration cannot route credential-bearing requests (ADR 0021).

**This adapter enforces transport safety.** Poll frequency, wait bounds and
presentation belong to `apps/cli.py`. This adapter sends one request,
parses one answer through `application/public_job.py`, and converts every
library failure into `RemoteCheckError` — so a `urllib` traceback never reaches
a user, which is the same rule `docs/requirements.md` section 11 puts on a
served response.

**The API key never reaches an error message.** It is set as a header and is not
interpolated into any string this module builds.

**This client follows no redirect at all.** `urllib`'s default opener copies
every header except `content-length` and `content-type` onto the redirected
request, so `Authorization: Bearer <key>` is forwarded to whatever host the
answer names — cross-origin, and over plaintext `http` if the redirect says so.
The stdlib additionally permits `ftp:` as a redirect target. `security/remote_url.py`
validates only the *first* URL, so after one hop the scheme allowlist, the
credential rule, and the host are all out of the picture.

A credential-bearing client cannot safely delegate that decision, so a `3xx`
becomes a `RemoteCheckError` and the request stops. Same-origin redirects are
refused too: "same origin" is a judgement about a URL an attacker may have
chosen, and an operator whose validator moved can change `--remote`. There is no
retry — a refused redirect is an answer, not a transient failure.

`urlopen` is blocking, so each call runs in a worker thread. That keeps the port
async without pretending a blocking client is not blocking.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Final

from emailcheck.ports.public_contract import PublicJob, public_job_from_json_object
from emailcheck.ports.remote_check import RemoteCheckError
from emailcheck.security.remote_url import join_api_path, normalize_base_url

#: The two published paths this client uses. Copied rather than imported:
#: `docs/architecture.md` section 1 puts `apps/` above `adapters/`, so an
#: adapter importing from `apps/` would invert the dependency. A test asserts
#: these equal `apps/api.py`'s constants, so the copy cannot drift.
ACTIVE_PATH: Final = "/v1/checks"
JOB_PATH_PREFIX: Final = "/v1/checks/"

#: Every outbound call is bounded, like every other external operation here.
DEFAULT_TIMEOUT_SECONDS: Final = 30.0

#: A remote body larger than this is not an answer to these two calls.
MAX_RESPONSE_BYTES: Final = 256 * 1024


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into a refusal, before a new request is built.

    `HTTPRedirectHandler.redirect_request` is what constructs the follow-up
    `Request`, and it is what copies the headers onto it. Raising *here* means
    no redirected request object is ever created, so the key cannot reach one
    even in memory — which is a stronger statement than stripping a header from
    a request that was going to be sent.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        # `newurl` is remote-chosen text and is deliberately not repeated.
        close = getattr(fp, "close", None)
        if callable(close):
            close()
        raise RemoteCheckError(f"the remote validator answered a redirect ({code})")


#: One opener, built at import, with the redirect handler replaced.
#:
#: `build_opener` substitutes a subclass for the default handler of the same
#: kind, so this is the whole redirect policy. Nothing else in this module calls
#: `urllib.request.urlopen`, which would silently use the default opener again.
_OPENER: Final = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RefuseRedirects())


@dataclass(frozen=True, slots=True)
class UrllibRemoteCheckClient:
    """One remote validator over HTTPS, or HTTP to exact loopback literals."""

    base_url: str = field(repr=False)
    api_key: str = field(repr=False)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", normalize_base_url(self.base_url))
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int | float)
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 300
        ):
            raise ValueError("a remote timeout must be finite and between 0 and 300 seconds")
        if (
            not isinstance(self.api_key, str)
            or not self.api_key
            or any(ord(character) < 32 or ord(character) >= 127 for character in self.api_key)
        ):
            raise ValueError("a remote API key must be printable ASCII text")

    async def submit(self, address: str) -> PublicJob:
        payload = await asyncio.to_thread(
            self._request, ACTIVE_PATH, "POST", json.dumps({"email": address}).encode("utf-8")
        )
        job = payload.get("job") if isinstance(payload, dict) else None
        if job is None:
            raise RemoteCheckError("the remote validator returned no job")
        return public_job_from_json_object(job)

    async def fetch(self, job_id: str) -> PublicJob:
        if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job_id):
            raise RemoteCheckError("the remote validator returned an unusable job identifier")
        payload = await asyncio.to_thread(self._request, f"{JOB_PATH_PREFIX}{job_id}", "GET", None)
        return public_job_from_json_object(payload)

    def _request(self, path: str, method: str, body: bytes | None) -> object:
        """One blocking call, with every failure converted to our own type."""
        request = urllib.request.Request(  # noqa: S310 - the scheme is checked by `join_api_path`
            join_api_path(self.base_url, path),
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with _OPENER.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except RemoteCheckError:
            # A refused redirect. Re-raised unchanged so the generic handler
            # below cannot flatten it into "could not be reached".
            raise
        except urllib.error.HTTPError as failure:
            # The status is this project's own vocabulary; the body is not read,
            # because a remote error body is remote text.
            with contextlib.suppress(OSError):
                failure.close()
            raise RemoteCheckError(f"the remote validator answered {failure.code}") from None
        except AssertionError:
            # A broken invariant or the test network guard is not a remote failure.
            raise
        except Exception:
            raise RemoteCheckError("the remote validator could not be reached") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RemoteCheckError("the remote validator answered with too much data")
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise RemoteCheckError("the remote validator answered with unreadable data") from None
