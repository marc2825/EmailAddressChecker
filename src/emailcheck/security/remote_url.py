"""Which remote endpoints `--remote` may talk to. A pure function.

`docs/requirements.md` section 12 lets the CLI submit an active job to a remote
validator. The URL is **operator-supplied**, typed on a command line, so this is
not the SSRF problem `security/destination.py` solves — nobody else chooses this
value. It is still screened, for two reasons that survive that difference:

- a scheme like `file:` or `data:` is not a validator at all, and accepting one
  turns a typo into a local file read;
- a bounded, explicitly joined path means the API path this project appends
  cannot be changed by what the operator typed.

The policy is an **allowlist of two schemes** rather than a deny list of the
dangerous ones, on the precedent the request schema in `apps/api.py` set: a
scheme nobody thought of is refused too.

HTTPS is required. HTTP is reserved for exactly 127.0.0.1 and ::1 literals;
hostnames and DNS resolution never grant a plaintext exception (ADR 0021).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final
from urllib.parse import unquote, urlsplit, urlunsplit

#: Long enough for any real deployment, short enough that it cannot be a payload.
MAX_URL_LENGTH: Final = 2048

#: The only two schemes a validator is reachable over.
PERMITTED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


class RemoteUrlError(ValueError):
    """The remote endpoint is not one this CLI will talk to."""


def normalize_base_url(url: str) -> str:
    """Return the validated origin-and-prefix this client will build paths on.

    Refuses a non-permitted scheme, a missing host, credentials in the
    authority, a query, and a fragment. Credentials are refused rather than
    stripped: `--remote https://key@host` is somebody putting a secret on a
    command line, and silently discarding it would hide that it was never sent.
    """
    if not isinstance(url, str) or not url:
        raise RemoteUrlError("a remote endpoint must be text")
    if len(url) > MAX_URL_LENGTH:
        raise RemoteUrlError(f"a remote endpoint must be at most {MAX_URL_LENGTH} characters")
    if any(ord(character) <= 32 or ord(character) >= 127 for character in url):
        # A control character in a URL is a request-splitting attempt or a
        # copy-paste accident. Neither should reach a client library.
        raise RemoteUrlError("a remote endpoint must use ASCII text without whitespace or controls")

    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise RemoteUrlError("a remote endpoint has an invalid authority") from None
    if parts.scheme not in PERMITTED_SCHEMES:
        raise RemoteUrlError("a remote endpoint must be http or https")
    if not host:
        raise RemoteUrlError("a remote endpoint must name a host")
    if parts.username is not None or parts.password is not None:
        raise RemoteUrlError("a remote endpoint must not carry credentials")
    if "?" in url or "#" in url:
        raise RemoteUrlError("a remote endpoint must not carry a query or a fragment")
    if "\\" in url or "%" in parts.netloc or parts.netloc.endswith(":") or port == 0:
        raise RemoteUrlError("a remote endpoint has an invalid authority")
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    if parts.netloc.lower() != authority or host.endswith(".."):
        raise RemoteUrlError("a remote endpoint has an invalid authority")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if (
            len(host) > 253
            or all(character in "0123456789." for character in host)
            or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
            )
        ):
            raise RemoteUrlError("a remote endpoint has an invalid host") from None
    if parts.scheme == "http" and host not in {"127.0.0.1", "::1"}:
        raise RemoteUrlError("a remote endpoint requires HTTPS except for 127.0.0.1 or ::1")
    decoded_path = unquote(parts.path)
    if any(ord(character) < 32 or ord(character) == 127 for character in decoded_path):
        raise RemoteUrlError("a remote endpoint carries a control character")

    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def join_api_path(base_url: str, path: str) -> str:
    """Append one of this project's own API paths to a validated base.

    `path` comes from `apps/api.py`'s published constants, never from a caller,
    and it must be absolute — so the result is always the base's origin plus a
    path this project chose. There is no relative resolution here and no
    `urljoin`, because `urljoin` with an absolute-looking input can replace the
    host, which is the one thing this function exists to keep fixed.
    """
    if not path.startswith("/"):
        raise RemoteUrlError("an API path must be absolute")
    if "//" in path or ".." in path or not re.fullmatch(r"/[A-Za-z0-9_/-]+", path):
        raise RemoteUrlError("an API path must not be protocol-relative or traverse")
    return f"{normalize_base_url(base_url)}{path}"
