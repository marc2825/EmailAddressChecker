"""Talking to another instance of this service, as a port.

`docs/requirements.md` section 12 gives the CLI a remote active mode. The
transport is a port so that `apps/cli.py` holds the polling policy and the
formatting while knowing nothing about HTTP — and so that every test of that
policy runs against a fake rather than against a socket.

The port speaks in `PublicJob`, not in JSON. Parsing and validating the remote's
answer happens at the adapter boundary, which means a remote server cannot put a
status, confidence level, reason, or risk flag into this process that this build
does not publish.
"""

from __future__ import annotations

from typing import Protocol

from emailcheck.ports.public_contract import PublicJob


class RemoteCheckError(Exception):
    """The remote validator could not be used.

    Carries a category chosen by the adapter, never a library's exception text:
    `docs/requirements.md` section 11's rule about exception text applies to
    what this project prints as much as to what it serves.
    """


class RemoteCheckClient(Protocol):
    async def submit(self, address: str) -> PublicJob:
        """Submit one active check and return the job it created."""
        ...

    async def fetch(self, job_id: str) -> PublicJob:
        """Return the current state of one previously submitted job."""
        ...
