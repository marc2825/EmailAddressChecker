# SMTP fixtures

The scripted SMTP scenarios are written in code, not stored here:

- `tests/fake_smtp_server.py`: a scripted SMTP peer that opens no socket and records every command it receives.
- `tests/fake_smtp_transport.py`: a scripted `SMTPTransport`, the default for transport tests.
- `tests/integration/loopback_server.py`: a plain TCP fixture bound to loopback only, for tests that need a real socket.

Fixtures must be deterministic, bind only to loopback, and record the complete client command transcript. See `docs/test-strategy.md`.
