# SMTP probe state machine

## 1. Purpose

This client is a recipient-stage observer, not a mail-sending client.

The implementation must expose no operation that can submit message content.

## 2. Allowed states

```text
DISCONNECTED
  → CONNECTING
  → BANNER_RECEIVED
  → EHLO_COMPLETED
  → TLS_NEGOTIATED          optional
  → EHLO_COMPLETED_AFTER_TLS
  → MAIL_FROM_ACCEPTED
  → RCPT_RESULT_RECEIVED
  → RESET_COMPLETED         best effort
  → CLOSED
```

Error or timeout from any state transitions to a terminal failed state and then
best-effort close.

## 3. Allowed commands

- `EHLO`
- `STARTTLS`
- `MAIL FROM`
- `RCPT TO`
- `RSET`
- `QUIT`

Forbidden:

- SMTP message-content command;
- `VRFY`;
- `EXPN`;
- `AUTH`;
- provider login or account endpoints;
- more than one requested target recipient in one MVP transaction.

## 4. STARTTLS

STARTTLS is optional in the first SMTP sub-Phase.

When enabled:

- parse the EHLO capability safely;
- send STARTTLS only once;
- apply handshake timeout;
- verify the peer according to the explicit TLS policy;
- issue EHLO again after TLS;
- never infer mailbox invalidity from TLS failure.

## 5. Reply parser

Requirements:

- support multiline replies;
- cap line bytes and line count;
- require syntactically consistent reply codes where practical;
- extract the basic code;
- extract an enhanced status code only when valid;
- retain a bounded redacted diagnostic;
- never use raw text alone when a structured code is available.

## 6. Timeout budget

Separate configuration:

- DNS resolution;
- TCP connect;
- banner;
- individual command;
- TLS handshake;
- total session.

The total session deadline dominates all others.

## 7. Transcript

Tests record every command. Production records only safe structured events by
default.

A test must fail if the command sequence contains a forbidden command or more
than one `RCPT TO`.

## 8. MX handling

- use MX priority order;
- do not race all MX hosts;
- make a bounded number of attempts;
- destination limits apply to domain and concrete MX;
- revalidate each resolved and connected IP;
- do not use an alternate MX to reinterpret an explicit target-specific
  recipient rejection without a documented policy.
