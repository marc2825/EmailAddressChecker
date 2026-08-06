from __future__ import annotations

from enum import StrEnum


class SMTPState(StrEnum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    BANNER_RECEIVED = "banner_received"
    EHLO_COMPLETED = "ehlo_completed"
    TLS_NEGOTIATED = "tls_negotiated"
    EHLO_COMPLETED_AFTER_TLS = "ehlo_completed_after_tls"
    MAIL_FROM_ACCEPTED = "mail_from_accepted"
    RCPT_RESULT_RECEIVED = "rcpt_result_received"
    RESET_COMPLETED = "reset_completed"
    CLOSED = "closed"
    FAILED = "failed"


class SMTPCommand(StrEnum):
    EHLO = "EHLO"
    STARTTLS = "STARTTLS"
    MAIL_FROM = "MAIL FROM"
    RCPT_TO = "RCPT TO"
    RSET = "RSET"
    QUIT = "QUIT"
