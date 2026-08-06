from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    INVALID_SYNTAX = "invalid_syntax"
    UNSUPPORTED_QUOTED_LOCAL_PART = "unsupported_quoted_local_part"
    UNSUPPORTED_DOMAIN_LITERAL = "unsupported_domain_literal"
    UNSUPPORTED_SMTPUTF8 = "unsupported_smtputf8"

    DOMAIN_NXDOMAIN = "domain_nxdomain"
    DNS_TEMPORARY_FAILURE = "dns_temporary_failure"
    NULL_MX = "null_mx"
    NO_MAIL_ROUTE = "no_mail_route"
    MX_AVAILABLE = "mx_available"
    IMPLICIT_MX_AVAILABLE = "implicit_mx_available"
    MX_CONFIGURATION_ANOMALY = "mx_configuration_anomaly"
    UNSAFE_DESTINATION = "unsafe_destination"

    DISPOSABLE_DOMAIN = "disposable_domain"
    ROLE_ACCOUNT = "role_account"
    FREE_MAIL = "free_mail"
    PROVIDER_OPAQUE = "provider_opaque"

    SMTP_CONNECTION_TIMEOUT = "smtp_connection_timeout"
    SMTP_CONNECTION_REFUSED = "smtp_connection_refused"
    SMTP_BANNER_INVALID = "smtp_banner_invalid"
    SMTP_TLS_FAILURE = "smtp_tls_failure"
    SMTP_POLICY_BLOCKED = "smtp_policy_blocked"
    MAIL_FROM_REJECTED = "mail_from_rejected"
    RCPT_ACCEPTED = "rcpt_accepted"
    RCPT_FORWARDED = "rcpt_forwarded"
    RCPT_UNVERIFIABLE = "rcpt_unverifiable"
    RCPT_REJECTED_ADDRESS = "rcpt_rejected_address"
    RCPT_REJECTED_POLICY = "rcpt_rejected_policy"
    SMTP_TEMPORARY_FAILURE = "smtp_temporary_failure"
    SMTP_AMBIGUOUS_PERMANENT_FAILURE = "smtp_ambiguous_permanent_failure"
    MAILBOX_FULL = "mailbox_full"
    ACCEPT_ALL_SUSPECTED = "accept_all_suspected"

    INTERNAL_ERROR = "internal_error"
