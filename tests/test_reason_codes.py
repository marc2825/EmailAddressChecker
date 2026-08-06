from emailcheck.domain.reasons import ReasonCode


def test_reason_codes_are_unique() -> None:
    values = [reason.value for reason in ReasonCode]
    assert len(values) == len(set(values))


def test_required_baseline_reasons_exist() -> None:
    required = {
        "invalid_syntax",
        "domain_nxdomain",
        "null_mx",
        "no_mail_route",
        "rcpt_accepted",
        "rcpt_unverifiable",
        "rcpt_rejected_address",
        "rcpt_rejected_policy",
        "smtp_temporary_failure",
        "accept_all_suspected",
    }
    assert required <= {reason.value for reason in ReasonCode}
