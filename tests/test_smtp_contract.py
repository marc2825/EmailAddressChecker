from emailcheck.domain.smtp_contract import SMTPCommand, SMTPState


def test_smtp_contract_has_only_recipient_stage_commands() -> None:
    assert {command.value for command in SMTPCommand} == {
        "EHLO",
        "STARTTLS",
        "MAIL FROM",
        "RCPT TO",
        "RSET",
        "QUIT",
    }


def test_smtp_contract_has_no_message_submission_state() -> None:
    forbidden_fragments = {"data", "body", "content", "message"}
    for state in SMTPState:
        assert not any(fragment in state.value.lower() for fragment in forbidden_fragments)


def test_contract_has_exactly_one_recipient_command_type() -> None:
    assert [command for command in SMTPCommand if command is SMTPCommand.RCPT_TO] == [
        SMTPCommand.RCPT_TO
    ]
