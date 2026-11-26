"""Plain-language explanations of the published vocabulary, in English and Japanese.

Statuses, confidence levels, reason codes, risk flags, and row states are
stable API values. People reading a terminal need to know what each one means
without opening `docs/status-model.md`, so this module holds one short label
and one sentence for every value, and `tests/unit/apps/test_cli_design.py`
fails when a published value has no entry.

**Presentation only.** Nothing here decides or changes a status. `mark` only
chooses the symbol drawn beside an evidence step (passed, failed, or neither),
and every symbol is printed next to a word, so the mark never carries meaning
alone. Wording follows `docs/requirements.md`: no entry claims that a mailbox
exists, and every entry that sounds positive says what it does not prove.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from emailcheck.apps.messages import Lang

Mark = Literal["ok", "fail", "warn"]
Kind = Literal["status", "confidence", "reason", "risk_flag", "state", "row_error"]


@dataclass(frozen=True, slots=True)
class Term:
    """One published value, described for people."""

    kind: Kind
    code: str
    en_label: str
    ja_label: str
    en_meaning: str
    ja_meaning: str
    layer: str | None = None
    mark: Mark = "warn"

    def label(self, lang: Lang) -> str:
        return self.ja_label if lang == "ja" else self.en_label

    def meaning(self, lang: Lang) -> str:
        return self.ja_meaning if lang == "ja" else self.en_meaning


def _terms(*terms: Term) -> dict[str, Term]:
    return {term.code: term for term in terms}


STATUSES: Final = _terms(
    Term(
        "status",
        "likely_deliverable",
        "Likely deliverable",
        "届く見込みがあります",
        "A mail server gave positive evidence at the delivery stage and nothing stronger "
        "contradicts it. This does not prove that the mailbox exists. A local check never "
        "gives this status, because it does not connect to SMTP.",
        "配送段階で肯定的な証拠があり、それを打ち消す強い証拠がありません。"
        "メールボックスの実在を証明するものではありません。"
        "ローカルの検査はSMTPに接続しないので、この判定は出ません。",
    ),
    Term(
        "status",
        "invalid",
        "Invalid",
        "無効です",
        "Strong evidence about this address shows that mail cannot be delivered as addressed: "
        "broken syntax, a domain that does not exist, a domain that accepts no mail, no mail "
        "route, or a server that explicitly said the recipient does not exist.",
        "このアドレスに固有の強い証拠から、届かないと判断しました。"
        "構文の誤り、存在しないドメイン、受信しない宣言、メールの経路なし、"
        "受信者が存在しないという明示的な応答のいずれかです。",
    ),
    Term(
        "status",
        "temporary_unknown",
        "Cannot tell right now",
        "今は判定できません",
        "The evidence reports a condition expected to change, such as a DNS server failure or "
        "a temporary mail server reply. A later check may give a different answer.",
        "DNSサーバーの障害や一時的な応答など、変わる見込みのある状態です。"
        "時間をおいて調べると、結果が変わることがあります。",
    ),
    Term(
        "status",
        "unknown",
        "Cannot tell",
        "判定できません",
        "There is no reliable evidence about this address either way. A mail route on its "
        "own, an unsupported form, a policy block, and a server that hides its recipients "
        "all end here. It is not a negative answer.",
        "このアドレスについて、どちらとも言える確かな証拠がありません。"
        "メールの経路があるだけの場合、未対応の形式、ポリシーによる拒否、"
        "受信者を明かさないサーバーなどがここに入ります。無効という意味ではありません。",
    ),
)

CONFIDENCE: Final = _terms(
    Term(
        "confidence",
        "high",
        "high",
        "高",
        "The deciding evidence is explicit, such as broken syntax or a domain that does not "
        "exist. Confidence is a category, not a probability.",
        "判定のもとになった証拠が明確です（例: 構文の誤り、存在しないドメイン）。"
        "信頼度は段階で、確率ではありません。",
    ),
    Term(
        "confidence",
        "medium",
        "medium",
        "中",
        "The evidence points one way but leaves room for another reading. Confidence is a "
        "category, not a probability.",
        "証拠は一方を示していますが、別の解釈の余地があります。"
        "信頼度は段階で、確率ではありません。",
    ),
    Term(
        "confidence",
        "low",
        "low",
        "低",
        "Only weak evidence was found, or none that decides the question. Confidence is a "
        "category, not a probability.",
        "弱い証拠しかないか、判定を決める証拠がありません。信頼度は段階で、確率ではありません。",
    ),
)


def _reason(
    code: str,
    layer: str,
    mark: Mark,
    en_label: str,
    ja_label: str,
    en_meaning: str,
    ja_meaning: str,
) -> Term:
    return Term("reason", code, en_label, ja_label, en_meaning, ja_meaning, layer, mark)


_RISK_ONLY_EN: Final = " This is a risk note, not part of the deliverability verdict."
_RISK_ONLY_JA: Final = "配送の判定とは別の、注意のための情報です。"

REASONS: Final = _terms(
    _reason(
        "invalid_syntax",
        "syntax",
        "fail",
        "not a valid address",
        "形式が正しくありません",
        "The input does not follow the supported address grammar.",
        "入力がメールアドレスの文法に合っていません。",
    ),
    _reason(
        "unsupported_quoted_local_part",
        "syntax",
        "warn",
        "quoted local part not supported",
        "引用符付きの形式には未対応",
        "The part before @ is in quotes. This form is not supported, so it is not judged invalid.",
        "@の前が引用符で囲まれています。この形式には対応していないので、無効とは判断しません。",
    ),
    _reason(
        "unsupported_domain_literal",
        "syntax",
        "warn",
        "IP address domain not supported",
        "IPアドレス形式のドメインには未対応",
        "The domain is an address literal such as [192.0.2.1]. This form is not supported.",
        "ドメインが [192.0.2.1] のようなIPアドレス表記です。この形式には対応していません。",
    ),
    _reason(
        "unsupported_smtputf8",
        "syntax",
        "warn",
        "non-ASCII local part not supported",
        "ASCII以外のローカルパートには未対応",
        "The part before @ has non-ASCII characters and needs SMTPUTF8. This form is not "
        "supported, so it is not judged invalid.",
        "@の前にASCII以外の文字があり、SMTPUTF8が必要です。"
        "この形式には対応していないので、無効とは判断しません。",
    ),
    _reason(
        "domain_nxdomain",
        "dns",
        "fail",
        "domain does not exist",
        "ドメインが存在しません",
        "DNS answered that the domain does not exist (NXDOMAIN).",
        "DNSが、このドメインは存在しないと回答しました（NXDOMAIN）。",
    ),
    _reason(
        "dns_temporary_failure",
        "dns",
        "warn",
        "DNS lookup failed for now",
        "DNSの一時的な失敗",
        "The DNS lookup failed or timed out. A later check may give a different answer.",
        "DNSの問い合わせが失敗したか、時間切れになりました。"
        "時間をおくと、結果が変わることがあります。",
    ),
    _reason(
        "null_mx",
        "dns",
        "fail",
        "domain accepts no mail (null MX)",
        "受信しない宣言（null MX）",
        "The domain declares in DNS that it accepts no mail (RFC 7505).",
        "このドメインは、メールを受け取らないとDNSで宣言しています（RFC 7505）。",
    ),
    _reason(
        "no_mail_route",
        "dns",
        "fail",
        "no mail route",
        "メールの経路がありません",
        "The domain has no MX record and no A/AAAA record to use instead.",
        "MXレコードも、代わりに使えるA/AAAAレコードもありません。",
    ),
    _reason(
        "mx_available",
        "dns",
        "ok",
        "mail route found (MX)",
        "メールの経路がある（MX）",
        "The domain is set up to receive mail (MX records). A route says nothing about "
        "whether this recipient exists.",
        "ドメインにメールを受け取る設定（MXレコード）があります。"
        "経路があるだけで、宛先の実在は示しません。",
    ),
    _reason(
        "implicit_mx_available",
        "dns",
        "ok",
        "mail route found (A/AAAA)",
        "メールの経路がある（A/AAAA）",
        "The domain has no MX record, but its A/AAAA record can be used as the route. A route "
        "says nothing about whether this recipient exists.",
        "MXレコードはありませんが、A/AAAAレコードを経路として使えます。"
        "経路があるだけで、宛先の実在は示しません。",
    ),
    _reason(
        "mx_configuration_anomaly",
        "dns",
        "warn",
        "MX records are unusable",
        "MXの設定に問題があります",
        "MX records exist, but none of them can be used. This is not proof that the domain "
        "refuses mail.",
        "MXレコードはありますが、使えるものがありません。"
        "メールを受け取らないという証拠にはなりません。",
    ),
    _reason(
        "unsafe_destination",
        "dns",
        "warn",
        "points to a refused destination",
        "接続しない宛先を指しています",
        "DNS points to an address this tool never connects to, such as a loopback or "
        "private address.",
        "DNSの結果が、ループバックやプライベートアドレスなど、接続しない宛先を指しています。",
    ),
    _reason(
        "disposable_domain",
        "passive_classification",
        "warn",
        "disposable-mail domain",
        "使い捨てメールのドメイン",
        "The domain is on the disposable-mail list." + _RISK_ONLY_EN,
        "使い捨てメールのドメイン一覧に含まれています。" + _RISK_ONLY_JA,
    ),
    _reason(
        "role_account",
        "passive_classification",
        "warn",
        "role address",
        "役割アドレス",
        "The part before @ names a role, such as info or support, rather than a person."
        + _RISK_ONLY_EN,
        "info や support のように、個人ではなく役割を表すアドレスです。" + _RISK_ONLY_JA,
    ),
    _reason(
        "free_mail",
        "passive_classification",
        "warn",
        "free-mail domain",
        "フリーメールのドメイン",
        "The domain is on the free-mail list." + _RISK_ONLY_EN,
        "フリーメールのドメイン一覧に含まれています。" + _RISK_ONLY_JA,
    ),
    _reason(
        "provider_opaque",
        "passive_classification",
        "warn",
        "provider hides recipients",
        "受信者を明かさない事業者",
        "The provider is known to hide whether a recipient is valid.",
        "受信者が有効かどうかを明かさないことが知られている事業者です。",
    ),
    _reason(
        "smtp_connection_timeout",
        "smtp",
        "warn",
        "mail server timed out",
        "メールサーバーが時間切れ",
        "Connecting to the mail server, or waiting for its reply, took longer than allowed.",
        "メールサーバーへの接続か応答が、決められた時間内に終わりませんでした。",
    ),
    _reason(
        "smtp_connection_refused",
        "smtp",
        "warn",
        "mail server refused the connection",
        "メールサーバーが接続を拒否",
        "The mail server refused the connection.",
        "メールサーバーが接続を拒否しました。",
    ),
    _reason(
        "smtp_banner_invalid",
        "smtp",
        "warn",
        "unusable greeting",
        "最初の応答が使えません",
        "The mail server's greeting was unusable.",
        "メールサーバーの最初の応答が、使えないものでした。",
    ),
    _reason(
        "smtp_protocol_error",
        "smtp",
        "warn",
        "unreadable reply",
        "応答を解釈できません",
        "A reply from the mail server could not be read. It says nothing about the recipient.",
        "メールサーバーの応答を解釈できませんでした。宛先についての証拠にはなりません。",
    ),
    _reason(
        "smtp_tls_failure",
        "smtp",
        "warn",
        "encryption failed",
        "暗号化に失敗",
        "STARTTLS or the TLS handshake failed. This never means the mailbox is invalid.",
        "STARTTLSによる暗号化を確立できませんでした。メールボックスが無効という意味ではありません。",
    ),
    _reason(
        "smtp_policy_blocked",
        "smtp",
        "warn",
        "blocked by policy",
        "ポリシーで拒否",
        "The mail server refused for reputation, policy, or security reasons unrelated to "
        "the recipient.",
        "宛先とは関係のない、評判やポリシー、セキュリティによる拒否です。",
    ),
    _reason(
        "mail_from_rejected",
        "smtp",
        "warn",
        "sender rejected",
        "送信者が拒否されました",
        "The sender address used for the check was rejected. It says nothing about the recipient.",
        "検査に使う送信者アドレスが拒否されました。宛先についての証拠にはなりません。",
    ),
    _reason(
        "rcpt_accepted",
        "smtp",
        "ok",
        "recipient accepted (not proof)",
        "受信者を受け付けた（実在の証明ではない）",
        "The mail server accepted the recipient. Some servers accept every recipient, so "
        "this is not proof that the mailbox exists.",
        "メールサーバーが受信者を受け付けました。どの宛先も受け付けるサーバーもあるので、"
        "実在の証明ではありません。",
    ),
    _reason(
        "rcpt_forwarded",
        "smtp",
        "ok",
        "accepted for forwarding",
        "転送先として受け付けた",
        "The mail server accepted the recipient for forwarding (251). This is not proof that "
        "the mailbox exists.",
        "メールサーバーが転送のために受信者を受け付けました（251）。実在の証明ではありません。",
    ),
    _reason(
        "rcpt_unverifiable",
        "smtp",
        "warn",
        "server declined to verify",
        "受信者の確認を断られた",
        "The mail server declined to verify the recipient (252). This is not an acceptance.",
        "メールサーバーが受信者の確認を断りました（252）。受け付けたという意味ではありません。",
    ),
    _reason(
        "rcpt_rejected_address",
        "smtp",
        "fail",
        "recipient does not exist",
        "受信者が存在しないと回答",
        "The mail server explicitly said that this recipient does not exist (5.1.1).",
        "メールサーバーが、この受信者は存在しないと明示しました（5.1.1）。",
    ),
    _reason(
        "rcpt_rejected_policy",
        "smtp",
        "warn",
        "recipient refused by policy",
        "受信者をポリシーで拒否",
        "The recipient was refused for policy or security reasons (5.7.x). Whether it "
        "exists is unknown.",
        "ポリシーやセキュリティの理由で受信者を拒否しました（5.7.x）。宛先の有無は分かりません。",
    ),
    _reason(
        "smtp_temporary_failure",
        "smtp",
        "warn",
        "temporary error (4xx)",
        "一時的なエラー（4xx）",
        "The mail server returned a temporary error.",
        "メールサーバーが一時的なエラーを返しました。",
    ),
    _reason(
        "smtp_ambiguous_permanent_failure",
        "smtp",
        "warn",
        "refused without a clear reason",
        "理由の分からない拒否",
        "A permanent refusal with no code that says why. It is not judged invalid.",
        "恒久的な拒否ですが、理由を示すコードがありません。無効とは判断しません。",
    ),
    _reason(
        "mailbox_full",
        "smtp",
        "warn",
        "mailbox or storage full",
        "メールボックスの容量不足",
        "The mail server reported a temporary mailbox or storage condition.",
        "メールボックスや保存領域の一時的な問題が報告されました。",
    ),
    _reason(
        "accept_all_suspected",
        "accept_all",
        "warn",
        "server seems to accept everyone",
        "すべての宛先を受け付ける疑い",
        "The server appears to accept every recipient, so an acceptance is not evidence "
        "about this one.",
        "このサーバーはどの宛先も受け付けるように見えます。受け付けても、この宛先の証拠にはなりません。",
    ),
    _reason(
        "internal_error",
        "internal",
        "warn",
        "internal error",
        "内部エラー",
        "A problem in this tool prevented a determination. It never means the address is invalid.",
        "このツール側の問題で判定できませんでした。アドレスが無効という意味ではありません。",
    ),
)

RISK_FLAGS: Final = _terms(
    Term(
        "risk_flag",
        "disposable",
        "disposable mail",
        "使い捨てメール",
        "The domain is a disposable-mail service." + _RISK_ONLY_EN,
        "使い捨てメールのドメインです。" + _RISK_ONLY_JA,
    ),
    Term(
        "risk_flag",
        "role_account",
        "role address",
        "役割アドレス",
        "The address names a role, such as info or support, rather than a person." + _RISK_ONLY_EN,
        "info や support のように、個人ではなく役割を表すアドレスです。" + _RISK_ONLY_JA,
    ),
    Term(
        "risk_flag",
        "free_mail",
        "free mail",
        "フリーメール",
        "The domain is a free-mail service." + _RISK_ONLY_EN,
        "フリーメールのドメインです。" + _RISK_ONLY_JA,
    ),
    Term(
        "risk_flag",
        "accept_all_suspected",
        "may accept everyone",
        "すべて受け付ける疑い",
        "The destination appears to accept every recipient." + _RISK_ONLY_EN,
        "宛先のサーバーが、どの受信者も受け付けるように見えます。" + _RISK_ONLY_JA,
    ),
    Term(
        "risk_flag",
        "provider_opaque",
        "provider hides recipients",
        "受信者を明かさない事業者",
        "The provider is known to hide whether a recipient is valid." + _RISK_ONLY_EN,
        "受信者が有効かどうかを明かさない事業者です。" + _RISK_ONLY_JA,
    ),
    Term(
        "risk_flag",
        "internationalized_local_part",
        "non-ASCII local part",
        "国際化ローカルパート",
        "The part before @ has non-ASCII characters." + _RISK_ONLY_EN,
        "@の前にASCII以外の文字があります。" + _RISK_ONLY_JA,
    ),
    Term(
        "risk_flag",
        "domain_configuration_anomaly",
        "inconsistent DNS setup",
        "DNS設定の矛盾",
        "The domain has a usable mail route, but its DNS setup is inconsistent (for example, "
        "MX records next to a null MX)." + _RISK_ONLY_EN,
        "メールの経路はありますが、DNSの設定に矛盾があります（例: MXとnull MXが両方ある）。"
        + _RISK_ONLY_JA,
    ),
)

STATES: Final = _terms(
    Term(
        "state",
        "completed",
        "checked",
        "検査済み",
        "The row was checked and has a status.",
        "検査して、判定が出た行です。",
    ),
    Term(
        "state",
        "duplicate",
        "duplicate",
        "重複",
        "With --duplicates skip, a repeat of an earlier row. It points to that row and "
        "carries no status of its own.",
        "--duplicates skip のとき、前の行と同じアドレスの行です。"
        "最初の行を参照し、判定は付けません。",
    ),
    Term(
        "state",
        "rejected",
        "rejected",
        "読み取れない行",
        "The row could not be read as input, for example a CSV row with the wrong number "
        "of fields. It has no status.",
        "入力として読み取れなかった行です（例: CSVの列の数が合わない）。判定は付けません。",
    ),
    Term(
        "state",
        "refused",
        "refused",
        "検査を見送った行",
        "The row was not checked because a limit was reached, such as the hourly quota. It "
        "has no status.",
        "1時間あたりの件数などの上限に達したため、検査しなかった行です。判定は付けません。",
    ),
    Term(
        "state",
        "failed",
        "failed",
        "処理に失敗した行",
        "The row could not be processed because of a problem in this tool. It has no status.",
        "このツール側の問題で処理できなかった行です。判定は付けません。",
    ),
)

ROW_ERRORS: Final = _terms(
    Term(
        "row_error",
        "malformed_row",
        "wrong number of fields",
        "列の数が合いません",
        "The CSV row has a different number of fields from the header.",
        "CSVの行の列の数が、ヘッダーと違います。",
    ),
    Term(
        "row_error",
        "input_too_long",
        "too long to check",
        "長すぎて検査できません",
        "The input is longer than any address can be.",
        "アドレスとして扱える長さを超えています。",
    ),
    Term(
        "row_error",
        "verification_refused",
        "limit reached",
        "上限に達しました",
        "A quota or rate limit was reached, so the row was not checked.",
        "件数の上限かレート制限に達したため、検査しませんでした。",
    ),
    Term(
        "row_error",
        "processing_failed",
        "processing failed",
        "処理に失敗しました",
        "A problem in this tool stopped the check.",
        "このツール側の問題で、検査を続けられませんでした。",
    ),
)

#: What a person can do about an SMTP outcome in Active Mode, as (English,
#: Japanese). Advice about the user's own setup only: nothing here suggests a
#: way around a server's refusal or a network's restriction.
HINTS: Final[dict[str, tuple[str, str]]] = {
    "smtp_connection_timeout": (
        "Your network may block outbound port 25; many ISPs and cloud providers do. "
        "The address was not judged.",
        "接続元のネットワークがポート25への接続を遮断している可能性があります"
        "（多くのISPやクラウドが遮断しています）。アドレスの判定ではありません。",
    ),
    "smtp_connection_refused": (
        "The server or your network refused the connection on port 25. The address was not judged.",
        "サーバーか接続元のネットワークが、ポート25への接続を拒否しました。"
        "アドレスの判定ではありません。",
    ),
    "smtp_tls_failure": (
        "This tool checks only over TLS with a valid certificate, and that was not "
        "possible with this server.",
        "このツールは証明書を検証できるTLSでしか検査しません。このサーバーとは、それができませんでした。",
    ),
    "smtp_policy_blocked": (
        "Servers often refuse connections from home or cloud IP addresses, or from a "
        "host whose reverse DNS and SPF do not match the configured sender.",
        "家庭やクラウドのIPアドレスや、逆引きDNSとSPFが設定した送信者と一致しない"
        "接続元は、拒否されることがよくあります。",
    ),
    "mail_from_rejected": (
        "The server refused the configured sender. Check that its domain is yours and "
        "that SPF allows this machine.",
        "設定した送信者が拒否されました。自分のドメインか、SPFでこの機器が許可されているかを確認してください。",
    ),
    "rcpt_rejected_policy": (
        "A policy refusal says nothing about whether the recipient exists.",
        "ポリシーによる拒否からは、受信者の有無は分かりません。",
    ),
    "smtp_temporary_failure": (
        "Some servers defer unknown senders at first (greylisting).",
        "知らない送信元を最初は一時的に断るサーバーもあります（グレイリスティング）。",
    ),
}

#: Every table, in the order `emailcheck explain` lists them.
TABLES: Final[tuple[dict[str, Term], ...]] = (
    STATUSES,
    CONFIDENCE,
    REASONS,
    RISK_FLAGS,
    STATES,
    ROW_ERRORS,
)

#: Which dataset a risk flag or reason code depends on, for the note that an
#: absent flag is not a negative answer while that dataset is unavailable.
DATASET_OF: Final[dict[str, str]] = {
    "disposable": "disposable",
    "disposable_domain": "disposable",
    "free_mail": "free_mail",
    "provider_opaque": "provider",
}


def lookup(code: str) -> tuple[Term, ...]:
    """Every entry named `code`. A few names are both a reason and a flag."""
    return tuple(table[code] for table in TABLES if code in table)


def every_code() -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for table in TABLES:
        for code in table:
            seen.setdefault(code, None)
    return tuple(seen)
