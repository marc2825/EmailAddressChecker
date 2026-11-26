# Comparison with other tools, and the limits of SMTP checks

Read on 2026-11-26 from each project's own documentation and source. Tools change; check the version you use. "Unverified" means the point could not be confirmed from an official source.

## Tools

| Tool | Checks | SMTP behaviour | Where it runs | Batch / output | Uncertainty | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| **EmailAddressChecker** | Syntax (IDNA 2008 + UTS-46; SMTPUTF8 local parts give `unknown`), DNS/MX with null MX, role addresses | Opt-in, one address per command; required TLS with certificate verification; one `RCPT TO`; no catch-all probing | Local CLI; Python API for syntax only | CSV/TXT batches (passive), JSON/CSV | Four statuses, categorical confidence, reason codes, evidence ladder | Apache-2.0 |
| [email-validator](https://github.com/JoshData/python-email-validator) 2.4.0 | Syntax; optional DNS (MX, null MX, A/AAAA fallback) | None: its README says there is "nothing to be gained by trying to actually contact an SMTP server" | Local Python library; a small test CLI | One address per line on stdin; JSON for one valid address | Exceptions | Unlicense |
| [py3-validate-email](https://git.ksol.io/karolyi/py3-validate-email) | Syntax, disposable list, MX, SMTP `RCPT` | Per its source, STARTTLS failure falls back to plaintext and the default TLS context does not verify certificates; MAIL FROM defaults to the checked address | Local Python library | Not documented | `True`, `False`, or `None` | LGPL on PyPI 1.0.5.post2; the current repository uses a modified, non-OSI licence |
| [check-if-email-exists / Reacher](https://github.com/reacherhq/check-if-email-exists) | Syntax, MX, SMTP, catch-all, disposable, role | Sends a random-address `RCPT` to detect catch-all, then the real one; defaults to a `gmail.com` EHLO name and sender unless configured | Local CLI, self-hosted HTTP API, SaaS | Bulk endpoint; JSON | `safe` / `risky` / `invalid` / `unknown` | MIT since 2026-10-07 (earlier releases differ) |
| [AfterShip email-verifier](https://github.com/AfterShip/email-verifier) (Go) | Syntax, MX, disposable, role, free provider, SMTP, optional catch-all | No STARTTLS in its SMTP code; its README warns that ISPs block port 25 and asks for your own domain and PTR | Go library and sample server | JSON | `yes` / `no` / `unknown` | MIT |
| [Truemail](https://github.com/truemail-rb/truemail) (Ruby) | Lists, regex, MX, SMTP | `tls_verify: false` in its SMTP request code | Ruby gem; separate server | JSON serializer | `success` plus per-layer errors | MIT |
| ZeroBounce, NeverBounce, Kickbox | Hosted verification with categories such as valid, invalid, catch-all/accept-all, unknown | Methodology unverified | Hosted API; account and API key | List upload and APIs | Categories, flags, or a score | Proprietary |

### Where this project differs

Having an SMTP check is not a distinction; several tools have one. The combination is what differs:

- local, with no external API, account, or key;
- SMTP off by default, one address per command, and no path from a file or from candidate generation to SMTP;
- TLS required and verified, never a plaintext fallback;
- evidence shown step by step, conservative statuses, categorical confidence, and no score;
- passive CSV/TXT batches with machine-readable output and privacy defaults;
- Japanese and English output;
- a reproducible evaluation ([evaluation](evaluation.md)) and open safety tests.

It does **not** detect catch-all servers, does not check SMTPUTF8 local parts, and its SMTP check is stricter than most tools about TLS, so it finishes on fewer servers.

## Limits of an SMTP check

These hold for every tool that probes with `RCPT TO`, including this one.

- **Port 25 is often blocked.** AWS EC2 blocks outbound port 25 by default ([AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-resource-limits.html)); Google Compute Engine blocks it to destinations outside the VPC ([Google Cloud](https://docs.cloud.google.com/compute/docs/tutorials/sending-mail)); Azure blocks it on most subscription types ([Azure](https://learn.microsoft.com/en-us/azure/virtual-network/troubleshoot-outbound-smtp-connectivity)); residential ISPs block it too ([Xfinity](https://www.xfinity.com/support/articles/list-of-blocked-ports)), and Japan's Ministry of Internal Affairs and Communications lists outbound port 25 blocking as a standard anti-spam measure ([MIC](https://www.soumu.go.jp/main_sosiki/joho_tsusin/d_syohi/m_mail.html)). Then the result is `temporary_unknown`.
- **An accepted recipient is not a mailbox.** RFC 5321 section 3.3 notes that some servers verify recipients only after the message text, and section 6.1 has a server that accepted a message report failure later ([RFC 5321](https://www.rfc-editor.org/rfc/rfc5321.txt)). Google Workspace documents catch-all routing for non-existent addresses ([Google](https://knowledge.workspace.google.com/admin/gmail/advanced/get-misaddressed-email-in-a-catch-all-mailbox)), and Exchange Online rejects unknown recipients at the edge only when configured to ([Microsoft](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-directory-based-edge-blocking)).
- **A 550 is not always "no such user".** RFC 5321 section 7.9 uses 550 for policy rejections too; only an explicit `5.1.1` is read as non-existence here.
- **Greylisting** answers unfamiliar senders with 4xx for minutes to hours ([RFC 6647](https://www.rfc-editor.org/rfc/rfc6647.txt)); a single probe reports `temporary_unknown`.
- **TLS.** A public MX must not require STARTTLS ([RFC 3207](https://www.rfc-editor.org/rfc/rfc3207.txt)), and MX certificates are often self-signed or privately issued ([RFC 7672](https://www.rfc-editor.org/rfc/rfc7672.txt), section 1.3.3). Requiring a verified certificate therefore gives `unknown` on many hosts. A verified certificate authenticates the MX host name, not the recipient domain, unless DNSSEC/DANE or MTA-STS ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461.txt)) is in place.
- **The receiver sees and judges the client.** Receivers check the connecting IP, its reverse DNS, the EHLO name, and the sender domain against blocklists before any message ([Spamhaus](https://docs.spamhaus.com/datasets/docs/source/40-real-world-usage/smtp/020-SMTP-Checks.html)); Gmail rejects clients without reverse DNS and throttles low-reputation ones ([Google](https://knowledge.workspace.google.com/admin/support/troubleshooting/gmail-smtp-errors-and-codes)). Spamhaus describes recipient verification against servers that disable `VRFY` as potentially hostile ([Spamhaus](https://www.spamhaus.org/resource-hub/deliverability/on-the-dubious-merits-of-email-verification-services)). Checking addresses you do not own can harm your own IP address and domain.

## Claims this project does not make

- That an accepted recipient proves the mailbox exists, is used, or will receive mail.
- That a 550, a timeout, or a TLS failure means the address is invalid.
- That it detects catch-all servers.
- That a probe is invisible: no message is sent, but the receiving server logs the connection and the recipient.
- That Active Mode works from typical home or cloud networks.
- Any accuracy percentage, or "more accurate than" another tool.
