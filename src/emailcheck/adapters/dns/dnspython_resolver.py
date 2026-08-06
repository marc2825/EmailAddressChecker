"""The dnspython adapter.

The only job here is translation: ask the library, convert what comes back into
this project's types, and convert every library exception into a `DNSFailure`.
No routing decision and no address judgment belongs in this file.

A library message is never kept. Callers get a member of a closed enum, so a
change in dnspython's wording cannot alter a public result or leak into an API
response. See ADR 0006.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

import dns.asyncresolver
import dns.exception
import dns.rcode
import dns.rdatatype
import dns.resolver

from emailcheck.domain.dns import (
    MAX_CNAME_CHAIN_LENGTH,
    AddressLookup,
    CNAMEChain,
    DNSFailure,
    HostName,
    MXLookup,
    MXRecord,
    apply_ttl_policy,
)

#: Every dnspython exception this adapter understands, most specific first.
#: A `DNSException` this project has not seen is a malformed answer; anything
#: that is not a `DNSException` at all is this project's own failure and is
#: handled separately.
_EXCEPTION_FAILURES: Final[tuple[tuple[type[dns.exception.DNSException], DNSFailure], ...]] = (
    (dns.resolver.NXDOMAIN, DNSFailure.NXDOMAIN),
    (dns.resolver.NoAnswer, DNSFailure.NO_RECORDS),
    (dns.resolver.LifetimeTimeout, DNSFailure.TIMEOUT),
    (dns.exception.Timeout, DNSFailure.TIMEOUT),
    (dns.resolver.YXDOMAIN, DNSFailure.MALFORMED),
    (dns.resolver.NoRootSOA, DNSFailure.MALFORMED),
    (dns.exception.FormError, DNSFailure.MALFORMED),
    (dns.exception.SyntaxError, DNSFailure.MALFORMED),
)


def _refused_or_servfail(exception: dns.resolver.NoNameservers) -> DNSFailure:
    """Tell a refusal from a server failure using the structured rcode.

    dnspython folds every non-NOERROR rcode into `NoNameservers`. Each entry it
    records carries the response message, so the rcode is read from the message
    itself. The human-readable text in the same entry is never parsed: it is
    free to change and is not a contract.

    Only a unanimous refusal is reported as one. A mixed answer stays
    `SERVFAIL`, which is retryable, because that is the conservative reading.
    """
    errors = exception.kwargs.get("errors") if hasattr(exception, "kwargs") else None
    if not isinstance(errors, list) or not errors:
        return DNSFailure.SERVFAIL

    rcodes: list[int] = []
    for entry in errors:
        response = entry[4] if isinstance(entry, tuple) and len(entry) >= 5 else None
        rcode = getattr(response, "rcode", None)
        if not callable(rcode):
            return DNSFailure.SERVFAIL
        try:
            rcodes.append(int(rcode()))
        except (TypeError, ValueError):
            return DNSFailure.SERVFAIL

    if rcodes and all(code == dns.rcode.REFUSED for code in rcodes):
        return DNSFailure.REFUSED
    return DNSFailure.SERVFAIL


def failure_for(exception: dns.exception.DNSException) -> DNSFailure:
    """Map a dnspython exception onto a closed failure vocabulary."""
    if isinstance(exception, dns.resolver.NoNameservers):
        return _refused_or_servfail(exception)
    for exception_type, failure in _EXCEPTION_FAILURES:
        if isinstance(exception, exception_type):
            return failure
    return DNSFailure.MALFORMED


def _chain_from_answer(answer: Any) -> CNAMEChain:
    """Collect CNAME names, bounded, ignoring anything unexpected."""
    names: list[HostName] = []
    try:
        cnames = list(getattr(answer.chaining_result, "cnames", []))
    except AttributeError:  # pragma: no cover - older or stubbed answers
        return CNAMEChain()
    for record_set in cnames[:MAX_CNAME_CHAIN_LENGTH]:
        host = HostName.normalize(str(getattr(record_set, "name", "")))
        if host is not None:
            names.append(host)
    return CNAMEChain(names=tuple(names), truncated=len(cnames) > MAX_CNAME_CHAIN_LENGTH)


def _ttl_of(answer: Any, *, positive: bool) -> Any:
    raw = getattr(answer, "ttl", None)
    ttl_seconds = raw if isinstance(raw, int) else None
    return apply_ttl_policy(ttl_seconds, positive=positive)


@dataclass(frozen=True, slots=True)
class DNSPythonResolver:
    """Adapter implementing the `DNSResolver` port with dnspython.

    The resolver instance is injected so a deployment can pin nameservers and
    timeouts, and so no test can accidentally use the system resolver.
    """

    resolver: dns.asyncresolver.Resolver = field(
        default_factory=dns.asyncresolver.Resolver  # pragma: no cover - deployment default
    )
    lifetime_seconds: float = 5.0

    async def _resolve(self, name: HostName, rdtype: Any) -> Any:
        """Ask the resolver for one record type.

        `search=False` is passed on every call. Without it the answer would
        depend on the injected resolver's `use_search_by_default` and on the
        host's `/etc/resolv.conf` search list, so `example.com` could silently
        become `example.com.corp.internal` and a probe could reach an internal
        domain. The query name is also made absolute for the same reason.
        """
        return await self.resolver.resolve(
            f"{name.value}.",
            rdtype,
            lifetime=self.lifetime_seconds,
            search=False,
        )

    async def query_mx(self, domain: HostName) -> MXLookup:
        try:
            answer = await self._resolve(domain, dns.rdatatype.MX)
        except dns.exception.DNSException as exception:
            return MXLookup(failure=failure_for(exception), ttl=_ttl_of(None, positive=False))
        except AssertionError:
            # A failed assertion is this project's own, or a test guard saying
            # the network was touched. Never convert it into a DNS result.
            raise
        except Exception:
            # A defect here is ours. Reporting it as a malformed answer would
            # blame the domain being checked for our bug.
            return MXLookup(failure=DNSFailure.INTERNAL_ERROR, ttl=_ttl_of(None, positive=False))

        records: list[MXRecord] = []
        for item in answer:
            preference = getattr(item, "preference", None)
            exchange = getattr(item, "exchange", None)
            if preference is None or exchange is None:
                continue
            records.append(MXRecord(preference=int(preference), exchange=str(exchange)))
        if not records:
            return MXLookup(failure=DNSFailure.NO_RECORDS, ttl=_ttl_of(answer, positive=False))
        return MXLookup(
            records=tuple(records),
            ttl=_ttl_of(answer, positive=True),
            cname_chain=_chain_from_answer(answer),
        )

    async def query_a(self, host: HostName) -> AddressLookup:
        return await self._query_addresses(host, dns.rdatatype.A)

    async def query_aaaa(self, host: HostName) -> AddressLookup:
        return await self._query_addresses(host, dns.rdatatype.AAAA)

    async def _query_addresses(self, host: HostName, rdtype: Any) -> AddressLookup:
        try:
            answer = await self._resolve(host, rdtype)
        except dns.exception.DNSException as exception:
            return AddressLookup(failure=failure_for(exception), ttl=_ttl_of(None, positive=False))
        except AssertionError:
            raise
        except Exception:
            return AddressLookup(
                failure=DNSFailure.INTERNAL_ERROR, ttl=_ttl_of(None, positive=False)
            )

        addresses = tuple(str(getattr(item, "address", "")) for item in answer)
        addresses = tuple(address for address in addresses if address)
        if not addresses:
            return AddressLookup(failure=DNSFailure.NO_RECORDS, ttl=_ttl_of(answer, positive=False))
        return AddressLookup(
            addresses=addresses,
            ttl=_ttl_of(answer, positive=True),
            cname_chain=_chain_from_answer(answer),
        )
