"""The dnspython adapter's translation layer.

Library exceptions are raised locally by a stub. No resolver is constructed and
no packet is sent, so these tests say nothing about the network.
"""

from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.resolver
import pytest

from emailcheck.adapters.dns.dnspython_resolver import DNSPythonResolver, failure_for
from emailcheck.domain.dns import DNSFailure, HostName


@dataclass
class StubRdata:
    preference: int | None = None
    exchange: str | None = None
    address: str | None = None


@dataclass
class StubAnswer:
    items: list[StubRdata]
    ttl: int | None = 3600

    def __iter__(self) -> Any:
        return iter(self.items)


@dataclass
class StubResolver:
    """Stands in for `dns.asyncresolver.Resolver`, answering from memory.

    `use_search_by_default` mirrors the real attribute so a test can prove the
    adapter does not rely on it.
    """

    answer: StubAnswer | None = None
    exception: BaseException | None = None
    queries: list[tuple[str, Any]] = field(default_factory=list)
    keywords: list[dict[str, Any]] = field(default_factory=list)
    use_search_by_default: bool = False

    async def resolve(self, name: str, rdtype: Any, **kwargs: Any) -> StubAnswer:
        self.queries.append((name, rdtype))
        self.keywords.append(kwargs)
        if self.exception is not None:
            raise self.exception
        if self.answer is None:
            raise AssertionError("stub was asked for an answer it was not given")
        return self.answer


def adapter(stub: StubResolver) -> DNSPythonResolver:
    return DNSPythonResolver(resolver=stub)  # type: ignore[arg-type]


# --- exception mapping ----------------------------------------------------


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (dns.resolver.NXDOMAIN(), DNSFailure.NXDOMAIN),
        (dns.resolver.NoAnswer(), DNSFailure.NO_RECORDS),
        (dns.exception.Timeout(), DNSFailure.TIMEOUT),
        (dns.exception.FormError(), DNSFailure.MALFORMED),
        (dns.exception.SyntaxError(), DNSFailure.MALFORMED),
        (dns.exception.DNSException(), DNSFailure.MALFORMED),
    ],
)
def test_every_library_exception_maps_to_a_closed_failure_vocabulary(
    exception: dns.exception.DNSException, expected: DNSFailure
) -> None:
    assert failure_for(exception) is expected


@pytest.mark.asyncio
async def test_a_library_exception_never_escapes_the_adapter() -> None:
    stub = StubResolver(exception=dns.resolver.NXDOMAIN())
    result = await adapter(stub).query_mx(HostName("example.com"))

    assert result.failure is DNSFailure.NXDOMAIN
    assert result.records == ()


# --- this project's own failures are not the domain's ---------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [
        TypeError("resolve() got an unexpected keyword"),
        AttributeError("'NoneType' object has no attribute 'rdtype'"),
        RuntimeError("resolver blew up"),
        ValueError("bad internal state"),
        KeyError("missing"),
    ],
)
@pytest.mark.parametrize("method", ["query_mx", "query_a", "query_aaaa"])
async def test_a_defect_in_this_project_is_reported_as_an_internal_error(
    exception: Exception, method: str
) -> None:
    """Our bug must not be published as the customer domain's misconfiguration."""
    stub = StubResolver(exception=exception)
    result = await getattr(adapter(stub), method)(HostName("example.com"))

    assert result.failure is DNSFailure.INTERNAL_ERROR
    assert result.failure.is_internal is True
    assert result.failure is not DNSFailure.MALFORMED
    assert result.failure.is_authoritative_absence is False


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["query_mx", "query_a", "query_aaaa"])
async def test_an_assertion_error_is_re_raised_not_converted(method: str) -> None:
    """Test guards and internal assertions must never become a DNS result."""
    stub = StubResolver(exception=AssertionError("network guard tripped"))
    with pytest.raises(AssertionError, match="network guard tripped"):
        await getattr(adapter(stub), method)(HostName("example.com"))


@pytest.mark.asyncio
async def test_an_internal_error_carries_no_exception_text() -> None:
    stub = StubResolver(exception=RuntimeError("nameserver 10.0.0.1 exploded for bob@example.com"))
    result = await adapter(stub).query_mx(HostName("example.com"))

    rendered = repr(result)
    assert "10.0.0.1" not in rendered
    assert "bob@example.com" not in rendered
    assert "exploded" not in rendered


@pytest.mark.asyncio
async def test_no_library_message_reaches_the_result() -> None:
    """The result carries this project's vocabulary, not the library's text.

    `DNSFailure.SERVFAIL` is our own member name, so the check looks for the
    parts of the message only dnspython would produce: the nameserver address
    and its wording.
    """
    message = "All nameservers failed to answer: nameserver 10.0.0.1 refused the query"
    stub = StubResolver(exception=dns.resolver.NoNameservers(message))
    result = await adapter(stub).query_mx(HostName("example.com"))

    rendered = repr(result)
    assert "10.0.0.1" not in rendered
    assert "nameserver" not in rendered
    assert "refused the query" not in rendered
    assert result.failure is DNSFailure.SERVFAIL


# --- answer translation ---------------------------------------------------


@pytest.mark.asyncio
async def test_mx_answers_become_typed_records() -> None:
    stub = StubResolver(
        answer=StubAnswer(
            items=[
                StubRdata(preference=10, exchange="mx1.example.com."),
                StubRdata(preference=20, exchange="mx2.example.com."),
            ]
        )
    )
    result = await adapter(stub).query_mx(HostName("example.com"))

    assert [(r.preference, r.exchange) for r in result.records] == [
        (10, "mx1.example.com."),
        (20, "mx2.example.com."),
    ]
    assert result.failure is None
    assert result.ttl is not None
    assert result.ttl.applied_seconds == 3600


@pytest.mark.asyncio
async def test_an_empty_answer_is_an_absence_not_a_success() -> None:
    stub = StubResolver(answer=StubAnswer(items=[]))
    result = await adapter(stub).query_mx(HostName("example.com"))
    assert result.failure is DNSFailure.NO_RECORDS
    assert result.records == ()


@pytest.mark.asyncio
async def test_address_answers_become_plain_text_for_the_policy_to_judge() -> None:
    stub = StubResolver(answer=StubAnswer(items=[StubRdata(address="93.184.216.34")]))
    result = await adapter(stub).query_a(HostName("mx.example.com"))
    assert result.addresses == ("93.184.216.34",)


@pytest.mark.asyncio
async def test_a_served_ttl_above_the_cap_is_clamped_by_the_adapter() -> None:
    stub = StubResolver(
        answer=StubAnswer(items=[StubRdata(address="93.184.216.34")], ttl=60 * 60 * 48)
    )
    result = await adapter(stub).query_a(HostName("mx.example.com"))
    assert result.ttl is not None
    assert result.ttl.applied_seconds == 24 * 60 * 60
    assert result.ttl.was_capped is True


@pytest.mark.asyncio
async def test_a_missing_ttl_falls_back_without_failing() -> None:
    stub = StubResolver(answer=StubAnswer(items=[StubRdata(address="93.184.216.34")], ttl=None))
    result = await adapter(stub).query_a(HostName("mx.example.com"))
    assert result.ttl is not None
    assert result.ttl.was_supplied is False


@pytest.mark.asyncio
async def test_the_adapter_asks_for_the_host_as_an_absolute_name() -> None:
    stub = StubResolver(answer=StubAnswer(items=[StubRdata(address="93.184.216.34")]))
    await adapter(stub).query_aaaa(HostName("mx.example.com"))
    assert stub.queries[0][0] == "mx.example.com."


# --- the search list can never redirect a query ---------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["query_mx", "query_a", "query_aaaa"])
async def test_every_query_disables_the_search_list(method: str) -> None:
    """Otherwise `example.com` could silently become `example.com.corp.internal`.

    The stub advertises `use_search_by_default = True`, which is what a
    misconfigured injected resolver would look like. The adapter must pass
    `search=False` regardless.
    """
    stub = StubResolver(answer=StubAnswer(items=[StubRdata(preference=10, exchange="mx.a.com.")]))
    stub.use_search_by_default = True

    await getattr(adapter(stub), method)(HostName("example.com"))
    assert stub.keywords[0]["search"] is False


# --- REFUSED is read from the structured rcode, never from text -----------


class StubResponse:
    """A response message carrying only the one thing that is a contract."""

    def __init__(self, rcode: int) -> None:
        self._rcode = rcode

    def rcode(self) -> int:
        return self._rcode


def no_nameservers(*rcodes: int) -> dns.resolver.NoNameservers:
    exception = dns.resolver.NoNameservers.__new__(dns.resolver.NoNameservers)
    exception.kwargs = {  # type: ignore[attr-defined]
        "errors": [
            ("192.0.2.1", False, 53, "text that must not be parsed", StubResponse(code))
            for code in rcodes
        ]
    }
    return exception


def test_a_unanimous_refusal_is_reported_as_refused() -> None:
    assert failure_for(no_nameservers(dns.rcode.REFUSED)) is DNSFailure.REFUSED
    assert failure_for(no_nameservers(dns.rcode.REFUSED, dns.rcode.REFUSED)) is DNSFailure.REFUSED


@pytest.mark.parametrize(
    "rcodes",
    [
        (dns.rcode.SERVFAIL,),
        (dns.rcode.REFUSED, dns.rcode.SERVFAIL),
        (dns.rcode.SERVFAIL, dns.rcode.REFUSED),
        (dns.rcode.NOTIMP,),
    ],
)
def test_anything_less_than_unanimous_stays_a_retryable_servfail(rcodes: tuple[int, ...]) -> None:
    assert failure_for(no_nameservers(*rcodes)) is DNSFailure.SERVFAIL


def test_a_refusal_without_structured_responses_falls_back_to_servfail() -> None:
    """No structured rcode means no claim: the text is never parsed."""
    exception = dns.resolver.NoNameservers.__new__(dns.resolver.NoNameservers)
    exception.kwargs = {"errors": [("192.0.2.1", False, 53, "REFUSED", None)]}  # type: ignore[attr-defined]
    assert failure_for(exception) is DNSFailure.SERVFAIL

    empty = dns.resolver.NoNameservers.__new__(dns.resolver.NoNameservers)
    empty.kwargs = {"errors": []}  # type: ignore[attr-defined]
    assert failure_for(empty) is DNSFailure.SERVFAIL
