"""A small upstream regression; no DNS, zone loading, or large allocation."""

import dns.exception
import dns.rdata
import pytest


def test_wks_parser_rejects_service_number_outside_bitmap_range() -> None:
    # The upstream CVE-2026-128089 example, at the first invalid value only.
    # This consumed a small bitmap under 2.8.0 instead of rejecting the input.
    with pytest.raises(dns.exception.SyntaxError):
        dns.rdata.from_text("IN", "WKS", "10.0.0.1 udp 65536")
