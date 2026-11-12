from typing import List, Optional, Tuple

import pytest

from certipy.lib.certificate import create_csr_attributes
from certipy.lib.certighost import (
    EDITF_ENABLECHASECLIENTDC,
    is_certighost_build_vulnerable,
    parse_windows_build,
)
from certipy.lib.req import Request
from certipy.lib.target import DnsResolver, Target


def test_edit_flag_value():
    assert EDITF_ENABLECHASECLIENTDC == 0x00100000


@pytest.mark.parametrize(
    "build,expected",
    [
        ("20348.5386", (20348, 5386)),
        ("10.0.20348.5386", (20348, 5386)),
        ("20348", None),
        ("", None),
        ("a.b", None),
    ],
)
def test_parse_windows_build(build: str, expected: Optional[Tuple[int, int]]):
    assert parse_windows_build(build) == expected


@pytest.mark.parametrize(
    "build,expected",
    [
        ("20348.5385", True),  # Server 2022, below fixed revision
        ("20348.5386", False),  # exactly fixed
        ("20348.6000", False),  # above fixed
        ("26100.33157", True),  # Server 2025, below fixed
        ("26100.33158", False),  # Server 2025, fixed
        ("99999.1", None),  # unknown branch
        ("Unknown", None),
        ("20348", None),  # revision missing
    ],
)
def test_is_certighost_build_vulnerable(build: str, expected: Optional[bool]):
    assert is_certighost_build_vulnerable(build) is expected


def _target() -> Target:
    return Target(
        DnsResolver.create(),
        domain="CORP.LOCAL",
        username="alice",
        remote_name="ca.corp.local",
        target_ip="10.0.0.5",
    )


@pytest.mark.parametrize(
    "cdc,rmd,expected",
    [
        ("10.0.0.99", "dc01.corp.local", ["cdc:10.0.0.99", "rmd:dc01.corp.local"]),
        ("10.0.0.99", None, ["cdc:10.0.0.99"]),
        (None, None, []),
    ],
)
def test_request_builds_cdc_rmd_attributes(
    cdc: Optional[str], rmd: Optional[str], expected: List[str]
):
    request = Request(target=_target(), ca="CORP-CA", cdc=cdc, rmd=rmd)
    assert request.request_attributes == expected


def test_create_csr_attributes_appends_request_attributes():
    attributes = create_csr_attributes(
        "User", request_attributes=["cdc:10.0.0.99", "rmd:dc01.corp.local"]
    )
    assert attributes[0] == "CertificateTemplate:User"
    assert "cdc:10.0.0.99" in attributes
    assert "rmd:dc01.corp.local" in attributes
