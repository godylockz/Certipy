from typing import Any, Dict, List

import pytest

from certipy.commands.ca import CA
from certipy.lib.certificate import format_serial_number


class FakeCertAdmin:
    def __init__(self, error_code: int = 0) -> None:
        self.error_code = error_code
        self.requests: List[Any] = []

    def request(self, request: Any) -> Dict[str, int]:
        self.requests.append(request)
        return {"ErrorCode": self.error_code}


def _ca(serial_number: str, cert_admin: FakeCertAdmin) -> CA:
    ca = CA.__new__(CA)
    ca.ca = "CORP-CA"
    ca.serial_number = serial_number
    ca._cert_admin = cert_admin  # type: ignore[assignment]
    return ca


@pytest.mark.parametrize(
    "serial,expected",
    [(0x0A1B, "0a1b"), (0x6100000002, "6100000002"), (0x1, "01")],
)
def test_format_serial_number_keeps_whole_bytes(serial: int, expected: str):
    assert format_serial_number(serial) == expected


@pytest.mark.parametrize(
    "given",
    ["61:00:00:00:02", "61 00 00 00 02", "0x6100000002", "6100000002"],
)
def test_revoke_sends_normalised_serial(given: str):
    admin = FakeCertAdmin()
    assert _ca(given, admin).revoke() is True
    request = admin.requests[0]
    assert request["pwszSerialNumber"] == "6100000002\x00"
    assert request["pwszAuthority"] == "CORP-CA\x00"
    assert request["Reason"] == 0


def test_revoke_rejects_non_hex_serial():
    admin = FakeCertAdmin()
    assert _ca("not-a-serial", admin).revoke() is False
    assert admin.requests == []


def test_revoke_reports_ca_error():
    assert _ca("01", FakeCertAdmin(error_code=0x80094004)).revoke() is False
