"""Clock skew detection from KRB-ERROR packets (upstream issue #332)."""

import datetime
from typing import Any, Optional, cast

import pytest
from impacket.krb5.asn1 import KRB_ERROR
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.types import KerberosTime

from certipy.lib.kerberos import KRB_CLOCK_SKEW, clock_skew_message, kdc_clock_skew

# Protocol numbers (RFC 4120, RFC 4556)
KRB_ERROR_MSG_TYPE = 30
NT_SRV_INST = 2
SKEW = 37  # KRB_AP_ERR_SKEW
CLIENT_NOT_TRUSTED = 62  # KDC_ERR_CLIENT_NOT_TRUSTED

NOW = datetime.datetime(2026, 11, 12, 18, 0, 0, tzinfo=datetime.timezone.utc)


def krb_error(
    code: int, server_time: Optional[datetime.datetime], susec: int = 0
) -> KerberosError:
    packet = KRB_ERROR()
    packet["pvno"] = 5
    packet["msg-type"] = KRB_ERROR_MSG_TYPE
    if server_time is not None:
        packet["stime"] = KerberosTime.to_asn1(server_time)
        packet["susec"] = susec
    packet["error-code"] = code
    packet["realm"] = "CORP.LOCAL"
    packet["sname"]["name-type"] = NT_SRV_INST
    packet["sname"]["name-string"][0] = "krbtgt"
    packet["sname"]["name-string"][1] = "CORP.LOCAL"
    return KerberosError(packet=cast(Any, packet))


@pytest.mark.parametrize("offset", [-900, -30, 0, 45, 3600])
def test_skew_is_measured_from_server_time(offset: int):
    error = krb_error(SKEW, NOW + datetime.timedelta(seconds=offset), susec=250000)
    assert kdc_clock_skew(error, NOW) == pytest.approx(offset + 0.25)


def test_skew_reported_even_when_kdc_says_client_not_trusted():
    # Issue #332: the KDC answered a skewed PKINIT request with CLIENT_NOT_TRUSTED
    error = krb_error(CLIENT_NOT_TRUSTED, NOW + datetime.timedelta(minutes=20))
    message = clock_skew_message(error, NOW)
    assert message is not None
    assert "1200 seconds behind the KDC" in message
    assert str(KRB_CLOCK_SKEW) in message


def test_local_clock_ahead_of_kdc():
    message = clock_skew_message(
        krb_error(SKEW, NOW - datetime.timedelta(minutes=10)), NOW
    )
    assert message is not None and "ahead of the KDC" in message


def test_no_message_within_tolerance():
    error = krb_error(CLIENT_NOT_TRUSTED, NOW + datetime.timedelta(seconds=120))
    assert clock_skew_message(error, NOW) is None


def test_errors_without_a_packet_are_ignored():
    assert kdc_clock_skew(KerberosError(error=SKEW), NOW) is None
    assert clock_skew_message(KerberosError(error=SKEW), NOW) is None
