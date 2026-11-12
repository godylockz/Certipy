from typing import Any, Dict, List

import ldap3
import pytest

from certipy.lib import ldap as ldap_module
from certipy.lib.ldap import LDAPConnection
from certipy.lib.target import DnsResolver, Target


class StopAfterConnectError(Exception):
    pass


def _target(**overrides: Any) -> Target:
    values: Dict[str, Any] = dict(
        domain="CORP.LOCAL",
        username="lowpriv",
        password="Passw0rd!",
        remote_name="dc01.corp.local",
        target_ip="10.0.0.10",
        ldap_scheme="ldap+starttls",
        ldap_port=389,
    )
    values.update(overrides)
    return Target(DnsResolver.create(), **values)


class FakeConnection:
    def __init__(self, calls: List[str], start_tls_ok: bool) -> None:
        self.calls = calls
        self.start_tls_ok = start_tls_ok
        self.bound = False
        self.closed = True
        self.last_error = "startTLS failed - unavailable"
        self.result: Dict[str, Any] = {}

    def open(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append("open")
        self.closed = False

    def start_tls(self) -> bool:
        self.calls.append("start_tls")
        return self.start_tls_ok

    def bind(self) -> bool:
        self.calls.append("bind")
        raise StopAfterConnectError


def _patch_connection(monkeypatch: pytest.MonkeyPatch, start_tls_ok: bool) -> List[str]:
    calls: List[str] = []
    monkeypatch.setattr(
        ldap_module,
        "ExtendedLdapConnection",
        lambda *args, **kwargs: FakeConnection(calls, start_tls_ok),
    )
    return calls


def test_starttls_scheme_uses_plain_port_and_no_ldaps():
    connection = LDAPConnection(_target())
    assert connection.use_starttls is True
    assert connection.use_ssl is False
    assert connection.port == 389


def test_starttls_runs_before_ntlm_bind(monkeypatch: pytest.MonkeyPatch):
    calls = _patch_connection(monkeypatch, start_tls_ok=True)
    with pytest.raises(StopAfterConnectError):
        LDAPConnection(_target()).connect()
    assert calls == ["open", "start_tls", "bind"]


def test_starttls_failure_stops_before_bind(monkeypatch: pytest.MonkeyPatch):
    calls = _patch_connection(monkeypatch, start_tls_ok=False)
    with pytest.raises(Exception, match="StartTLS failed"):
        LDAPConnection(_target()).connect()
    assert "bind" not in calls


def test_schannel_starttls_binds_with_sasl_external(
    monkeypatch: pytest.MonkeyPatch,
    make_cert: Any,
    rsa_key: Any,
):
    seen: Dict[str, Any] = {}

    def fake_connection(server: ldap3.Server, **kwargs: Any) -> Any:
        seen["ssl"] = server.ssl
        seen.update(kwargs)
        raise StopAfterConnectError

    monkeypatch.setattr(ldap_module.ldap3, "Connection", fake_connection)
    connection = LDAPConnection(_target(), schannel_auth=(make_cert(), rsa_key))
    with pytest.raises(StopAfterConnectError):
        connection.connect()
    assert seen["ssl"] is False
    assert seen["sasl_mechanism"] == ldap3.EXTERNAL
    assert seen["auto_bind"] == ldap3.AUTO_BIND_TLS_BEFORE_BIND
