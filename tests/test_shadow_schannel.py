import argparse
from pathlib import Path
from typing import Any, List

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from certipy.commands import shadow as shadow_module
from certipy.commands.parsers import shadow as shadow_parser
from certipy.commands.shadow import Shadow
from certipy.lib.certificate import create_pfx
from certipy.lib.target import DnsResolver, Target


def _parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    shadow_parser.add_subparser(parser.add_subparsers())
    return parser.parse_args(["shadow", "list", *argv])


def _target() -> Target:
    return Target(
        DnsResolver.create(),
        domain="CORP.LOCAL",
        username="alice",
        target_ip="10.0.0.10",
    )


def test_parser_maps_pfx_to_schannel_options():
    options = _parse("-pfx", "alice.pfx", "-pfx-password", "secret")
    assert options.schannel_pfx == "alice.pfx"
    assert options.pfx_password == "secret"


def test_shadow_connects_with_schannel_certificate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    make_cert: Any,
):
    cert: x509.Certificate = make_cert()
    pfx = tmp_path / "alice.pfx"
    pfx.write_bytes(create_pfx(rsa_key, cert, "secret"))
    seen: List[Any] = []

    class FakeLDAPConnection:
        def __init__(self, target: Target, schannel_auth: Any = None) -> None:
            seen.append(schannel_auth)

        def connect(self) -> None:
            pass

    monkeypatch.setattr(shadow_module, "LDAPConnection", FakeLDAPConnection)
    shadow = Shadow(_target(), "bob", schannel_pfx=str(pfx), pfx_password="secret")
    _ = shadow.connection
    cert_used, key_used = seen[0]
    assert cert_used == cert
    assert key_used.private_numbers() == rsa_key.private_numbers()


def test_shadow_without_pfx_uses_credentials(monkeypatch: pytest.MonkeyPatch):
    seen: List[Any] = []

    class FakeLDAPConnection:
        def __init__(self, target: Target, schannel_auth: Any = None) -> None:
            seen.append(schannel_auth)

        def connect(self) -> None:
            pass

    monkeypatch.setattr(shadow_module, "LDAPConnection", FakeLDAPConnection)
    _ = Shadow(_target(), "bob").connection
    assert seen == [None]
