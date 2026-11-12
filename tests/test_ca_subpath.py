import argparse
from typing import Any, List, Optional
from unittest.mock import MagicMock

import httpx
import pytest

from certipy.commands.parsers import relay as relay_parser
from certipy.commands.parsers import req as req_parser
from certipy.lib.req import Request, web_retrieve
from certipy.lib.target import DnsResolver, Target


def _target() -> Target:
    return Target(
        DnsResolver.create(),
        domain="CORP.LOCAL",
        username="alice",
        remote_name="ca.corp.local",
        target_ip="10.0.0.5",
    )


@pytest.mark.parametrize(
    "given,stored",
    [(None, ""), ("", ""), ("/en-us/", "en-us"), ("en-us", "en-us")],
)
def test_request_normalises_ca_subpath(given: Optional[str], stored: str):
    request = Request(target=_target(), ca="CORP-CA", ca_subpath=given)
    assert request.ca_subpath == stored


@pytest.mark.parametrize(
    "ca_subpath,expected",
    [
        ("", "/certsrv/certnew.cer"),
        ("en-us", "/certsrv/en-us/certnew.cer"),
    ],
)
def test_web_retrieve_uses_subpath(ca_subpath: str, expected: str):
    captured: List[str] = []

    class FakeSession:
        def get(self, path: str, params: Any = None) -> httpx.Response:
            captured.append(path)
            return httpx.Response(404, text="")

    assert web_retrieve(FakeSession(), 7, ca_subpath) is None  # type: ignore[arg-type]
    assert captured == [expected]


@pytest.mark.parametrize(
    "ca_subpath,expected_page",
    [
        (None, "http://ca.corp.local/certsrv/certfnsh.asp"),
        ("/en-us/", "http://ca.corp.local/certsrv/en-us/certfnsh.asp"),
    ],
)
def test_relay_builds_target_with_subpath(
    ca_subpath: Optional[str],
    expected_page: str,
    monkeypatch: pytest.MonkeyPatch,
):
    from certipy.commands import relay as relay_module

    monkeypatch.setattr(relay_module, "SMBRelayServer", lambda config: MagicMock())
    monkeypatch.setattr(relay_module, "TargetsProcessor", lambda *a, **k: MagicMock())
    relay = relay_module.Relay(
        target="ca.corp.local", ca="CORP-CA", ca_subpath=ca_subpath
    )
    assert relay.target == expected_page


def test_parsers_accept_ca_subpath():
    req_parser_obj = argparse.ArgumentParser()
    req_parser.add_subparser(req_parser_obj.add_subparsers())
    options = req_parser_obj.parse_args(
        ["req", "-ca", "CORP-CA", "-ca-subpath", "en-us"]
    )
    assert options.ca_subpath == "en-us"

    relay_parser_obj = argparse.ArgumentParser()
    relay_parser.add_subparser(relay_parser_obj.add_subparsers())
    options = relay_parser_obj.parse_args(
        ["relay", "-target", "http://ca", "-ca-subpath", "en-us"]
    )
    assert options.ca_subpath == "en-us"
