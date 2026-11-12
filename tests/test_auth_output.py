"""Ticket output path for `auth` (upstream issue #352)."""

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional, cast

from certipy.commands.auth import Authenticate
from certipy.commands.parsers import ENTRY_PARSERS
from certipy.lib.target import Target


class FakeCCache:
    def getData(self) -> bytes:  # noqa: N802 - impacket's method name
        return b"ccache-bytes"

    def toKRBCRED(self) -> bytes:  # noqa: N802 - impacket's method name
        return b"kirbi-bytes"


def save(tmp: Path, out: Optional[str], kirbi: bool = False) -> Authenticate:
    auth = Authenticate(cast(Target, SimpleNamespace()), out=out, kirbi=kirbi)
    auth.save_ticket(cast(Any, FakeCCache()), "DC01$")
    return auth


def test_default_name_in_working_directory(tmp_cwd: Path):
    auth = save(tmp_cwd, None)
    assert (tmp_cwd / "DC01.ccache").read_bytes() == b"ccache-bytes"
    assert auth.ccache_name == "DC01.ccache"


def test_out_sets_ccache_path(tmp_cwd: Path):
    target = tmp_cwd / "tickets" / "dc01.ccache"
    target.parent.mkdir()
    auth = save(tmp_cwd, str(target))
    assert target.read_bytes() == b"ccache-bytes"
    assert auth.ccache_name == str(target)
    assert not (tmp_cwd / "DC01.ccache").exists()


def test_out_with_kirbi(tmp_cwd: Path):
    target = tmp_cwd / "admin.kirbi"
    save(tmp_cwd, str(target), kirbi=True)
    assert target.read_bytes() == b"kirbi-bytes"


def test_parser_accepts_out():
    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for entry_parser in ENTRY_PARSERS:
        entry_parser.add_subparser(subparsers)
    options = parser.parse_args(["auth", "-pfx", "a.pfx", "-out", "t.ccache"])
    assert options.out == "t.ccache"
