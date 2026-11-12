import argparse
from typing import Any, Dict, List, Optional, Tuple, cast

import pytest

from certipy.commands.parsers import template as template_parser
from certipy.commands.template import Template
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.target import DnsResolver, Target

CONFIG = "CN=Configuration,DC=corp,DC=local"
TEMPLATES = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{CONFIG}"
OID_CONTAINER = f"CN=OID,CN=Public Key Services,CN=Services,{CONFIG}"
FOREST_OID = "1.3.6.1.4.1.311.21.8.1.2.3"
SOURCE_SD = b"\x01\x00\x04\x8c" + b"\x00" * 16

SOURCE_ATTRIBUTES: Dict[str, Any] = {
    "cn": "User",
    "name": "User",
    "displayName": "User",
    "objectClass": ["top", "pKICertificateTemplate"],
    "objectGUID": "{00000000-0000-0000-0000-000000000000}",
    "whenCreated": "20260101000000.0Z",
    "distinguishedName": f"CN=User,{TEMPLATES}",
    "msPKI-Cert-Template-OID": "1.3.6.1.4.1.311.21.8.1.2.3.1",
    "revision": 100,
    "msPKI-Template-Schema-Version": 1,
    "msPKI-Template-Minor-Revision": 4,
    "flags": 66106,
    "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
    "nTSecurityDescriptor": SOURCE_SD,
}


def _entry(attributes: Dict[str, Any], dn: str) -> LDAPEntry:
    return LDAPEntry(dn=dn, attributes=dict(attributes), raw_attributes={})


class FakeConnection:
    configuration_path = CONFIG

    def __init__(self, existing: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.objects: Dict[str, Dict[str, Any]] = {
            f"CN=User,{TEMPLATES}": dict(SOURCE_ATTRIBUTES)
        }
        self.objects.update(existing or {})
        self.adds: List[Tuple[str, List[str], Dict[str, Any]]] = []
        self.modifies: List[Tuple[str, Dict[str, Any]]] = []

    def search(
        self, search_filter: str, search_base: str = "", **kwargs: Any
    ) -> List[LDAPEntry]:
        if search_base == OID_CONTAINER:
            return [_entry({"msPKI-Cert-Template-OID": FOREST_OID}, OID_CONTAINER)]
        if search_filter.startswith("(msPKI-Cert-Template-OID="):
            oid = search_filter[len("(msPKI-Cert-Template-OID=") : -1]
            return [
                _entry(a, dn)
                for dn, a in self.objects.items()
                if a.get("msPKI-Cert-Template-OID") == oid
            ]
        if search_base in self.objects:
            return [_entry(self.objects[search_base], search_base)]
        for dn, attributes in self.objects.items():
            if f"(cn={attributes['cn']})" in search_filter:
                return [_entry(attributes, dn)]
        return []

    def add(self, dn: str, object_class: List[str], attributes: Dict[str, Any]) -> Any:
        self.adds.append((dn, object_class, attributes))
        created = dict(attributes)
        created["objectClass"] = object_class
        created["name"] = attributes["cn"]
        self.objects[dn] = created
        return {"result": 0}

    def modify(self, dn: str, changes: Dict[str, Any], **kwargs: Any) -> Any:
        self.modifies.append((dn, changes))
        return {"result": 0}


def _template(fake: FakeConnection, **kwargs: Any) -> Template:
    target = Target(DnsResolver.create(), domain="CORP.LOCAL", username="alice")
    return Template(
        target,
        template="New Template",
        create=True,
        source_template="User",
        force=True,
        connection=cast(LDAPConnection, fake),
        **kwargs,
    )


@pytest.mark.parametrize("oid", ["1.2.840.113549", "2.999.1", "0.39.5"])
def test_validate_template_oid_accepts(oid: str):
    Template._validate_template_oid(oid)


@pytest.mark.parametrize("oid", ["1.40.1", "3.1", "1.02.3", "1", "1.2.", "a.b"])
def test_validate_template_oid_rejects(oid: str):
    with pytest.raises(ValueError):
        Template._validate_template_oid(oid)


def test_create_clones_source_with_new_identity():
    fake = FakeConnection()
    assert _template(fake).create() is True

    ((dn, object_class, attributes),) = fake.adds
    assert dn == f"CN=New Template,{TEMPLATES}"
    assert object_class == ["top", "pKICertificateTemplate"]
    assert attributes["cn"] == attributes["displayName"] == "New Template"
    assert attributes["msPKI-Cert-Template-OID"].startswith(FOREST_OID + ".")
    assert attributes["flags"] == 66106
    for key in (
        "name",
        "objectGUID",
        "whenCreated",
        "objectClass",
        "distinguishedName",
        "nTSecurityDescriptor",
    ):
        assert key not in attributes
    # The DACL goes in a separate modify after the ADD
    ((sd_dn, changes),) = fake.modifies
    assert sd_dn == dn
    assert changes["nTSecurityDescriptor"][0][1] == [SOURCE_SD]


def test_create_refuses_existing_template():
    fake = FakeConnection(
        {f"CN=New Template,{TEMPLATES}": dict(SOURCE_ATTRIBUTES, cn="New Template")}
    )
    assert _template(fake).create() is False
    assert fake.adds == []


def test_create_refuses_explicit_oid_in_use():
    fake = FakeConnection()
    template = _template(fake, template_oid="1.3.6.1.4.1.311.21.8.1.2.3.1")
    assert template.create() is False
    assert fake.adds == []


def test_create_with_default_configuration_is_authoritative():
    fake = FakeConnection()
    assert _template(fake, write_default_configuration="S-1-5-11").create() is True
    ((_, _, attributes),) = fake.adds
    # ESC1 configuration replaces the cloned flags; versions come from the source
    assert attributes["msPKI-Certificate-Name-Flag"] == 1
    assert attributes["revision"] == 100
    assert "pKIExtendedKeyUsage" in attributes


def _parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    template_parser.add_subparser(parser.add_subparsers())
    return parser.parse_args(["template", "-template", "New", *argv])


@pytest.mark.parametrize(
    "argv",
    [
        ("-create",),
        ("-source-template", "User"),
        ("-template-oid", "1.2.3"),
        ("-create", "-source-template", "User", "-no-save"),
    ],
)
def test_parser_rejects_invalid_creation_combinations(argv: Tuple[str, ...]):
    with pytest.raises(ValueError):
        template_parser.validate_options(_parse(*argv))
