"""Template write-access detection in `find` (upstream issue #353)."""

from types import SimpleNamespace
from typing import Any, Set, cast

import pytest

from certipy.commands.find import Find
from certipy.lib.bloodhound_export import (
    ENROLL_GUID,
    PKI_ENROLLMENT_FLAG_GUID,
    PKI_NAME_FLAG_GUID,
)
from certipy.lib.constants import CertificateRights
from certipy.lib.ldap import LDAPEntry
from certipy.lib.security import CertificateSecurity
from certipy.lib.target import Target

from .test_bloodhound_export import (
    ADMINS,
    CA_MANAGERS,
    READ,
    USERS,
    WRITE,
    AceSpec,
    ace,
    build_sd,
)

ATTACKER = "S-1-5-21-1111-2222-3333-1104"


class FakeConnection:
    def __init__(self, user_sids: Set[str]):
        self.user_sids = user_sids

    def get_user_sids(self, *args: Any, **kwargs: Any) -> Set[str]:
        return self.user_sids

    def lookup_sid(self, sid: str) -> LDAPEntry:
        return LDAPEntry(attributes={"name": f"CORP\\{sid}", "objectSid": sid})


def make_find(user_sids: Set[str]) -> Find:
    find = Find(target=cast(Target, SimpleNamespace(username="attacker")))
    find._connection = FakeConnection(user_sids)  # type: ignore[assignment]
    return find


def template_with(*aces: AceSpec) -> LDAPEntry:
    return LDAPEntry(
        attributes={"nTSecurityDescriptor": build_sd(ADMINS, list(aces))},
        raw_attributes={},
    )


def test_read_write_without_enroll_is_reported_and_vulnerable():
    template = template_with(ace(CA_MANAGERS, READ | WRITE))
    find = make_find({CA_MANAGERS})

    controls = find.get_template_permissions(template)["Object Control Permissions"]
    assert controls["Write Property Principals"] == [f"CORP\\{CA_MANAGERS}"]

    vulnerable, sids = find.template_has_vulnerable_acl(template)
    assert vulnerable and sids == [CA_MANAGERS]


@pytest.mark.parametrize("attribute", [PKI_NAME_FLAG_GUID, PKI_ENROLLMENT_FLAG_GUID])
def test_single_pki_flag_write_is_vulnerable(attribute: str):
    template = template_with(ace(ATTACKER, 0x20, object_type=attribute))
    find = make_find({ATTACKER})

    vulnerable, _ = find.template_has_vulnerable_acl(template)
    assert vulnerable
    controls = find.get_template_permissions(template)["Object Control Permissions"]
    assert any(name.startswith("Write Property msPKI-") for name in controls)


def test_enroll_only_is_not_vulnerable_acl():
    template = template_with(ace(USERS, 0x100, object_type=ENROLL_GUID))
    find = make_find({USERS})

    vulnerable, _ = find.template_has_vulnerable_acl(template)
    assert not vulnerable
    controls = find.get_template_permissions(template)["Object Control Permissions"]
    assert "Write Property Principals" not in controls
    assert "Full Control Principals" not in controls


def test_typed_object_ace_does_not_widen_rights():
    # Write + control access scoped to one GUID must not read as object-wide write
    sd = build_sd(ADMINS, [ace(USERS, 0x20 | 0x100, object_type=ENROLL_GUID)])
    parsed = CertificateSecurity(sd).aces[USERS]
    assert CertificateRights.WRITE_PROPERTY not in parsed["rights"]
    assert parsed["extended_rights"] == [ENROLL_GUID]
    assert parsed["write_properties"] == [ENROLL_GUID]


def test_untyped_object_ace_applies_to_whole_object():
    sd = build_sd(ADMINS, [ace(USERS, CertificateRights.GENERIC_ALL, object_ace=True)])
    parsed = CertificateSecurity(sd).aces[USERS]
    assert CertificateRights.GENERIC_ALL in parsed["rights"]
