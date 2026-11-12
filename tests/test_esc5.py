import datetime
import uuid

from cryptography import x509
from impacket.ldap import ldaptypes

from certipy.commands.esc5 import classify_ace, generate_rogue_ca
from certipy.lib.constants import ActiveDirectoryRights
from certipy.lib.security import INHERITED_ACE

SID = "S-1-5-21-1-2-3-1105"
CACERT_GUID = uuid.uuid4().bytes


def _allow_ace(sid: str, mask: int, inherited: bool = False) -> ldaptypes.ACE:
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = INHERITED_ACE if inherited else 0x00
    body = ldaptypes.ACCESS_ALLOWED_ACE()
    body["Mask"] = ldaptypes.ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["Sid"] = ldaptypes.LDAP_SID()
    body["Sid"].fromCanonical(sid)
    ace["Ace"] = body
    return ace


def _object_ace(sid: str, mask: int, object_type: bytes) -> ldaptypes.ACE:
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = 0x00
    body = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    body["Mask"] = ldaptypes.ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["ObjectType"] = object_type
    body["InheritedObjectType"] = b""
    body["Flags"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    body["Sid"] = ldaptypes.LDAP_SID()
    body["Sid"].fromCanonical(sid)
    ace["Ace"] = body
    return ace


def _classify(ace: ldaptypes.ACE, check_cacert: bool, check_create_child: bool):
    return classify_ace(ace, CACERT_GUID, check_cacert, check_create_child)


def test_generic_all_is_flagged_on_any_object():
    assert _classify(
        _allow_ace(SID, ActiveDirectoryRights.GENERIC_ALL), False, False
    ) == (SID, False, "GenericAll")


def test_inherited_flag_is_preserved():
    sid, inherited, right = _classify(
        _allow_ace(SID, ActiveDirectoryRights.WRITE_DACL, inherited=True), False, False
    )
    assert (sid, inherited, right) == (SID, True, "WriteDacl")


def test_plain_write_property_without_scope_is_ignored():
    # Unscoped WriteProperty is not dangerous here; only the generic rights are
    assert _classify(
        _allow_ace(SID, ActiveDirectoryRights.WRITE_PROPERTY), True, False
    ) == (None, False, None)


def test_create_child_only_counts_on_containers():
    ace = _allow_ace(SID, ActiveDirectoryRights.CREATE_CHILD)
    assert _classify(ace, False, True) == (SID, False, "CreateChild")
    assert _classify(ace, False, False) == (None, False, None)


def test_write_property_scoped_to_cacert_is_flagged():
    ace = _object_ace(SID, ActiveDirectoryRights.WRITE_PROPERTY, CACERT_GUID)
    assert _classify(ace, True, False) == (SID, False, "WriteProperty(cACertificate)")


def test_write_property_scoped_to_other_attribute_is_ignored():
    ace = _object_ace(SID, ActiveDirectoryRights.WRITE_PROPERTY, uuid.uuid4().bytes)
    assert _classify(ace, True, False) == (None, False, None)


def test_cacert_scoped_ace_skipped_when_guid_unresolved():
    ace = _object_ace(SID, ActiveDirectoryRights.WRITE_PROPERTY, CACERT_GUID)
    assert classify_ace(ace, None, True, False) == (None, False, None)


def test_denied_ace_is_ignored():
    ace = _allow_ace(SID, ActiveDirectoryRights.GENERIC_ALL)
    ace["AceType"] = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
    assert _classify(ace, False, False) == (None, False, None)


def test_generate_rogue_ca_is_a_ca_certificate():
    _key, cert = generate_rogue_ca("CN=Rogue", key_size=2048, validity_period=365)
    assert cert.subject.rfc4514_string() == "CN=Rogue"
    assert cert.issuer == cert.subject
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_cert_sign is True
    delta = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert delta >= datetime.timedelta(days=365)


def test_generate_rogue_ca_defaults_subject():
    _, cert = generate_rogue_ca(None, key_size=2048, validity_period=1)
    assert cert.subject.rfc4514_string().startswith("CN=ESC5-PoC-CA-")
