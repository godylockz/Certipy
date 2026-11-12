import io
import json
import zipfile
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin

from certipy.commands.ca import EnrollmentAgentRestriction
from certipy.lib.bloodhound_export import (
    DEFAULT_CLASS_GUIDS,
    ENROLL_GUID,
    PKI_ENROLLMENT_FLAG_GUID,
    PKI_NAME_FLAG_GUID,
    CEExporter,
    CertificateInfo,
    build_chain,
    legacy_node,
    parse_aces,
    ra_application_policies,
    template_properties,
    write_zip,
)
from certipy.lib.constants import CertificateRights
from certipy.lib.ldap import LDAPEntry
from certipy.lib.security import CASecurity

from .conftest import CertFactory

EntryFactory = Callable[..., LDAPEntry]

DOMAIN_SID = "S-1-5-21-1111-2222-3333"
USERS = f"{DOMAIN_SID}-513"
ADMINS = f"{DOMAIN_SID}-512"
CA_MANAGERS = f"{DOMAIN_SID}-1105"
TEMPLATE_CLASS = DEFAULT_CLASS_GUIDS["pKICertificateTemplate"]
OTHER_CLASS = "bf967aba-0de6-11d0-a285-00aa003049e2"  # user

READ = 0x00020094
WRITE = 0x00020028

AceSpec = Dict[str, Any]


def resolve(sid: str) -> Tuple[str, str]:
    if sid == "S-1-5-11":
        return "CORP.LOCAL-S-1-5-11", "Group"
    return sid, "Group"


def ace(
    sid: str,
    mask: int,
    object_type: Optional[str] = None,
    inherited_object_type: Optional[str] = None,
    flags: int = 0,
    object_ace: bool = False,
) -> AceSpec:
    return {
        "sid": sid,
        "mask": mask,
        "object_type": object_type,
        "inherited_object_type": inherited_object_type,
        "flags": flags,
        "object_ace": object_ace or bool(object_type or inherited_object_type),
    }


def build_sd(owner: str, aces: List[AceSpec], protected: bool = False) -> bytes:
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004 | (0x1000 if protected else 0)
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical(owner)
    sd["GroupSid"] = b""
    sd["Sacl"] = b""

    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    for spec in aces:
        entry = ldaptypes.ACE()
        entry["AceFlags"] = spec["flags"]
        if spec["object_ace"]:
            entry["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
            data = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
            data["Flags"] = 0
            data["ObjectType"] = b""
            data["InheritedObjectType"] = b""
            if spec["object_type"]:
                data["Flags"] |= 1
                data["ObjectType"] = string_to_bin(spec["object_type"])
            if spec["inherited_object_type"]:
                data["Flags"] |= 2
                data["InheritedObjectType"] = string_to_bin(
                    spec["inherited_object_type"]
                )
        else:
            entry["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            data = ldaptypes.ACCESS_ALLOWED_ACE()
        data["Mask"] = ldaptypes.ACCESS_MASK()
        data["Mask"]["Mask"] = spec["mask"]
        data["Sid"] = ldaptypes.LDAP_SID()
        data["Sid"].fromCanonical(spec["sid"])
        entry["Ace"] = data
        acl.aces.append(entry)
    sd["Dacl"] = acl
    return sd.getData()


def rights(aces: List[Dict[str, Any]]) -> Set[Tuple[str, str, bool]]:
    return {(a["PrincipalSID"], a["RightName"], a["IsInherited"]) for a in aces}


# =========================================================================
# ACE conversion
# =========================================================================


def test_owner_becomes_owns_edge():
    aces, _ = parse_aces(build_sd(ADMINS, []), resolve, TEMPLATE_CLASS)
    assert rights(aces) == {(ADMINS, "Owns", False)}


def test_generic_all_supersedes_other_rights():
    sd = build_sd(ADMINS, [ace(ADMINS, CertificateRights.GENERIC_ALL)])
    aces, _ = parse_aces(sd, resolve, TEMPLATE_CLASS)
    assert (ADMINS, "GenericAll", False) in rights(aces)
    assert (ADMINS, "WriteDacl", False) not in rights(aces)


def test_read_write_without_enroll_is_generic_write():
    # Issue #353: "Read" + "Write" in the template's security tab, no "Enroll"
    sd = build_sd(ADMINS, [ace(CA_MANAGERS, READ | WRITE)])
    aces, _ = parse_aces(sd, resolve, TEMPLATE_CLASS, template=True)
    assert rights(aces) - {(ADMINS, "Owns", False)} == {
        (CA_MANAGERS, "GenericWrite", False)
    }


def test_enroll_and_pki_flag_writes():
    sd = build_sd(
        ADMINS,
        [
            ace(USERS, 0x100, object_type=ENROLL_GUID),
            ace(CA_MANAGERS, 0x20, object_type=PKI_NAME_FLAG_GUID),
            ace(CA_MANAGERS, 0x20, object_type=PKI_ENROLLMENT_FLAG_GUID),
        ],
    )
    aces, _ = parse_aces(sd, resolve, TEMPLATE_CLASS, template=True)
    assert {
        (USERS, "Enroll", False),
        (CA_MANAGERS, "WritePKINameFlag", False),
        (CA_MANAGERS, "WritePKIEnrollmentFlag", False),
    } <= rights(aces)
    assert not any(a["RightName"] == "GenericWrite" for a in aces)


def test_pki_flag_writes_only_on_templates():
    sd = build_sd(ADMINS, [ace(CA_MANAGERS, 0x20, object_type=PKI_NAME_FLAG_GUID)])
    aces, _ = parse_aces(sd, resolve, TEMPLATE_CLASS, template=False)
    assert rights(aces) == {(ADMINS, "Owns", False)}


def test_all_extended_rights_without_object_type():
    sd = build_sd(ADMINS, [ace(USERS, 0x100)])
    aces, _ = parse_aces(sd, resolve, TEMPLATE_CLASS)
    assert (USERS, "AllExtendedRights", False) in rights(aces)


def test_inherit_only_and_foreign_class_aces_are_skipped():
    sd = build_sd(
        ADMINS,
        [
            # Set here only to be inherited by children
            ace(USERS, CertificateRights.GENERIC_ALL, flags=0x08),
            # Inherited, but targeted at user objects
            ace(
                USERS,
                CertificateRights.GENERIC_ALL,
                inherited_object_type=OTHER_CLASS,
                flags=0x10,
            ),
            # Inherited and targeted at certificate templates
            ace(
                CA_MANAGERS,
                WRITE,
                inherited_object_type=TEMPLATE_CLASS,
                flags=0x10,
            ),
        ],
    )
    aces, _ = parse_aces(sd, resolve, TEMPLATE_CLASS)
    assert rights(aces) == {
        (ADMINS, "Owns", False),
        (CA_MANAGERS, "GenericWrite", True),
    }


def test_ignored_and_well_known_principals():
    sd = build_sd(
        "S-1-3-0",
        [ace("S-1-5-18", CertificateRights.GENERIC_ALL), ace("S-1-5-11", 0x100)],
        protected=True,
    )
    aces, protected = parse_aces(sd, resolve, TEMPLATE_CLASS)
    assert protected
    assert rights(aces) == {("CORP.LOCAL-S-1-5-11", "AllExtendedRights", False)}


def test_ca_security_rights():
    sd = build_sd(ADMINS, [ace(CA_MANAGERS, 0x1 | 0x2), ace(USERS, 0x200 | 0x100)])
    from certipy.lib.bloodhound_export import ca_security_aces

    aces = ca_security_aces(CASecurity(sd), resolve)
    assert {
        (ADMINS, "Owns", False),
        (CA_MANAGERS, "ManageCA", False),
        (CA_MANAGERS, "ManageCertificates", False),
        (USERS, "Enroll", False),
    } == rights(aces)


# =========================================================================
# Templates
# =========================================================================


def template_entry(
    make_ldap_entry: EntryFactory,
    name: str = "VulnTemplate",
    schema_version: int = 2,
    ekus: Optional[List[str]] = None,
    app_policy: Optional[List[str]] = None,
    name_flag: int = 1,
    enrollment_flag: int = 0,
    sd: Optional[bytes] = None,
) -> LDAPEntry:
    return make_ldap_entry(
        attributes={
            "cn": name,
            "displayName": name,
            "objectGUID": "{5c4f2b4a-1d1a-4a3e-9f00-0123456789ab}",
            "distinguishedName": f"CN={name},CN=Certificate Templates",
            "msPKI-Cert-Template-OID": "1.3.6.1.4.1.311.21.8.1.2",
            "msPKI-Template-Schema-Version": schema_version,
            "msPKI-Certificate-Name-Flag": name_flag,
            "msPKI-Enrollment-Flag": enrollment_flag,
            "msPKI-RA-Signature": 0,
            "nTSecurityDescriptor": sd,
            "validity_period": "1 year",
            "renewal_period": "6 weeks",
        },
        raw_attributes={
            "pKIExtendedKeyUsage": [e.encode() for e in ekus or []],
            "msPKI-Certificate-Application-Policy": [
                e.encode() for e in app_policy or []
            ],
        },
    )


def test_template_properties_v2_uses_application_policy(make_ldap_entry: EntryFactory):
    template = template_entry(
        make_ldap_entry,
        ekus=["1.3.6.1.5.5.7.3.4"],
        app_policy=["1.3.6.1.5.5.7.3.2"],
    )
    props = template_properties(template)
    assert props["effectiveekus"] == ["1.3.6.1.5.5.7.3.2"]
    assert props["authenticationenabled"] is True
    assert props["schannelauthenticationenabled"] is True
    assert props["enrolleesuppliessubject"] is True
    assert props["requiresmanagerapproval"] is False
    assert props["certificatenameflag"] == "ENROLLEE_SUPPLIES_SUBJECT"
    assert props["oid"] == "1.3.6.1.4.1.311.21.8.1.2"


def test_template_properties_v1_uses_ekus(make_ldap_entry: EntryFactory):
    template = template_entry(
        make_ldap_entry,
        schema_version=1,
        ekus=["1.3.6.1.5.5.7.3.4"],
        app_policy=["1.3.6.1.5.5.7.3.2"],
        name_flag=0,
        enrollment_flag=0x2 | 0x80000,
    )
    props = template_properties(template)
    assert props["effectiveekus"] == ["1.3.6.1.5.5.7.3.4"]
    assert props["authenticationenabled"] is False
    assert props["requiresmanagerapproval"] is True
    assert props["nosecurityextension"] is True


def test_template_without_ekus_allows_authentication(make_ldap_entry: EntryFactory):
    props = template_properties(template_entry(make_ldap_entry))
    assert props["effectiveekus"] == []
    assert props["authenticationenabled"] is True


@pytest.mark.parametrize(
    "values, expected",
    [
        ([b"1.3.6.1.4.1.311.20.2.1"], ["1.3.6.1.4.1.311.20.2.1"]),
        (
            [
                b"msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`"
                b"msPKI-RA-Application-Policies`PZPWSTR`1.3.6.1.4.1.311.20.2.1`"
            ],
            ["1.3.6.1.4.1.311.20.2.1"],
        ),
        (None, []),
    ],
)
def test_ra_application_policies(values: Optional[List[bytes]], expected: List[str]):
    assert ra_application_policies(values) == expected


# =========================================================================
# Certificate authorities
# =========================================================================


@pytest.fixture(scope="module")
def pki(make_cert: CertFactory) -> SimpleNamespace:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = make_cert(subject_cn="CORP Root CA", key=root_key, ca=True)
    issuing = make_cert(
        subject_cn="CORP Issuing CA",
        key=issuing_key,
        issuer=root,
        issuer_key=root_key,
        ca=True,
    )

    def der(cert: x509.Certificate) -> bytes:
        return cert.public_bytes(serialization.Encoding.DER)

    return SimpleNamespace(root=der(root), issuing=der(issuing))


def test_chain_walks_to_root(pki: SimpleNamespace):
    root = CertificateInfo(pki.root)
    issuing = CertificateInfo(pki.issuing)
    assert root.self_signed and not issuing.self_signed
    assert build_chain(issuing, [root]) == [issuing.thumbprint, root.thumbprint]
    assert build_chain(root, [root]) == [root.thumbprint]
    # Unknown issuer: the chain stops at the certificate itself
    assert build_chain(issuing, []) == [issuing.thumbprint]


def ca_entry(
    make_ldap_entry: EntryFactory, pki: SimpleNamespace, **extra: Any
) -> LDAPEntry:
    attributes = {
        "name": "CORP-CA",
        "dNSHostName": "ca.corp.local",
        "objectGUID": "{aaaaaaaa-1111-2222-3333-444444444444}",
        "cACertificate": [pki.issuing],
        "certificateTemplates": ["VulnTemplate", "Missing"],
        "nTSecurityDescriptor": build_sd(
            ADMINS, [ace(USERS, 0x100, object_type=ENROLL_GUID)]
        ),
        "hosting_computer_sid": f"{DOMAIN_SID}-1000",
    }
    attributes.update(extra)
    return make_ldap_entry(attributes=attributes)


def test_enterprise_ca_node_with_registry_data(
    make_ldap_entry: EntryFactory, pki: SimpleNamespace
):
    security = CASecurity(build_sd(ADMINS, [ace(CA_MANAGERS, 0x1)]))
    ca = ca_entry(
        make_ldap_entry,
        pki,
        security=security,
        user_specified_san="Enabled",
        enforce_encrypt_icertrequest="Disabled",
        disabled_extensions=["1.3.6.1.4.1.311.25.2"],
        enrollment_agent_restrictions=[
            EnrollmentAgentRestriction(USERS, [ADMINS], "VulnTemplate")
        ],
        web_enrollment={
            "http": {"enabled": True},
            "https": {"enabled": True, "channel_binding": False},
        },
    )
    exporter = CEExporter("corp.local", DOMAIN_SID, resolve)
    node = exporter.enterprise_ca_node(
        ca, {"VulnTemplate": "TEMPLATE-GUID"}, [CertificateInfo(pki.root)]
    )

    props = node["Properties"]
    assert node["ObjectIdentifier"] == "AAAAAAAA-1111-2222-3333-444444444444"
    assert props["name"] == "CORP-CA@CORP.LOCAL"
    assert props["certchain"] == [
        CertificateInfo(pki.issuing).thumbprint,
        CertificateInfo(pki.root).thumbprint,
    ]
    assert props["isuserspecifiessanenabled"] is True
    assert props["isuserspecifiessanenabledcollected"] is True
    assert props["rpcencryptionenforced"] is False
    assert props["disabledextensions"] == ["1.3.6.1.4.1.311.25.2"]
    assert props["unresolvedpublishedtemplates"] == ["Missing"]
    assert node["EnabledCertTemplates"] == [
        {"ObjectIdentifier": "TEMPLATE-GUID", "ObjectType": "CertTemplate"}
    ]
    assert node["HostingComputer"] == f"{DOMAIN_SID}-1000"
    assert (USERS, "Enroll", False) in rights(node["Aces"])

    registry = node["CARegistryData"]
    assert (CA_MANAGERS, "ManageCA", False) in rights(registry["CASecurity"]["Data"])
    restriction = registry["EnrollmentAgentRestrictions"]["Restrictions"][0]
    assert restriction["Agent"]["ObjectIdentifier"] == USERS
    assert restriction["Template"]["ObjectIdentifier"] == "TEMPLATE-GUID"
    assert restriction["AllTemplates"] is False

    endpoints = {e["Result"]["Url"]: e for e in node["HttpEnrollmentEndpoints"]}
    assert endpoints["http://ca.corp.local/certsrv/"]["Result"]["ADCSWebEnrollmentHTTP"]
    https = endpoints["https://ca.corp.local/certsrv/"]
    assert https["Collected"] and not https["Result"]["ADCSWebEnrollmentEPA"]


def test_enterprise_ca_node_dc_only(
    make_ldap_entry: EntryFactory, pki: SimpleNamespace
):
    ca = ca_entry(
        make_ldap_entry,
        pki,
        security=None,
        user_specified_san="Unknown",
        enforce_encrypt_icertrequest="Unknown",
        web_enrollment={
            "http": {"enabled": "Unknown"},
            "https": {"enabled": "Unknown", "channel_binding": None},
        },
    )
    node = CEExporter("corp.local", DOMAIN_SID, resolve).enterprise_ca_node(ca, {}, [])
    registry = node["CARegistryData"]
    assert not any(registry[k]["Collected"] for k in registry)
    assert node["Properties"]["casecuritycollected"] is False
    assert "isuserspecifiessanenabled" not in node["Properties"]
    assert node["HttpEnrollmentEndpoints"] == []


def test_https_endpoint_with_unknown_epa_is_not_collected(
    make_ldap_entry: EntryFactory, pki: SimpleNamespace
):
    ca = ca_entry(
        make_ldap_entry,
        pki,
        web_enrollment={
            "http": {"enabled": False},
            "https": {"enabled": True, "channel_binding": "Unknown"},
        },
    )
    node = CEExporter("corp.local", DOMAIN_SID, resolve).enterprise_ca_node(ca, {}, [])
    https = node["HttpEnrollmentEndpoints"][1]
    assert https["Collected"] is False


def test_root_aia_ntauth_and_policy_nodes(
    make_ldap_entry: EntryFactory, pki: SimpleNamespace
):
    exporter = CEExporter("corp.local", DOMAIN_SID, resolve)
    root = CertificateInfo(pki.root)
    store = make_ldap_entry(
        attributes={
            "cn": "NTAuthCertificates",
            "objectGUID": "{bbbbbbbb-0000-0000-0000-000000000000}",
            "cACertificate": [pki.root, pki.issuing],
        }
    )
    ntauth = exporter.ntauth_store_node(store)
    assert ntauth["DomainSID"] == DOMAIN_SID
    assert ntauth["Properties"]["certthumbprints"] == [
        root.thumbprint,
        CertificateInfo(pki.issuing).thumbprint,
    ]

    root_entry = make_ldap_entry(
        attributes={
            "cn": "CORP Root CA",
            "objectGUID": "{cccccccc-0000-0000-0000-000000000000}",
            "cACertificate": [pki.root],
        }
    )
    root_node = exporter.root_ca_node(root_entry, [root])
    assert root_node["Properties"]["certchain"] == [root.thumbprint]
    aia_node = exporter.aia_ca_node(root_entry, [root])
    assert aia_node["Properties"]["hascrosscertificatepair"] is False

    oid = make_ldap_entry(
        attributes={
            "cn": "1234.ABCD",
            "displayName": "High Assurance",
            "objectGUID": "{dddddddd-0000-0000-0000-000000000000}",
            "msPKI-Cert-Template-OID": "1.3.6.1.4.1.311.21.8.9",
            "linked_group_sid": f"{DOMAIN_SID}-1200",
        }
    )
    policy = exporter.issuance_policy_node(oid)
    assert policy["GroupLink"] == {
        "ObjectIdentifier": f"{DOMAIN_SID}-1200",
        "ObjectType": "Group",
    }
    assert policy["Properties"]["certtemplateoid"] == "1.3.6.1.4.1.311.21.8.9"


def test_template_node(make_ldap_entry: EntryFactory):
    sd = build_sd(ADMINS, [ace(USERS, 0x100, object_type=ENROLL_GUID)])
    node = CEExporter("corp.local", DOMAIN_SID, resolve).template_node(
        template_entry(make_ldap_entry, sd=sd)
    )
    assert node["ObjectIdentifier"] == "5C4F2B4A-1D1A-4A3E-9F00-0123456789AB"
    assert node["Properties"]["name"] == "VULNTEMPLATE@CORP.LOCAL"
    assert node["Properties"]["domainsid"] == DOMAIN_SID
    assert (USERS, "Enroll", False) in rights(node["Aces"])


# =========================================================================
# Output
# =========================================================================


def test_write_zip_meta():
    data = write_zip(
        "20260101",
        {"certtemplates": ("certtemplates", [{"ObjectIdentifier": "A"}], 6)},
    )
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.namelist() == ["20260101_certtemplates.json"]
        payload = json.loads(archive.read("20260101_certtemplates.json"))
    assert payload["meta"]["type"] == "certtemplates"
    assert payload["meta"]["count"] == 1
    assert payload["meta"]["version"] == 6


def test_legacy_node_is_gpo_shaped(make_ldap_entry: EntryFactory):
    sd = build_sd(ADMINS, [ace(CA_MANAGERS, READ | WRITE)])
    node = legacy_node(
        template_entry(make_ldap_entry, sd=sd),
        "VulnTemplate",
        "corp.local",
        "Certificate Template",
        {"Enabled": True, "Unset": None},
        resolve,
        TEMPLATE_CLASS,
        template=True,
    )
    assert node["Properties"]["name"] == "VULNTEMPLATE@CORP.LOCAL"
    assert node["Properties"]["type"] == "Certificate Template"
    assert "Unset" not in node["Properties"]
    assert all("InheritanceHash" not in a for a in node["Aces"])
    assert (CA_MANAGERS, "GenericWrite", False) in rights(node["Aces"])
