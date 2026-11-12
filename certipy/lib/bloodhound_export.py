"""
BloodHound export for Certipy's AD CS enumeration.

Two formats are supported:
- BloodHound Community Edition (``-bloodhound``): the SharpHound v6 JSON schema
  for AD CS objects (certtemplates, enterprisecas, rootcas, aiacas, ntauthstores,
  issuancepolicies). BloodHound CE computes the ADCSESC* and GoldenCert edges
  from these objects during post-processing, so the zip must be uploaded into
  the same database as the domain data (users, groups, computers) collected by
  SharpHound, RustHound-CE or bloodhound-ce-python.
- Legacy BloodHound 4.x (``-old-bloodhound``): templates and CAs written as
  GPO nodes, as Certipy 4.x did. Legacy BloodHound has no AD CS model, so this
  only shows who controls or can enroll in each object.

The CE schema mirrors BloodHound CE's ingest models (packages/go/ein) and the
SharpHound/RustHound-CE property names that its AD CS analysis reads.
"""

import hashlib
import io
import json
import os
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from asn1crypto import x509
from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from certipy.lib.constants import (
    EXTENDED_RIGHTS_NAME_MAP,
    PKI_ATTRIBUTE_GUIDS,
    CertificateAuthorityRights,
    CertificateNameFlag,
    EnrollmentFlag,
)
from certipy.lib.logger import logging

# SharpHound JSON schema version understood by BloodHound CE
CE_META_VERSION = 6

# Extended rights and attributes that BloodHound CE models on AD CS objects
ENROLL_GUID = EXTENDED_RIGHTS_NAME_MAP["Enroll"]
_PKI_ATTRIBUTES = {name: guid for guid, name in PKI_ATTRIBUTE_GUIDS.items()}
PKI_NAME_FLAG_GUID = _PKI_ATTRIBUTES["msPKI-Certificate-Name-Flag"]
PKI_ENROLLMENT_FLAG_GUID = _PKI_ATTRIBUTES["msPKI-Enrollment-Flag"]

# Fallback schemaIDGUIDs, used when the schema cannot be read. They only filter
# inherited ACEs that target a specific object class.
DEFAULT_CLASS_GUIDS = {
    "pKICertificateTemplate": "e5209ca2-3bba-11d2-90cc-00c04fd91ab1",
    "pKIEnrollmentService": "ee4aa692-3bba-11d2-90cc-00c04fd91ab1",
    "certificationAuthority": "3fdfee50-47f4-11d1-a9c3-0000f80367c1",
    "msPKI-Enterprise-Oid": "37cfd85c-6719-4ad8-8f9e-8678ba627563",
}

# Access mask bits (MS-ADTS 5.1.3.2)
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_ALL = 0x000F01FF
GENERIC_WRITE = 0x00020028

# ACE header flags
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10
SE_DACL_PROTECTED = 0x1000

# SIDs that never become graph edges (Creator Owner, Principal Self, Local System)
IGNORED_SIDS = {"S-1-3-0", "S-1-5-10", "S-1-5-18"}

# EKUs that allow domain authentication (PKINIT/Schannel)
CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"
ANY_PURPOSE_EKU = "2.5.29.37.0"
AUTHENTICATION_EKUS = {
    CLIENT_AUTH_EKU,
    "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    ANY_PURPOSE_EKU,
}

# Principal types BloodHound CE resolves to node kinds; anything else becomes Base
CE_PRINCIPAL_TYPES = {"User", "Group", "Computer"}

# (principal id, principal type) for a raw SID
PrincipalResolver = Callable[[str], Tuple[str, str]]


# =========================================================================
# Helpers
# =========================================================================


def as_list(value: Any) -> List[Any]:
    """Normalize an LDAP attribute value to a list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def to_str(value: Any) -> str:
    """Decode bytes attribute values; pass strings through."""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def clean_guid(value: Any) -> str:
    """Return a GUID in BloodHound's object identifier format (upper case, no braces)."""
    return str(value).strip("{}").upper()


def to_epoch(value: Any) -> int:
    """Convert an LDAP generalized time to a Unix timestamp (0 if unknown)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())
    return 0


def flag_names(flags: Iterable[Any]) -> str:
    """Format IntFlag members the way SharpHound does ("A, B")."""
    return ", ".join(sorted(getattr(f, "name", None) or str(f) for f in flags))


def principal_type(object_type: Optional[str]) -> str:
    """Map Certipy's account type to a BloodHound CE node kind."""
    if object_type in CE_PRINCIPAL_TYPES:
        return object_type
    return "Base"


# =========================================================================
# Certificates
# =========================================================================


class CertificateInfo:
    """Fields BloodHound CE reads from a CA certificate."""

    def __init__(self, der: bytes):
        self.der = der
        self.thumbprint = hashlib.sha1(der).hexdigest().upper()
        cert = x509.Certificate.load(der)
        self.subject = cert.subject.dump()
        self.issuer = cert.issuer.dump()
        self.self_signed = self.subject == self.issuer
        self.name = cert.subject.human_friendly
        self.has_basic_constraints = False
        self.path_length = 0
        constraints = cert.basic_constraints_value
        if constraints is not None:
            path_length = constraints.native.get("path_len_constraint")
            if path_length is not None:
                self.has_basic_constraints = True
                self.path_length = int(path_length)


def load_certificates(values: Any) -> List[CertificateInfo]:
    """Parse DER certificates from an LDAP attribute, skipping unparsable ones."""
    certs = []
    for der in as_list(values):
        try:
            certs.append(CertificateInfo(bytes(der)))
        except Exception as e:
            logging.debug(f"Skipping unparsable certificate: {e}")
    return certs


def build_chain(
    cert: CertificateInfo, issuers: List[CertificateInfo], max_depth: int = 10
) -> List[str]:
    """
    Build the thumbprint chain from a certificate up to its root.

    Issuers are matched by subject name against the root and AIA certificates
    published in AD, which is what BloodHound CE matches IssuedSignedBy against.
    The first element is the certificate itself.
    """
    chain = [cert.thumbprint]
    current = cert
    for _ in range(max_depth):
        if current.self_signed:
            break
        parent = next(
            (
                c
                for c in issuers
                if c.subject == current.issuer and c.thumbprint not in chain
            ),
            None,
        )
        if parent is None:
            break
        chain.append(parent.thumbprint)
        current = parent
    return chain


def certificate_properties(
    cert: Optional[CertificateInfo], issuers: List[CertificateInfo]
) -> Dict[str, Any]:
    """Certificate properties shared by root, AIA and enterprise CA nodes."""
    if cert is None:
        return {}
    return {
        "certthumbprint": cert.thumbprint,
        "certname": cert.thumbprint,
        "certchain": build_chain(cert, issuers),
        "hasbasicconstraints": cert.has_basic_constraints,
        "basicconstraintpathlength": cert.path_length,
    }


# =========================================================================
# Access control
# =========================================================================


def parse_aces(
    security_descriptor: Optional[bytes],
    resolve: PrincipalResolver,
    class_guid: Optional[str],
    template: bool = False,
) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Convert an AD security descriptor into BloodHound CE ACEs.

    Follows SharpHound's rules: inherit-only ACEs and ACEs inherited for a
    different object class are skipped, GenericAll supersedes other rights,
    and write-property/extended-right ACEs map to the AD CS edges BloodHound
    models (Enroll, WritePKINameFlag, WritePKIEnrollmentFlag, ...).

    Args:
        security_descriptor: Raw nTSecurityDescriptor
        resolve: Maps a SID to (BloodHound principal id, principal type)
        class_guid: schemaIDGUID of the object's class
        template: True for certificate templates, which carry PKI flag edges

    Returns:
        (ACE list, whether the DACL is protected from inheritance)
    """
    if not security_descriptor:
        return [], False

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd.fromString(security_descriptor)
    is_protected = bool(sd["Control"] & SE_DACL_PROTECTED)

    aces: List[Dict[str, Any]] = []
    seen = set()

    def add(sid: str, right: str, inherited: bool) -> None:
        if sid in IGNORED_SIDS:
            return
        principal_id, principal_kind = resolve(sid)
        key = (principal_id, right, inherited)
        if key in seen:
            return
        seen.add(key)
        aces.append(
            {
                "PrincipalSID": principal_id,
                "PrincipalType": principal_kind,
                "RightName": right,
                "IsInherited": inherited,
                "InheritanceHash": "",
            }
        )

    owner = sd["OwnerSid"]
    if owner:
        add(format_sid(owner.getData()), "Owns", False)

    if not sd["Dacl"]:
        return aces, is_protected

    for ace in sd["Dacl"]["Data"]:
        ace_type = ace["AceType"]
        if ace_type not in (
            ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,
            ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
        ):
            continue

        flags = ace["AceFlags"]
        inherited = bool(flags & INHERITED_ACE)
        if flags & INHERIT_ONLY_ACE and not inherited:
            continue

        sid = format_sid(ace["Ace"]["Sid"].getData())
        mask = ace["Ace"]["Mask"]["Mask"]
        object_type = None

        if ace_type == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
            object_flags = ace["Ace"]["Flags"]
            if (
                object_flags
                & ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
            ):
                object_type = bin_to_string(ace["Ace"]["ObjectType"]).lower()
            if (
                inherited
                and class_guid
                and object_flags
                & ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT
                and bin_to_string(ace["Ace"]["InheritedObjectType"]).lower()
                != class_guid
            ):
                continue

        if mask & GENERIC_ALL == GENERIC_ALL:
            add(sid, "GenericAll", inherited)
            continue
        if mask & WRITE_DACL:
            add(sid, "WriteDacl", inherited)
        if mask & WRITE_OWNER:
            add(sid, "WriteOwner", inherited)

        if mask & GENERIC_WRITE == GENERIC_WRITE or (
            mask & ADS_RIGHT_DS_WRITE_PROP and object_type is None
        ):
            add(sid, "GenericWrite", inherited)
        elif template and mask & ADS_RIGHT_DS_WRITE_PROP:
            if object_type == PKI_NAME_FLAG_GUID:
                add(sid, "WritePKINameFlag", inherited)
            elif object_type == PKI_ENROLLMENT_FLAG_GUID:
                add(sid, "WritePKIEnrollmentFlag", inherited)

        if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
            if object_type is None:
                add(sid, "AllExtendedRights", inherited)
            elif object_type == ENROLL_GUID:
                add(sid, "Enroll", inherited)

    return aces, is_protected


def ca_security_aces(security: Any, resolve: PrincipalResolver) -> List[Dict[str, Any]]:
    """Convert the CA's registry security descriptor (CASecurity) to ACEs."""
    aces = []
    rights_map = [
        (CertificateAuthorityRights.MANAGE_CA, "ManageCA"),
        (CertificateAuthorityRights.MANAGE_CERTIFICATES, "ManageCertificates"),
        (CertificateAuthorityRights.ENROLL, "Enroll"),
    ]
    owner_id, owner_type = resolve(security.owner)
    aces.append(
        {
            "PrincipalSID": owner_id,
            "PrincipalType": owner_type,
            "RightName": "Owns",
            "IsInherited": False,
            "InheritanceHash": "",
        }
    )
    for sid, entry in security.aces.items():
        if sid in IGNORED_SIDS:
            continue
        principal_id, principal_kind = resolve(sid)
        for right, name in rights_map:
            if entry["rights"] & right:
                aces.append(
                    {
                        "PrincipalSID": principal_id,
                        "PrincipalType": principal_kind,
                        "RightName": name,
                        "IsInherited": entry.get("inherited", False),
                        "InheritanceHash": "",
                    }
                )
    return aces


# =========================================================================
# Certificate template properties
# =========================================================================


def ra_application_policies(values: Any) -> List[str]:
    """
    Decode msPKI-RA-Application-Policies.

    Schema version 4 templates store this as backtick-separated
    name`type`value triples; older templates store plain OIDs.
    """
    values = [to_str(v) for v in as_list(values)]
    if not any("`" in v for v in values):
        return values
    parts = "".join(values).split("`")
    return [
        parts[i + 2]
        for i in range(0, len(parts) - 2, 3)
        if parts[i] == "msPKI-RA-Application-Policies"
    ]


def template_properties(template: Any) -> Dict[str, Any]:
    """Build the BloodHound CE property set for a certificate template."""
    name_flag = CertificateNameFlag(
        int(template.get("msPKI-Certificate-Name-Flag") or 0)
    )
    enrollment_flag = EnrollmentFlag(int(template.get("msPKI-Enrollment-Flag") or 0))
    schema_version = int(template.get("msPKI-Template-Schema-Version") or 1)

    ekus = [to_str(v) for v in as_list(template.get_raw("pKIExtendedKeyUsage"))]
    application_policy = [
        to_str(v)
        for v in as_list(template.get_raw("msPKI-Certificate-Application-Policy"))
    ]
    effective_ekus = ekus if schema_version == 1 and ekus else application_policy

    authentication = not effective_ekus or bool(
        AUTHENTICATION_EKUS.intersection(effective_ekus)
    )
    schannel = not effective_ekus or bool(
        {CLIENT_AUTH_EKU, ANY_PURPOSE_EKU}.intersection(effective_ekus)
    )

    def has(flag: Any, member: Any) -> bool:
        return bool(flag & member)

    return {
        "displayname": template.get("displayName") or template.get("cn"),
        "oid": template.get("msPKI-Cert-Template-OID") or "",
        "validityperiod": str(template.get("validity_period") or ""),
        "renewalperiod": str(template.get("renewal_period") or ""),
        "schemaversion": schema_version,
        "enrollmentflag": flag_names(enrollment_flag.to_list()),
        "certificatenameflag": flag_names(name_flag.to_list()),
        "requiresmanagerapproval": has(
            enrollment_flag, EnrollmentFlag.PEND_ALL_REQUESTS
        ),
        "nosecurityextension": has(
            enrollment_flag, EnrollmentFlag.NO_SECURITY_EXTENSION
        ),
        "enrolleesuppliessubject": has(
            name_flag, CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT
        ),
        "subjectaltrequireupn": has(
            name_flag, CertificateNameFlag.SUBJECT_ALT_REQUIRE_UPN
        ),
        "subjectaltrequiredns": has(
            name_flag, CertificateNameFlag.SUBJECT_ALT_REQUIRE_DNS
        ),
        "subjectaltrequiredomaindns": has(
            name_flag, CertificateNameFlag.SUBJECT_ALT_REQUIRE_DOMAIN_DNS
        ),
        "subjectaltrequireemail": has(
            name_flag, CertificateNameFlag.SUBJECT_ALT_REQUIRE_EMAIL
        ),
        "subjectaltrequirespn": has(
            name_flag, CertificateNameFlag.SUBJECT_ALT_REQUIRE_SPN
        ),
        "subjectrequireemail": has(
            name_flag, CertificateNameFlag.SUBJECT_REQUIRE_EMAIL
        ),
        "ekus": ekus,
        "certificateapplicationpolicy": application_policy,
        "authorizedsignatures": int(template.get("msPKI-RA-Signature") or 0),
        "applicationpolicies": ra_application_policies(
            template.get_raw("msPKI-RA-Application-Policies")
        ),
        "issuancepolicies": [
            to_str(v) for v in as_list(template.get_raw("msPKI-RA-Policies"))
        ],
        "certificatepolicy": [
            to_str(v) for v in as_list(template.get_raw("msPKI-Certificate-Policy"))
        ],
        "effectiveekus": effective_ekus,
        "authenticationenabled": authentication,
        "schannelauthenticationenabled": schannel,
    }


# =========================================================================
# BloodHound CE export
# =========================================================================


class CEExporter:
    """
    Build BloodHound CE AD CS nodes from Certipy's enumeration results.

    Args:
        domain: DNS domain name (upper-cased for node names)
        domain_sid: Domain SID, links root CAs/NTAuth/templates to the domain node
        resolve: Maps a SID to (BloodHound principal id, principal type)
        class_guids: lDAPDisplayName -> schemaIDGUID for the AD CS classes
    """

    def __init__(
        self,
        domain: str,
        domain_sid: str,
        resolve: PrincipalResolver,
        class_guids: Optional[Dict[str, str]] = None,
    ):
        self.domain = domain.upper()
        self.domain_sid = domain_sid
        self.resolve = resolve
        self.class_guids = {**DEFAULT_CLASS_GUIDS, **(class_guids or {})}

    def _base(
        self, entry: Any, name: str, class_name: str, template: bool = False
    ) -> Dict[str, Any]:
        aces, is_protected = parse_aces(
            entry.get("nTSecurityDescriptor"),
            self.resolve,
            self.class_guids.get(class_name),
            template=template,
        )
        guid = clean_guid(entry.get("objectGUID"))
        properties = {
            "name": f"{name}@{self.domain}".upper(),
            "domain": self.domain,
            "domainsid": self.domain_sid,
            "distinguishedname": (entry.get("distinguishedName") or "").upper(),
            "objectguid": guid,
            "description": entry.get("description"),
            "whencreated": to_epoch(entry.get("whenCreated")),
            "isaclprotected": is_protected,
        }
        return {
            "ObjectIdentifier": guid,
            "Properties": properties,
            "Aces": aces,
            "IsDeleted": False,
            "IsACLProtected": is_protected,
            "ContainedBy": None,
        }

    def template_node(self, template: Any) -> Dict[str, Any]:
        node = self._base(
            template, template.get("cn"), "pKICertificateTemplate", template=True
        )
        node["Properties"].update(template_properties(template))
        return node

    def issuance_policy_node(self, oid: Any) -> Dict[str, Any]:
        node = self._base(
            oid, oid.get("displayName") or oid.get("cn"), "msPKI-Enterprise-Oid"
        )
        node["Properties"].update(
            {
                "displayname": oid.get("displayName") or oid.get("cn"),
                "certtemplateoid": oid.get("msPKI-Cert-Template-OID") or "",
            }
        )
        group_link = {"ObjectIdentifier": None, "ObjectType": "Base"}
        group_sid = oid.get("linked_group_sid")
        if group_sid:
            node["Properties"]["oidgrouplink"] = group_sid
            group_link = {"ObjectIdentifier": group_sid, "ObjectType": "Group"}
        node["GroupLink"] = group_link
        return node

    def root_ca_node(self, ca: Any, issuers: List[CertificateInfo]) -> Dict[str, Any]:
        node = self._base(ca, ca.get("cn"), "certificationAuthority")
        certs = load_certificates(ca.get("cACertificate"))
        node["Properties"].update(
            certificate_properties(certs[0] if certs else None, issuers)
        )
        node["DomainSID"] = self.domain_sid
        return node

    def aia_ca_node(self, ca: Any, issuers: List[CertificateInfo]) -> Dict[str, Any]:
        node = self.root_ca_node(ca, issuers)
        cross_pairs = as_list(ca.get("crossCertificatePair"))
        node["Properties"]["hascrosscertificatepair"] = bool(cross_pairs)
        node["Properties"]["crosscertificatepair"] = [
            hashlib.sha1(bytes(p)).hexdigest().upper() for p in cross_pairs
        ]
        return node

    def ntauth_store_node(self, store: Any) -> Dict[str, Any]:
        node = self._base(store, store.get("cn"), "certificationAuthority")
        node["Properties"]["certthumbprints"] = [
            c.thumbprint for c in load_certificates(store.get("cACertificate"))
        ]
        node["DomainSID"] = self.domain_sid
        return node

    def enterprise_ca_node(
        self,
        ca: Any,
        template_ids: Dict[str, str],
        issuers: List[CertificateInfo],
    ) -> Dict[str, Any]:
        """
        Build an EnterpriseCA node.

        Args:
            ca: Processed CA entry from Find (registry data and web enrollment set)
            template_ids: Template name -> object identifier
            issuers: Root and AIA certificates for chain building
        """
        node = self._base(ca, ca.get("name"), "pKIEnrollmentService")
        certs = load_certificates(ca.get("cACertificate"))
        properties = node["Properties"]
        properties.update(certificate_properties(certs[0] if certs else None, issuers))
        properties.update(
            {
                "caname": ca.get("name"),
                "dnshostname": ca.get("dNSHostName") or "",
                "flags": str(ca.get("flags") or ""),
            }
        )

        enabled = []
        unresolved = []
        for template_name in as_list(ca.get("certificateTemplates")):
            if template_name in template_ids:
                enabled.append(
                    {
                        "ObjectIdentifier": template_ids[template_name],
                        "ObjectType": "CertTemplate",
                    }
                )
            else:
                unresolved.append(template_name)
        node["EnabledCertTemplates"] = enabled
        properties["unresolvedpublishedtemplates"] = unresolved

        registry = self._ca_registry_data(ca, template_ids)
        node["CARegistryData"] = registry
        properties.update(
            {
                "casecuritycollected": registry["CASecurity"]["Collected"],
                "enrollmentagentrestrictionscollected": registry[
                    "EnrollmentAgentRestrictions"
                ]["Collected"],
                "isuserspecifiessanenabledcollected": registry[
                    "IsUserSpecifiesSanEnabled"
                ]["Collected"],
                "roleseparationenabledcollected": registry["RoleSeparationEnabled"][
                    "Collected"
                ],
                "rpcencryptioncollected": registry["RPCEncryptionEnforced"][
                    "Collected"
                ],
                "disabledextensionscollected": registry["DisabledExtensions"][
                    "Collected"
                ],
            }
        )
        if registry["IsUserSpecifiesSanEnabled"]["Collected"]:
            properties["isuserspecifiessanenabled"] = registry[
                "IsUserSpecifiesSanEnabled"
            ]["Value"]
        if registry["RPCEncryptionEnforced"]["Collected"]:
            properties["rpcencryptionenforced"] = registry["RPCEncryptionEnforced"][
                "Value"
            ]
        if registry["DisabledExtensions"]["Collected"]:
            properties["disabledextensions"] = registry["DisabledExtensions"]["Data"]
        if registry["EnrollmentAgentRestrictions"]["Collected"]:
            properties["hasenrollmentagentrestrictions"] = bool(
                registry["EnrollmentAgentRestrictions"]["Restrictions"]
            )

        node["HostingComputer"] = ca.get("hosting_computer_sid") or ""
        node["HttpEnrollmentEndpoints"] = self._web_enrollment(ca)
        return node

    def _ca_registry_data(
        self, ca: Any, template_ids: Dict[str, str]
    ) -> Dict[str, Any]:
        def result(collected: bool, reason: str = "", **fields: Any) -> Dict[str, Any]:
            return {
                "Collected": collected,
                "FailureReason": "" if collected else reason,
                **fields,
            }

        reason = "Not collected (dc-only or CA unreachable)"
        security = ca.get("security")
        user_san = ca.get("user_specified_san")
        encrypt = ca.get("enforce_encrypt_icertrequest")
        disabled = ca.get("disabled_extensions")
        restrictions = ca.get("enrollment_agent_restrictions")
        # Restrictions are only read when the CA configuration was read
        config_read = security is not None

        ea_restrictions = []
        for restriction in as_list(restrictions):
            agent_id, agent_type = self.resolve(restriction.agent)
            all_templates = restriction.template == "<All>"
            template_id = template_ids.get(restriction.template)
            ea_restrictions.append(
                {
                    "AccessType": "AccessAllowedCallback",
                    "Agent": {"ObjectIdentifier": agent_id, "ObjectType": agent_type},
                    "AllTemplates": all_templates,
                    "Targets": [
                        dict(zip(("ObjectIdentifier", "ObjectType"), self.resolve(t)))
                        for t in restriction.targets
                    ],
                    "Template": (
                        {
                            "ObjectIdentifier": template_id,
                            "ObjectType": "CertTemplate",
                        }
                        if template_id
                        else None
                    ),
                }
            )

        return {
            "CASecurity": result(
                security is not None,
                reason,
                Data=ca_security_aces(security, self.resolve) if security else [],
            ),
            "EnrollmentAgentRestrictions": result(
                config_read, reason, Restrictions=ea_restrictions
            ),
            "IsUserSpecifiesSanEnabled": result(
                user_san in ("Enabled", "Disabled"),
                reason,
                Value=user_san == "Enabled",
            ),
            "RoleSeparationEnabled": result(
                False, "Not collected by Certipy", Value=False
            ),
            "RPCEncryptionEnforced": result(
                encrypt in ("Enabled", "Disabled"), reason, Value=encrypt == "Enabled"
            ),
            # LDAPEntry.get returns None for an empty list, so an empty
            # DisableExtensionList shows up as None once the config was read
            "DisabledExtensions": result(
                config_read or isinstance(disabled, list),
                reason,
                Data=disabled if isinstance(disabled, list) else [],
            ),
        }

    def _web_enrollment(self, ca: Any) -> List[Dict[str, Any]]:
        host = ca.get("dNSHostName") or ""
        web = ca.get("web_enrollment") or {}
        endpoints = []
        http = web.get("http", {}).get("enabled")
        if isinstance(http, bool):
            endpoints.append(
                {
                    "Collected": True,
                    "FailureReason": "",
                    "Result": {
                        "Url": f"http://{host}/certsrv/",
                        "ADCSWebEnrollmentHTTP": http,
                        "ADCSWebEnrollmentHTTPS": False,
                        "ADCSWebEnrollmentEPA": False,
                    },
                }
            )
        https = web.get("https", {})
        if isinstance(https.get("enabled"), bool):
            binding = https.get("channel_binding")
            endpoints.append(
                {
                    # EPA state unknown means the endpoint cannot be judged
                    "Collected": not https["enabled"] or isinstance(binding, bool),
                    "FailureReason": "",
                    "Result": {
                        "Url": f"https://{host}/certsrv/",
                        "ADCSWebEnrollmentHTTP": False,
                        "ADCSWebEnrollmentHTTPS": https["enabled"],
                        "ADCSWebEnrollmentEPA": binding is True,
                    },
                }
            )
        return endpoints


def write_zip(
    path: str, files: Dict[str, Tuple[str, List[Dict[str, Any]], int]]
) -> bytes:
    """
    Serialize BloodHound JSON files into an in-memory zip.

    Args:
        path: Output prefix; only its base name is used for the member file names
        files: suffix -> (meta type, data, meta version)

    Returns:
        Zip archive bytes
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for suffix, (data_type, data, version) in files.items():
            payload = {
                "data": data,
                "meta": {
                    "methods": 0,
                    "type": data_type,
                    "count": len(data),
                    "version": version,
                    "collectorversion": "Certipy",
                },
            }
            archive.writestr(
                f"{os.path.basename(path)}_{suffix}.json",
                json.dumps(payload, default=str),
            )
    return buffer.getvalue()


# =========================================================================
# Legacy BloodHound 4.x export
# =========================================================================


def legacy_node(
    entry: Any,
    name: str,
    domain: str,
    node_type: str,
    properties: Dict[str, Any],
    resolve: PrincipalResolver,
    class_guid: Optional[str],
    template: bool = False,
    extra_aces: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build a GPO-shaped node for legacy BloodHound, as Certipy 4.x did.

    Legacy BloodHound has no certificate template or CA node types, so these
    are imported as GPOs with a "type" property to tell them apart.
    """
    aces, _ = parse_aces(
        entry.get("nTSecurityDescriptor"), resolve, class_guid, template=template
    )
    aces.extend(extra_aces or [])
    for ace in aces:
        ace.pop("InheritanceHash", None)
    return {
        "ObjectIdentifier": clean_guid(entry.get("objectGUID")),
        "Properties": {
            "name": f"{name}@{domain}".upper(),
            "domain": domain.upper(),
            "type": node_type,
            "highvalue": False,
            **{k: v for k, v in properties.items() if v is not None},
        },
        "Aces": aces,
    }
