import datetime
from typing import Any, Callable, Tuple, cast

import pytest
from asn1crypto import cms as asn1cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from certipy.commands.forge import Forge
from certipy.lib.certificate import (
    create_csr,
    create_on_behalf_of,
    create_renewal,
    csr_to_der,
    generate_ec_key,
    load_pfx,
    sign_data,
    signature_algorithm_name,
)
from certipy.lib.pkinit import sign_authpack


def _ec_cert(key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def _csr(key_type: str) -> x509.CertificateSigningRequest:
    csr, _ = create_csr(
        "alice",
        alt_dns=None,
        alt_upn="administrator@corp.local",
        alt_sid=None,
        subject=None,
        key_size=2048,
        application_policies=None,
        smime=None,
        key_type=key_type,
    )
    return csr


def _signer_info(content_info: bytes) -> Any:
    # asn1crypto's stubs type parsed fields as Void, so walk them untyped
    parsed = cast(Any, asn1cms.ContentInfo.load(content_info))
    return parsed["content"]["signer_infos"][0]


def _verify(public_key: object, signer_info: Any) -> None:
    signed = signer_info["signed_attrs"].untag().dump()
    hash_name = signer_info["digest_algorithm"]["algorithm"].native
    algorithm = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}[hash_name]()
    signature: bytes = signer_info["signature"].native
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, signed, ec.ECDSA(algorithm))
    else:
        assert isinstance(public_key, rsa.RSAPublicKey)
        public_key.verify(signature, signed, padding.PKCS1v15(), algorithm)


@pytest.mark.parametrize(
    "key_type,public_type",
    [("rsa", rsa.RSAPublicKey), ("ec", ec.EllipticCurvePublicKey)],
)
def test_create_csr_key_types_are_signed(key_type: str, public_type: type):
    csr = _csr(key_type)
    assert isinstance(csr.public_key(), public_type)
    assert csr.is_signature_valid


def test_create_csr_rejects_unknown_key_type():
    with pytest.raises(ValueError):
        _csr("dsa")


def test_signature_algorithm_name():
    key = generate_ec_key()
    assert signature_algorithm_name(key, hashes.SHA256) == "sha256_ecdsa"


def test_sign_data_ecdsa_verifies():
    key = generate_ec_key()
    signature = sign_data(b"data", key, hashes.SHA256)
    key.public_key().verify(signature, b"data", ec.ECDSA(hashes.SHA256()))


def test_sign_authpack_ec_uses_sha256_ecdsa():
    key = generate_ec_key()
    cert = _ec_cert(key)
    signer_info = _signer_info(sign_authpack(b"authpack", key, cert))
    assert signer_info["signature_algorithm"]["algorithm"].native == "sha256_ecdsa"
    _verify(key.public_key(), signer_info)


def test_sign_authpack_rsa_keeps_sha1(
    rsa_key: rsa.RSAPrivateKey, make_cert: Callable[..., x509.Certificate]
):
    cert = make_cert()
    signer_info = _signer_info(sign_authpack(b"authpack", rsa_key, cert))
    assert signer_info["signature_algorithm"]["algorithm"].native == "sha1_rsa"
    _verify(rsa_key.public_key(), signer_info)


@pytest.mark.parametrize("builder", ["renewal", "on_behalf_of"])
def test_cms_wrappers_sign_with_ec_key(builder: str):
    key = generate_ec_key()
    cert = _ec_cert(key)
    request = csr_to_der(_csr("rsa"))
    if builder == "renewal":
        cms = create_renewal(request, cert, key)
    else:
        cms = create_on_behalf_of(request, "CORP\\administrator", cert, key)
    signer_info = _signer_info(cms)
    assert signer_info["signature_algorithm"]["algorithm"].native == "sha256_ecdsa"
    _verify(key.public_key(), signer_info)


def test_forge_new_ec_certificate(
    ca_chain: Tuple[
        x509.Certificate, rsa.RSAPrivateKey, x509.Certificate, rsa.RSAPrivateKey
    ],
):
    ca_cert, ca_key, _, _ = ca_chain
    forge = Forge(upn="administrator@corp.local", key_type="ec")
    key, pfx = forge.build_new_certificate(ca_key, ca_key.public_key(), ca_cert)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    loaded_key, loaded_cert = load_pfx(pfx)
    assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
    assert loaded_cert is not None
    assert isinstance(loaded_cert.public_key(), ec.EllipticCurvePublicKey)
    loaded_cert.verify_directly_issued_by(ca_cert)
