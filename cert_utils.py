"""Shared certificate parsing utilities used by scanner, certstore, and sniffer."""

from __future__ import annotations

import hashlib
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509 import ExtendedKeyUsage, SubjectAlternativeName
from cryptography.x509.oid import ExtendedKeyUsageOID

from assets import DiscoveredAsset, is_quantum_vulnerable

_EKU_MAP = {
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning",
    ExtendedKeyUsageOID.IPSEC_END_SYSTEM: "ipsecEndSystem",
    ExtendedKeyUsageOID.IPSEC_TUNNEL: "ipsecTunnel",
    ExtendedKeyUsageOID.IPSEC_USER: "ipsecUser",
    ExtendedKeyUsageOID.MICROSOFT_SERVER_GATED_CRYPTO: "msServerGatedCrypto",
    ExtendedKeyUsageOID.NETSCAPE_SERVER_GATED_CRYPTO: "netscapeServerGatedCrypto",
}


def sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pub_key_info(cert: x509.Certificate) -> tuple[str, Optional[int]]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(pub).__name__, None


def get_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        result = []
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                result.append(name.value)
            elif isinstance(name, x509.IPAddress):
                result.append(str(name.value))
            elif isinstance(name, x509.RFC822Name):
                result.append(name.value)
        return result
    except x509.ExtensionNotFound:
        return []


def get_ekus(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
        return [_EKU_MAP.get(oid, "any") for oid in ext.value]
    except x509.ExtensionNotFound:
        return []


def cert_name(cert: x509.Certificate, fp: str, san_list: list[str]) -> str:
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    if san_list:
        return san_list[0]
    return f"cert:{fp[:16]}"


def parse_der_cert(
    der: bytes,
    uid_prefix: str,
    probe_name: str,
    *,
    host: Optional[str] = None,
    file_path: Optional[str] = None,
    labels: Optional[list[str]] = None,
    custom_metadata: Optional[dict] = None,
) -> Optional[DiscoveredAsset]:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    fp = sha256hex(der)
    algo, key_size = pub_key_info(cert)
    san_list = get_sans(cert)
    name = cert_name(cert, fp, san_list)
    self_signed = cert.issuer == cert.subject

    return DiscoveredAsset(
        uid=f"probe:{probe_name}:{uid_prefix}:{fp}",
        name=name,
        type="certificate",
        algorithm=algo,
        key_size=key_size,
        self_signed=self_signed,
        is_quantum_vulnerable=is_quantum_vulnerable(algo),
        extended_key_usage=get_ekus(cert),
        subject_alternative_names=san_list,
        host=host,
        file_path=file_path,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        fingerprint=fp,
        valid_from=cert.not_valid_before_utc,
        valid_to=cert.not_valid_after_utc,
        labels=labels or [],
        custom_metadata=custom_metadata or {},
    )
