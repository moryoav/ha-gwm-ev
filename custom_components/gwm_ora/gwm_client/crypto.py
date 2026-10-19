"""Offline certificate and key operations used by GWM mutual TLS."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass(frozen=True, slots=True)
class GeneratedClientCertificateRequest:
    """Base64-encoded DER CSR and its PKCS#8 private key."""

    csr: str = field(repr=False)
    private_key: str = field(repr=False)


def load_certificate(data: bytes) -> x509.Certificate:
    """Parse one PEM or DER X.509 certificate."""

    normalized = data.lstrip()
    if normalized.startswith(b"-----BEGIN CERTIFICATE-----"):
        return x509.load_pem_x509_certificate(normalized)
    return x509.load_der_x509_certificate(normalized)


def recover_transformed_private_key(
    certificate_data: bytes,
    transformed_key_data: bytes,
) -> rsa.RSAPrivateKey:
    """Recover the RSA key embedded in the official app's transformed format.

    The bundled key is base64-encoded DER.  Its modulus is usable as-is, while
    the private exponent stores a reversible per-five-bit transformation.  The
    public exponent comes from the matching certificate; the CRT parameters are
    then recovered without contacting GWM.
    """

    certificate = load_certificate(certificate_data)
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("The bootstrap certificate does not contain an RSA key")

    encoded_key = b"".join(transformed_key_data.split())
    der = base64.b64decode(encoded_key, validate=True)
    modulus, transformed_private_exponent = _read_transformed_rsa_values(der)
    private_exponent = _untransform_private_exponent(transformed_private_exponent)
    public_numbers = public_key.public_numbers()
    if modulus != public_numbers.n:
        raise ValueError("The transformed key does not match the bootstrap certificate")

    prime_p, prime_q = rsa.rsa_recover_prime_factors(
        modulus,
        public_numbers.e,
        private_exponent,
    )
    private_numbers = rsa.RSAPrivateNumbers(
        p=prime_p,
        q=prime_q,
        d=private_exponent,
        dmp1=rsa.rsa_crt_dmp1(private_exponent, prime_p),
        dmq1=rsa.rsa_crt_dmq1(private_exponent, prime_q),
        iqmp=rsa.rsa_crt_iqmp(prime_p, prime_q),
        public_numbers=rsa.RSAPublicNumbers(public_numbers.e, modulus),
    )
    return private_numbers.private_key()


def generate_client_certificate_request(
    country: str | None,
    device_id: str | None,
    *,
    now: datetime | None = None,
) -> GeneratedClientCertificateRequest:
    """Create the DER CSR and RSA key expected by certificate enrollment."""

    instant = now if now is not None else datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("now must include timezone information")

    timestamp = int(instant.timestamp())
    normalized_country = (country or "").strip().upper()
    normalized_device = (device_id or "").replace("-", "")
    normalized_device = (
        normalized_device[:32]
        if len(normalized_device) >= 32
        else normalized_device.ljust(32, "0")
    ).upper()
    common_name = f"LGWMy GWM-AD-{normalized_country}{normalized_device}{timestamp}"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Great Wall Motor Co., Ltd."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "EE System Design Dept"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Operational"),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return GeneratedClientCertificateRequest(
        csr=base64.b64encode(csr_der).decode("ascii"),
        private_key=base64.b64encode(key_der).decode("ascii"),
    )


def _read_transformed_rsa_values(der: bytes) -> tuple[int, int]:
    sequence, end = _read_der_value(der, 0, 0x30)
    if end != len(der):
        raise ValueError("Trailing data after transformed RSA key")

    offset = 0
    version, offset = _read_der_integer(sequence, offset)
    modulus, offset = _read_der_integer(sequence, offset)
    stored_public_exponent, offset = _read_der_integer(sequence, offset)
    transformed_private_exponent, offset = _read_der_integer(sequence, offset)
    placeholders: list[int] = []
    for _index in range(5):
        placeholder, offset = _read_der_integer(sequence, offset)
        placeholders.append(placeholder)

    if offset != len(sequence):
        raise ValueError("Unexpected data in transformed RSA key")
    if version != 0 or stored_public_exponent != 1 or placeholders != [1] * 5:
        raise ValueError("Unexpected transformed RSA key structure")
    if modulus <= 0 or transformed_private_exponent <= 0:
        raise ValueError("Invalid transformed RSA key integers")
    return modulus, transformed_private_exponent


def _read_der_integer(data: bytes, offset: int) -> tuple[int, int]:
    encoded, end = _read_der_value(data, offset, 0x02)
    if not encoded:
        raise ValueError("Empty DER integer")
    return int.from_bytes(encoded, "big", signed=True), end


def _read_der_value(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise ValueError(f"Expected DER tag 0x{expected_tag:02x}")
    offset += 1
    if offset >= len(data):
        raise ValueError("Missing DER length")

    first_length = data[offset]
    offset += 1
    if first_length < 0x80:
        length = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or offset + length_bytes > len(data):
            raise ValueError("Invalid DER length")
        length = int.from_bytes(data[offset : offset + length_bytes], "big")
        offset += length_bytes

    end = offset + length
    if end > len(data):
        raise ValueError("Truncated DER value")
    return data[offset:end], end


def _untransform_private_exponent(number: int) -> int:
    group_count = (number.bit_length() + 4) // 5
    if group_count == 0:
        raise ValueError("Transformed private exponent is empty")

    groups = [0] * group_count
    for index in range(group_count - 1, -1, -1):
        groups[index] = number & 0x1F
        number >>= 5

    result = groups[0]
    for group in groups[1:]:
        result = (result << 5) | ((group & 0xF8) + ((group + 3) & 0x07))
    return result
