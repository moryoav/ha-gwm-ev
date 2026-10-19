"""Tests proving that legacy GWM TLS settings remain context-local."""

from __future__ import annotations

import os
import re
import ssl
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from custom_components.gwm_ora.gwm_client.crypto import load_certificate, recover_transformed_private_key
from custom_components.gwm_ora.gwm_client.tls import create_gwm_ssl_context

RESOURCE_DIR = (
    Path(__file__).resolve().parents[3]
    / "custom_components"
    / "gwm_ora"
    / "resources"
)


def _cipher_fingerprint(context: ssl.SSLContext) -> tuple[tuple[str, str, int], ...]:
    return tuple(
        (cipher["name"], cipher["protocol"], cipher["strength_bits"])
        for cipher in context.get_ciphers()
    )


def test_gwm_context_does_not_change_process_defaults() -> None:
    openssl_conf = os.environ.get("OPENSSL_CONF")
    https_factory = ssl._create_default_https_context
    module_default_ciphers = getattr(ssl, "_DEFAULT_CIPHERS", None)
    before = ssl.create_default_context()
    before_ciphers = _cipher_fingerprint(before)
    before_security_level = before.security_level
    before_minimum_version = before.minimum_version
    before_maximum_version = before.maximum_version

    gwm_context = create_gwm_ssl_context()

    after = ssl.create_default_context()
    assert gwm_context is not before
    assert before_security_level > 0
    assert gwm_context.security_level == 0
    assert gwm_context.minimum_version == before_minimum_version
    assert gwm_context.maximum_version == before_maximum_version
    assert after.security_level == before_security_level
    assert _cipher_fingerprint(after) == before_ciphers
    assert ssl._create_default_https_context is https_factory
    assert getattr(ssl, "_DEFAULT_CIPHERS", None) == module_default_ciphers
    assert os.environ.get("OPENSSL_CONF") == openssl_conf


@pytest.mark.parametrize(
    ("certificate_name", "key_name", "chain_name"),
    [
        ("gwm_general.cer", "gwm_general.key", "gwm_root.pem"),
        ("gwm_general_rus.cer", "gwm_general_rus.key", "gwm_root_rus.pem"),
    ],
)
def test_dedicated_context_loads_regional_legacy_chain_and_identity(
    tmp_path: Path,
    certificate_name: str,
    key_name: str,
    chain_name: str,
) -> None:
    baseline_ca_count = ssl.create_default_context().cert_store_stats()["x509_ca"]
    certificate_data = (RESOURCE_DIR / certificate_name).read_bytes()
    private_key = recover_transformed_private_key(
        certificate_data,
        (RESOURCE_DIR / key_name).read_bytes(),
    )
    certificate = load_certificate(certificate_data)
    certfile = tmp_path / "client.pem"
    keyfile = tmp_path / "client.key"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    context = create_gwm_ssl_context(
        ca_data=(RESOURCE_DIR / chain_name).read_bytes(),
        certfile=certfile,
        keyfile=keyfile,
    )

    assert context.security_level == 0
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    # Platform stores may already contain or deduplicate one of the OEM roots.
    assert context.cert_store_stats()["x509_ca"] > baseline_ca_count


def test_dedicated_context_requires_certificate_for_key() -> None:
    with pytest.raises(ValueError, match="certfile"):
        create_gwm_ssl_context(keyfile="client.key")


def test_dedicated_context_rejects_trailing_ca_garbage() -> None:
    bundle = (RESOURCE_DIR / "gwm_root.pem").read_text(encoding="ascii")

    with pytest.raises(ValueError, match="outside"):
        create_gwm_ssl_context(ca_data=bundle + "\nnot-a-certificate")


def test_dedicated_context_rejects_incomplete_ca_bundle() -> None:
    bundle = (RESOURCE_DIR / "gwm_root.pem").read_text(encoding="ascii")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        bundle,
        re.DOTALL,
    )

    with pytest.raises(ValueError, match="3 certificates"):
        create_gwm_ssl_context(ca_data="\n".join(blocks[:2]))


def test_dedicated_context_rejects_invalid_ca_base64() -> None:
    bundle = (RESOURCE_DIR / "gwm_root.pem").read_text(encoding="ascii")
    payload = re.search(r"(?<=-----BEGIN CERTIFICATE-----\n)[A-Za-z0-9+/]", bundle)
    assert payload is not None
    corrupted = bundle[: payload.start()] + "!" + bundle[payload.end() :]

    with pytest.raises(ValueError, match="base64"):
        create_gwm_ssl_context(ca_data=corrupted)
