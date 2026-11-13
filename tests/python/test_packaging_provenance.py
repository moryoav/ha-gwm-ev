"""Packaging boundary and bundled protocol-material provenance tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from custom_components.gwm_ora import bean_tech_lock
from custom_components.gwm_ora.cloud_auth import _RESOURCE_DIRECTORY
from custom_components.gwm_ora.gwm_client.crypto import load_certificate, recover_transformed_private_key

ROOT = Path(__file__).resolve().parents[2]
RESOURCE_DIRECTORY = ROOT / "custom_components" / "gwm_ora" / "resources"
CLIENT_DIRECTORY = ROOT / "custom_components/gwm_ora/gwm_client"

EXPECTED_FILES = {
    "beantech_lock_encoder.bin": (235568, "741c5d031404643b18b8d3efb8e42715a58e4875bcf9071a213313a9c678f687"),
    "gwm_general.cer": (1529, "24886bad04d8b26aa2aafd3fb22c74bd1f2859d81499a39c561df4930429a03d"),
    "gwm_general.key": (732, "1fbaf6b3d46feab76f4bc73806cd08d79c7cfda6c5183ceb5fdc4d6720560da6"),
    "gwm_root.pem": (4517, "ffb870f997b2037df5873ef1d773100ab7c380ecb78c2ce4eab84144d5895665"),
    "gwm_general_rus.cer": (1529, "2df3b98cf422ddc69d30c57f1fdb824bd54fde41b3bfa8394a1bf0516617df6f"),
    "gwm_general_rus.key": (728, "ffd7c95ef5b45e66d62bb37acd037b84c860e3eea35cc1aba6c0b6246e715424"),
    "gwm_root_rus.pem": (4516, "822af12df026e88ea95cd4c5a74ac360933b9dc2b32981b1b8780a6bc4f1cdf4"),
    "apac/bootstrap.cer": (1529, "dd525a458253fcbfb01f4433de5930ddbc7bea1e521868a9d9cedb7ae8e222ef"),
    "apac/bootstrap.key": (728, "177f979899aa36a351e8f37315ed8c711624390bb6bab46fbe14c383def2c8b7"),
    "apac/ca.pem": (5988, "7c092608eec70d500a86c8682c9896adf4dca98e1fe4380eb5e1b82913f5a3b0"),
    "apac/signing.json": (76, "570a5bdc82073666955643a455063f6de83e8127d791939fe5fb30bf70b4281d"),
    "br/gwm_general.cer": (1507, "40a54928be2bd9ad81708dc2eb007bf9c70acfa212b136014647b3d32126a4c3"),
    "br/gwm_general.key": (1682, "f08816ed1c4181cd5b8b96fa8f7b94996dac15e8b2f3a13180ab6868554b0a66"),
    "br/gwm_root.cer": (4513, "428b1b29561efd2f5aba7f44909230631fd2315e620a9c235e7d3c3a9eee87a7"),
}


def _load_provenance() -> dict:
    return json.loads((RESOURCE_DIRECTORY / "provenance.json").read_text(encoding="utf-8"))


def _parse_instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_resource_bytes(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def test_integration_resources_match_the_provenance_inventory() -> None:
    """Pin each shipped resource to its documented size and digest."""
    provenance = _load_provenance()
    records = {record["path"]: record for record in provenance["resources"]}

    assert provenance["schema_version"] == 1
    assert provenance["reviewed_at"] == "2026-08-30"
    assert provenance["license_reference"] == "LicenseRef-GWM-Protocol-Materials"
    assert provenance["content_canonicalization"] == "utf8_lf"
    assert provenance["renewal_lead_days"] == 90
    assert set(records) == set(EXPECTED_FILES)
    assert {
        path.relative_to(RESOURCE_DIRECTORY).as_posix()
        for path in RESOURCE_DIRECTORY.rglob("*")
        if path.is_file()
    } == {*EXPECTED_FILES, "provenance.json"}

    for name, (expected_size, expected_hash) in EXPECTED_FILES.items():
        data = (RESOURCE_DIRECTORY / name).read_bytes()
        record = records[name]
        canonical_data = data if record.get("content_canonicalization") == "raw_bytes" else _canonical_resource_bytes(data)
        assert len(canonical_data) == expected_size == record["bytes"]
        assert hashlib.sha256(canonical_data).hexdigest() == expected_hash == record["sha256"]
        if normalized_upstream_hash := record.get("normalized_upstream_sha256"):
            assert hashlib.sha256(canonical_data).hexdigest() == normalized_upstream_hash

    encoder = records["beantech_lock_encoder.bin"]
    assert encoder["content_canonicalization"] == "raw_bytes"
    assert encoder["redistribution_permission"] == "unresolved"


def test_bean_tech_encoder_rejects_modified_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject a changed binary before the encoder can execute."""
    bundle = tmp_path / "beantech_lock_encoder.bin"
    verified = (RESOURCE_DIRECTORY / bundle.name).read_bytes()
    bundle.write_bytes(verified[:-1] + bytes([verified[-1] ^ 1]))
    monkeypatch.setattr(bean_tech_lock, "_ENCODER", bundle)

    with pytest.raises(bean_tech_lock.BeanTechLockPreparationError, match="bean_tech_lock_encoder_invalid"):
        bean_tech_lock._prepare_credential("000123")


@pytest.mark.parametrize(
    ("certificate_name", "key_name", "bundle_name"),
    [
        ("gwm_general.cer", "gwm_general.key", "gwm_root.pem"),
        ("gwm_general_rus.cer", "gwm_general_rus.key", "gwm_root_rus.pem"),
        ("apac/bootstrap.cer", "apac/bootstrap.key", "apac/ca.pem"),
    ],
    ids=["eu", "russia", "apac"],
)
def test_bootstrap_certificate_metadata_keys_and_renewal_controls_are_exact(
    certificate_name: str, key_name: str, bundle_name: str
) -> None:
    """Check each regional bundle's identity, key pairing, and renewal deadline independently."""
    provenance = _load_provenance()
    records = {record["path"]: record for record in provenance["resources"]}

    certificate_data = (RESOURCE_DIRECTORY / certificate_name).read_bytes()
    certificate = load_certificate(certificate_data)
    record = records[certificate_name]["certificate"]
    private_key = recover_transformed_private_key(
        certificate_data,
        (RESOURCE_DIRECTORY / key_name).read_bytes(),
    )

    assert format(certificate.serial_number, "x") == record["serial_hex"]
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == record[
        "subject_common_name"
    ]
    assert certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == record[
        "subject_country"
    ]
    assert certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == record[
        "issuer_common_name"
    ]
    assert certificate.not_valid_before_utc == _parse_instant(record["not_before"])
    assert certificate.not_valid_after_utc == _parse_instant(record["not_after"])
    renew_by = _parse_instant(record["renew_by"])
    assert renew_by == certificate.not_valid_after_utc - timedelta(days=90)
    assert hashlib.sha256(
        certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest() == record["spki_sha256"]
    assert records[key_name]["paired_certificate"] == certificate_name
    assert private_key.key_size == records[key_name]["rsa_bits"]
    assert private_key.public_key().public_numbers() == certificate.public_key().public_numbers()

    bundle = (RESOURCE_DIRECTORY / bundle_name).read_bytes()
    assert bundle.count(b"-----BEGIN CERTIFICATE-----") == records[bundle_name]["certificate_count"]


def test_brazil_bundle_identity_pairing_and_renewal_control_are_exact() -> None:
    """Check the Brazil files without ``cryptography``'s strict parser.

    The vendor certificates carry an ``emailAddress`` as a PrintableString containing "@",
    which rust-asn1 refuses, so the certificate is read by OpenSSL and the key by ``cryptography``.
    """
    import ssl
    import tempfile

    records = {record["path"]: record for record in _load_provenance()["resources"]}
    certificate_record = records["br/gwm_general.cer"]["certificate"]
    certificate_path = RESOURCE_DIRECTORY / "br" / "gwm_general.cer"
    decoded = ssl._ssl._test_decode_cert(str(certificate_path))  # OpenSSL-backed, no cryptography parser

    subject = {key: value for rdn in decoded["subject"] for key, value in rdn}
    issuer = {key: value for rdn in decoded["issuer"] for key, value in rdn}
    assert subject["commonName"] == certificate_record["subject_common_name"] == "LGWGWM-AD-BR-GENERAL"
    assert subject["countryName"] == certificate_record["subject_country"] == "BR"
    assert issuer["commonName"] == certificate_record["issuer_common_name"]
    assert decoded["serialNumber"].lower() == certificate_record["serial_hex"]
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notBefore"]), UTC)
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), UTC)
    assert not_before == _parse_instant(certificate_record["not_before"])
    assert not_after == _parse_instant(certificate_record["not_after"])
    assert _parse_instant(certificate_record["renew_by"]) == not_after - timedelta(days=90)

    key = serialization.load_pem_private_key((RESOURCE_DIRECTORY / "br" / "gwm_general.key").read_bytes(), None)
    assert key.key_size == records["br/gwm_general.key"]["rsa_bits"]
    assert records["br/gwm_general.key"]["paired_certificate"] == "br/gwm_general.cer"
    assert hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest() == certificate_record["spki_sha256"]

    bundle = (RESOURCE_DIRECTORY / "br" / "gwm_root.cer").read_bytes()
    assert bundle.count(b"-----BEGIN CERTIFICATE-----") == records["br/gwm_root.cer"]["certificate_count"]
    for name in ("gwm_general.cer", "gwm_general.key", "gwm_root.cer"):
        assert records[f"br/{name}"]["redistribution_permission"] == "unresolved"
    # Not a trust anchor check: only that OpenSSL accepts the bundled key with the leaf.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    with tempfile.TemporaryDirectory() as directory:
        pem = Path(directory) / "chain.pem"
        pem.write_bytes(certificate_path.read_bytes())
        context.load_cert_chain(str(pem), str(RESOURCE_DIRECTORY / "br" / "gwm_general.key"))


def test_protocol_material_is_confined_to_audited_resources() -> None:
    assert _RESOURCE_DIRECTORY == RESOURCE_DIRECTORY
    assert not any(
        path.suffix.casefold() in {".cer", ".key", ".pem"}
        for path in CLIENT_DIRECTORY.rglob("*")
    )


def test_bootstrap_renewal_deadlines_have_not_elapsed() -> None:
    now = datetime.now(UTC)
    overdue = {
        record["path"]: record["certificate"]["renew_by"]
        for record in _load_provenance()["resources"]
        if "certificate" in record
        and now >= _parse_instant(record["certificate"]["renew_by"])
    }
    assert not overdue, f"Bootstrap certificate renewal deadlines have elapsed: {overdue}"


def test_protocol_material_notice_is_shipped_with_the_hacs_integration() -> None:
    root_notice = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    integration_notice = (
        ROOT / "custom_components" / "gwm_ora" / "THIRD_PARTY_NOTICES.md"
    ).read_text(encoding="utf-8")

    assert integration_notice == root_notice
    assert "LicenseRef-GWM-Protocol-Materials" in root_notice
    assert (ROOT / "custom_components/gwm_ora/LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
