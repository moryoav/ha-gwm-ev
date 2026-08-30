"""Packaging boundary and bundled protocol-material provenance tests."""

from __future__ import annotations

import hashlib
import json
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from custom_components.gwm_ora.cloud_auth import _RESOURCE_DIRECTORY
from gwm_client.crypto import load_certificate, recover_transformed_private_key

ROOT = Path(__file__).resolve().parents[2]
RESOURCE_DIRECTORY = ROOT / "custom_components" / "gwm_ora" / "resources"
CLIENT_SOURCE_TAG = "v0.16.1"

EXPECTED_FILES = {
    "gwm_general.cer": (1529, "24886bad04d8b26aa2aafd3fb22c74bd1f2859d81499a39c561df4930429a03d"),
    "gwm_general.key": (732, "1fbaf6b3d46feab76f4bc73806cd08d79c7cfda6c5183ceb5fdc4d6720560da6"),
    "gwm_root.pem": (4517, "ffb870f997b2037df5873ef1d773100ab7c380ecb78c2ce4eab84144d5895665"),
    "gwm_general_rus.cer": (1529, "2df3b98cf422ddc69d30c57f1fdb824bd54fde41b3bfa8394a1bf0516617df6f"),
    "gwm_general_rus.key": (728, "ffd7c95ef5b45e66d62bb37acd037b84c860e3eea35cc1aba6c0b6246e715424"),
    "gwm_root_rus.pem": (4516, "822af12df026e88ea95cd4c5a74ac360933b9dc2b32981b1b8780a6bc4f1cdf4"),
}


def _load_provenance() -> dict:
    return json.loads((RESOURCE_DIRECTORY / "provenance.json").read_text(encoding="utf-8"))


def _parse_instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_resource_bytes(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def test_integration_resources_match_the_provenance_inventory() -> None:
    provenance = _load_provenance()
    records = {record["path"]: record for record in provenance["resources"]}

    assert provenance["schema_version"] == 1
    assert provenance["reviewed_at"] == "2026-08-30"
    assert provenance["license_reference"] == "LicenseRef-GWM-Protocol-Materials"
    assert provenance["content_canonicalization"] == "utf8_lf"
    assert provenance["renewal_lead_days"] == 90
    assert set(records) == set(EXPECTED_FILES)
    assert {path.name for path in RESOURCE_DIRECTORY.iterdir()} == {*EXPECTED_FILES, "provenance.json"}

    for name, (expected_size, expected_hash) in EXPECTED_FILES.items():
        data = (RESOURCE_DIRECTORY / name).read_bytes()
        canonical_data = _canonical_resource_bytes(data)
        record = records[name]
        assert len(canonical_data) == expected_size == record["bytes"]
        assert hashlib.sha256(canonical_data).hexdigest() == expected_hash == record["sha256"]
        if normalized_upstream_hash := record.get("normalized_upstream_sha256"):
            assert hashlib.sha256(canonical_data).hexdigest() == normalized_upstream_hash


def test_bootstrap_certificate_metadata_keys_and_renewal_controls_are_exact() -> None:
    provenance = _load_provenance()
    records = {record["path"]: record for record in provenance["resources"]}

    for certificate_name, key_name in (
        ("gwm_general.cer", "gwm_general.key"),
        ("gwm_general_rus.cer", "gwm_general_rus.key"),
    ):
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
        assert datetime.now(UTC) < renew_by
        assert hashlib.sha256(
            certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest() == record["spki_sha256"]
        assert private_key.key_size == records[key_name]["rsa_bits"]
        assert private_key.public_key().public_numbers() == certificate.public_key().public_numbers()

    for bundle_name in ("gwm_root.pem", "gwm_root_rus.pem"):
        bundle = (RESOURCE_DIRECTORY / bundle_name).read_bytes()
        assert bundle.count(b"-----BEGIN CERTIFICATE-----") == records[bundle_name]["certificate_count"]


def test_packaging_decision_keeps_the_client_separate_and_activates_test_pin() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    manifest = json.loads(
        (ROOT / "custom_components" / "gwm_ora" / "manifest.json").read_text(encoding="utf-8")
    )

    assert project["name"] == "gwm-client"
    assert project["version"] == "0.1.0"
    assert project["requires-python"] == ">=3.13"
    assert project["license"] == "MIT AND LicenseRef-GWM-Protocol-Materials"
    assert project["license-files"] == ["LICENSE", "THIRD_PARTY_NOTICES.md"]
    assert set(project["dependencies"]) == {
        "aiohttp>=3.13.3,<4",
        "cryptography>=46.0.2",
        "yarl>=1.22.0,<2",
    }
    assert manifest["requirements"] == [
        "gwm-client@https://github.com/moryoav/ha-gwm-ev/archive/refs/tags/"
        f"{CLIENT_SOURCE_TAG}.zip"
    ]
    assert manifest["version"] == "0.16.1"
    assert manifest["integration_type"] == "hub"
    assert manifest["loggers"] == ["gwm_client"]
    assert manifest["domain"] == "gwm_ora"
    assert _RESOURCE_DIRECTORY == RESOURCE_DIRECTORY
    assert (ROOT / "gwm_client" / "__init__.py").is_file()
    assert not (ROOT / "gwm_ora_client").exists()
    assert not (ROOT / "addons").exists()
    assert not any(
        path.suffix.casefold() in {".cer", ".key", ".pem"}
        for path in (ROOT / "gwm_client").rglob("*")
    )


def test_protocol_material_notice_is_shipped_with_the_hacs_integration() -> None:
    root_notice = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    integration_notice = (
        ROOT / "custom_components" / "gwm_ora" / "THIRD_PARTY_NOTICES.md"
    ).read_text(encoding="utf-8")

    assert integration_notice == root_notice
    assert "LicenseRef-GWM-Protocol-Materials" in root_notice
    assert "immutable source dependency" in root_notice
    assert "I will not publish the client package or make a production release" in root_notice


def test_new_client_name_has_only_explicit_legacy_compatibility_values() -> None:
    allowed_lines = {
        "anz_auth.py": {'_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-anz-account-v1\\0"'},
        "china_client.py": {'_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-china-account-v1\\0"'},
        "eu_auth.py": {'_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-eu-account-v1\\0"'},
        "live_poc.py": {'/ "gwm_ora"'},
        "russia_auth.py": {
            '_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-russia-account-v1\\0"',
            '_LEGACY_APP_MODEL = "ha-gwm-ora"',
        },
    }
    actual_lines: dict[str, set[str]] = {}

    for path in sorted((ROOT / "gwm_client").glob("*.py")):
        matching_lines = {
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if any(marker in line for marker in ("gwm-ora", "gwm_ora", "GwmOra", "GWM ORA"))
        }
        if matching_lines:
            actual_lines[path.name] = matching_lines

    assert actual_lines == allowed_lines
