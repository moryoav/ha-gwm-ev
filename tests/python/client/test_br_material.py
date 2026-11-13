"""BR mTLS material loading with dummy certificates generated in a temp dir."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest
from cryptography import x509
from support.br import write_dummy_material, write_quirky_material

from custom_components.gwm_ora.gwm_client.br_material import BrMaterial, create_br_ssl_context, load_br_material


def _chain_count(material: BrMaterial) -> int:
    return material.chain_pem.count(b"BEGIN CERTIFICATE")


def test_builds_chain_from_leaf_plus_whole_bundle(tmp_path: Path) -> None:
    """Check that the leaf is followed by the whole CA bundle and the repr hides PEM content."""
    write_dummy_material(tmp_path)
    material = load_br_material(tmp_path)
    assert _chain_count(material) == 4  # leaf + the 3 bundle certificates
    assert "BEGIN" not in repr(material)
    assert material.chain_pem.startswith((tmp_path / "gwm_general.cer").read_bytes().strip())
    assert material.chain_pem.strip().endswith(b"-----END CERTIFICATE-----")


def test_vendor_certificates_rejected_by_cryptography_still_load(tmp_path: Path) -> None:
    """Regression: PrintableString emailAddress with "@" breaks the strict parser, not OpenSSL."""
    write_quirky_material(tmp_path)
    for name in ("gwm_general.cer", "gwm_root.cer"):
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate((tmp_path / name).read_bytes().split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n")
    material = load_br_material(tmp_path)
    assert _chain_count(material) == 3
    context = create_br_ssl_context(material)
    assert context.security_level == 0
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_material_post_init_is_textual_only() -> None:
    """Check that BrMaterial validates PEM markers textually and rejects bad chain or key with a redacted error."""
    from custom_components.gwm_ora.gwm_client import br_material

    assert not hasattr(br_material, "x509")
    block = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    key = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    assert BrMaterial(block + block, key)
    for chain, private in ((block, key), (block + block, b"nothing")):
        with pytest.raises(ValueError, match="^br_material_invalid$"):
            BrMaterial(chain, private)


def test_context_is_mtls_scoped_security_level_zero(tmp_path: Path) -> None:
    """Check that the mTLS context uses security level zero while default contexts stay stricter."""
    write_dummy_material(tmp_path)
    context = create_br_ssl_context(load_br_material(tmp_path))
    assert context.security_level == 0
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert create_default_level() > 0


def create_default_level() -> int:
    return ssl.create_default_context().security_level


def test_missing_key_fails_redacted(tmp_path: Path) -> None:
    """Check that a missing key file raises the redacted material error."""
    write_dummy_material(tmp_path)
    (tmp_path / "gwm_general.key").unlink()
    with pytest.raises(ValueError, match="^br_material_invalid$"):
        load_br_material(tmp_path)


def test_key_not_matching_leaf_is_rejected_by_openssl(tmp_path: Path) -> None:
    """Check that OpenSSL rejects a private key that does not match the leaf certificate."""
    write_dummy_material(tmp_path, key_mismatch=True)
    material = load_br_material(tmp_path)
    with pytest.raises(ValueError, match="^br_material_invalid$"):
        create_br_ssl_context(material)


def test_relative_path_is_rejected() -> None:
    """Check that a relative path is refused as a material folder."""
    with pytest.raises(ValueError, match="^br_material_invalid$"):
        load_br_material(Path("relative"))


def test_bundled_material_loads_from_the_integration_package() -> None:
    """The shipped files work with no setup, and nothing in the checkout is refused."""
    from custom_components.gwm_ora.gwm_client import br_installed

    directory = br_installed.installed_br_directory()
    assert directory.is_relative_to(Path(__file__).resolve().parents[3] / "custom_components" / "gwm_ora")
    assert br_installed.missing_br_files(directory) == []
    material = br_installed.load_installed_br_material()
    assert _chain_count(material) == 4  # leaf + the 3 certificates of gwm_root.cer
    context = br_installed.load_installed_br_context()
    assert context.security_level == 0
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
