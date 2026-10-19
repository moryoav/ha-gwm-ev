"""One-shot, reuse-only live read proof for Task 3.

This module is deliberately narrower than a production client.  It accepts an
existing add-on access token/device identity, exposes exactly two GET routes,
does not refresh or log in, and emits only schema-level evidence.  Task 4 will
replace this synchronous proof with the typed async client foundation.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import ssl
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .crypto import load_certificate, recover_transformed_private_key
from .signing import (
    ANZ_BT_AUTH,
    EU_BT_AUTH,
    RUSSIA_GWM_AUTH,
    SigningProfile,
    sign_request,
)
from .tls import create_gwm_ssl_context

Region = Literal["eu", "aus", "rus"]
ResponseReader = Callable[[Request, ssl.SSLContext, float], bytes]

_MAX_STATE_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_ACCESS_TOKEN_LENGTH = 16 * 1024
_MAX_VEHICLE_IDENTIFIER_LENGTH = 512
_IS_POSIX = os.name == "posix"
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PEM_CERTIFICATE = re.compile(
    br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)


class LivePocError(RuntimeError):
    """A failure category that never embeds cloud or credential material."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class _TransportError(Exception):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True, slots=True)
class ReusedPocState:
    """Only the existing state fields the reuse-only proof is allowed to read."""

    device_id: str = field(repr=False)
    access_token: str = field(repr=False)
    client_certificate: str | None = field(default=None, repr=False)
    client_private_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class LivePocEvidence:
    """Allowlisted, non-identifying evidence from one successful live read."""

    status: str
    region: Region
    auth_mode: str
    authenticated: bool
    mutual_tls: bool
    scoped_legacy_tls: bool
    default_tls_unchanged: bool
    request_count: int
    endpoint_aliases: tuple[str, ...]
    vehicle_found: bool
    vehicle_metadata_present: bool
    status_received: bool
    status_items_present: bool
    status_values_present: bool
    location_fields_present: bool
    state_timestamps_present: bool
    soc_signal_present: bool
    charging_signal_present: bool

    def to_json(self) -> str:
        """Serialize only the explicitly safe evidence fields."""

        return json.dumps(asdict(self), indent=2, sort_keys=True)


@dataclass(frozen=True, slots=True)
class _RegionSettings:
    region: Region
    app_base_url: str
    profile: SigningProfile
    device_id_length: int | None
    base_headers: Mapping[str, str]
    ca_bundle: str | None
    bootstrap_certificate: str | None
    bootstrap_key: str | None

    @property
    def uses_mutual_tls(self) -> bool:
        return self.region in {"eu", "rus"}

    @property
    def uses_legacy_tls(self) -> bool:
        return self.region in {"eu", "rus"}


_EU_HEADERS = {
    "rs": "2",
    "terminal": "GW_APP_GWM",
    "brand": "6",
    "language": "en",
    "systemType": "1",
    "cVer": "1.3.0",
    "secVersion": "2.0",
    "appId": "6",
    "channel": "APP",
    "enterpriseId": "CC01",
}

_ANZ_HEADERS = {
    "rs": "2",
    "terminal": "GW_APP_Haval",
    "brand": "1",
    "enterpriseId": "CC01",
    "appId": "1",
    "channel": "APP",
    "cVer": "1.0.0",
    "systemType": "1",
    "language": "en_US",
}

_RUSSIA_HEADERS = {
    "rs": "2",
    "terminal": "GW_APP_Haval",
    "brand": "1",
    "enterpriseId": "CC01",
    "brandId": "CCZ001",
    "appId": "1",
    "channel": "APP",
    "systemType": "1",
    "cVer": "1.0.0",
    "communityBrand": "1",
    "language": "ru",
    "secVersion": "2.0",
}

_SAFE_TRANSPORT_CATEGORIES = frozenset(
    {
        "http_error",
        "http_auth_rejected",
        "network_error",
        "network_timeout",
        "redirect_rejected",
        "response_too_large",
        "tls_error",
    }
)


def load_reused_poc_state(
    path: str | os.PathLike[str],
    *,
    repository_root: Path,
) -> ReusedPocState:
    """Read a disposable state copy without retaining unrelated secret fields."""

    try:
        state_path = Path(path).resolve(strict=True)
        root = repository_root.resolve(strict=True)
    except OSError as error:
        raise LivePocError("state_unavailable") from error

    if state_path == root or state_path.is_relative_to(root):
        raise LivePocError("state_must_be_outside_repository")
    if not state_path.is_file() or state_path.stat().st_size > _MAX_STATE_BYTES:
        raise LivePocError("state_invalid")

    try:
        with state_path.open("rb") as state_file:
            encoded = state_file.read(_MAX_STATE_BYTES + 1)
    except OSError as error:
        raise LivePocError("state_invalid") from error
    if len(encoded) > _MAX_STATE_BYTES:
        raise LivePocError("state_invalid")
    try:
        decoded = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LivePocError("state_invalid") from error
    if not isinstance(decoded, Mapping):
        raise LivePocError("state_invalid")

    device_id = _required_secret_string(decoded, "device_id")
    access_token = _required_secret_string(decoded, "access_token")
    certificate = _optional_secret_string(decoded, "client_certificate")
    private_key = _optional_secret_string(decoded, "client_private_key")
    return ReusedPocState(
        device_id=device_id,
        access_token=access_token,
        client_certificate=certificate,
        client_private_key=private_key,
    )


def run_reused_state_poc(
    *,
    region: str,
    country: str,
    state: ReusedPocState,
    resource_dir: Path | None = None,
    timeout: float = 20.0,
    response_reader: ResponseReader | None = None,
) -> LivePocEvidence:
    """Perform the approved two-request, read-only live proof once."""

    settings = _settings_for_region(region)
    normalized_country = country.strip().upper()
    if re.fullmatch(r"[A-Z]{2}", normalized_country) is None:
        raise LivePocError("country_invalid")
    if settings.region == "aus" and normalized_country not in {"AU", "NZ"}:
        raise LivePocError("country_region_mismatch")
    if settings.region == "rus" and normalized_country != "RU":
        raise LivePocError("country_region_mismatch")
    if settings.uses_mutual_tls and not _IS_POSIX:
        raise LivePocError("posix_runtime_required")
    if timeout <= 0 or timeout > 60:
        raise LivePocError("timeout_invalid")

    headers = _request_headers(settings, normalized_country, state)
    resources = resource_dir or _default_resource_dir()
    default_before = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if default_before.security_level <= 0:
        raise LivePocError("default_tls_already_downgraded")
    default_https_factory = ssl._create_default_https_context
    default_fingerprint = _tls_policy_fingerprint(default_before)

    app_context = _build_app_context(settings, state, resources)
    default_after = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    default_unchanged = (
        _tls_policy_fingerprint(default_after) == default_fingerprint
        and ssl._create_default_https_context is default_https_factory
    )
    context_verified = (
        app_context.check_hostname
        and app_context.verify_mode == ssl.CERT_REQUIRED
    )
    expected_app_security_level = 0 if settings.uses_legacy_tls else default_before.security_level
    if (
        not context_verified
        or app_context.security_level != expected_app_security_level
        or (
            not settings.uses_legacy_tls
            and _tls_policy_fingerprint(app_context) != default_fingerprint
        )
        or not default_unchanged
    ):
        raise LivePocError("tls_isolation_failed")

    reader = response_reader or _read_https_response

    vehicles_data = _get_enveloped_data(
        alias="acquire_vehicles",
        base_url=settings.app_base_url,
        relative_url="globalapp/vehicle/acquireVehicles",
        settings=settings,
        headers=headers,
        context=app_context,
        timeout=timeout,
        response_reader=reader,
    )
    if not isinstance(vehicles_data, list):
        raise LivePocError("vehicle_list_schema_error")
    vehicles = [vehicle for vehicle in vehicles_data if isinstance(vehicle, Mapping)]
    if not vehicles:
        raise LivePocError("no_vehicle_available")

    vehicle = next(
        (candidate for candidate in vehicles if candidate.get("defaultVehicle") is True),
        vehicles[0],
    )
    vin = vehicle.get("vin")
    if not isinstance(vin, str) or not _is_allowed_vehicle_identifier(vin):
        raise LivePocError("vehicle_identity_schema_error")

    status_data = _get_enveloped_data(
        alias="last_status",
        base_url=settings.app_base_url,
        relative_url=f"vehicle/getLastStatus?vin={quote(vin, safe='')}&seqNo=",
        settings=settings,
        headers=headers,
        context=app_context,
        timeout=timeout,
        response_reader=reader,
    )
    if not isinstance(status_data, Mapping):
        raise LivePocError("vehicle_status_schema_error")

    items_value = status_data.get("items")
    items = (
        [item for item in items_value if isinstance(item, Mapping)]
        if isinstance(items_value, list)
        else []
    )
    item_codes = {
        str(item.get("code"))
        for item in items
        if item.get("code") is not None
    }
    return LivePocEvidence(
        status="success",
        region=settings.region,
        auth_mode="reused_access",
        authenticated=True,
        mutual_tls=settings.uses_mutual_tls,
        scoped_legacy_tls=settings.uses_legacy_tls,
        default_tls_unchanged=default_unchanged,
        request_count=2,
        endpoint_aliases=("acquire_vehicles", "last_status"),
        vehicle_found=True,
        vehicle_metadata_present=any(
            vehicle.get(name) is not None and vehicle.get(name) != ""
            for name in ("brandName", "modelName", "vTypeName", "appShowSeriesName")
        ),
        status_received=True,
        status_items_present=bool(items),
        status_values_present=any(item.get("value") is not None for item in items),
        location_fields_present=(
            status_data.get("latitude") is not None
            or status_data.get("longitude") is not None
        ),
        state_timestamps_present=(
            status_data.get("acquisitionTime") is not None
            or status_data.get("updateTime") is not None
        ),
        soc_signal_present="2013021" in item_codes,
        charging_signal_present=bool({"2041142", "2042082"} & item_codes),
    )


def _settings_for_region(region: str) -> _RegionSettings:
    normalized = region.strip().lower()
    if normalized == "eu":
        return _RegionSettings(
            region="eu",
            app_base_url="https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/",
            profile=EU_BT_AUTH,
            device_id_length=16,
            base_headers=_EU_HEADERS,
            ca_bundle="gwm_root.pem",
            bootstrap_certificate=None,
            bootstrap_key=None,
        )
    if normalized == "aus":
        base_url = "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/"
        return _RegionSettings(
            region="aus",
            app_base_url=base_url,
            profile=ANZ_BT_AUTH,
            device_id_length=16,
            base_headers=_ANZ_HEADERS,
            ca_bundle=None,
            bootstrap_certificate=None,
            bootstrap_key=None,
        )
    if normalized == "rus":
        return _RegionSettings(
            region="rus",
            app_base_url="https://rus-app-gateway.gwmcloud.com/app-api/api/v1.0/",
            profile=RUSSIA_GWM_AUTH,
            device_id_length=None,
            base_headers=_RUSSIA_HEADERS,
            ca_bundle="gwm_root_rus.pem",
            bootstrap_certificate="gwm_general_rus.cer",
            bootstrap_key="gwm_general_rus.key",
        )
    raise LivePocError("region_invalid")


def _request_headers(
    settings: _RegionSettings,
    country: str,
    state: ReusedPocState,
) -> dict[str, str]:
    raw_device_id = state.device_id
    if (
        len(raw_device_id) > 64
        or re.fullmatch(r"[0-9A-Fa-f-]+", raw_device_id) is None
    ):
        raise LivePocError("state_invalid")
    if (
        not state.access_token
        or len(state.access_token) > _MAX_ACCESS_TOKEN_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in state.access_token)
    ):
        raise LivePocError("state_invalid")

    normalized_device_id = raw_device_id
    if settings.device_id_length is not None:
        normalized_device_id = normalized_device_id.replace("-", "")
        normalized_device_id = (
            normalized_device_id[: settings.device_id_length]
            if len(normalized_device_id) >= settings.device_id_length
            else normalized_device_id.ljust(settings.device_id_length, "0")
        )
    if not normalized_device_id or not normalized_device_id.replace("-", ""):
        raise LivePocError("state_invalid")

    return {
        **settings.base_headers,
        "country": country,
        "regionCode": country,
        "deviceId": normalized_device_id,
        "iccid": normalized_device_id,
        "accessToken": state.access_token,
        "Accept": "application/json",
    }


def _build_app_context(
    settings: _RegionSettings,
    state: ReusedPocState,
    resource_dir: Path,
) -> ssl.SSLContext:
    if settings.region == "aus":
        return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    if settings.ca_bundle is None:
        raise LivePocError("tls_material_invalid")
    try:
        ca_data = (resource_dir / settings.ca_bundle).read_bytes()
    except OSError as error:
        raise LivePocError("tls_material_unavailable") from error

    if settings.region == "eu":
        certificate, private_key = _load_stored_identity(state)
    else:
        certificate, private_key = _load_bootstrap_identity(settings, resource_dir)
    _validate_identity(certificate, private_key)
    cert_chain = _client_certificate_chain(certificate, ca_data)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    try:
        with tempfile.TemporaryDirectory(prefix="gwm-poc-") as temp_directory:
            directory = Path(temp_directory)
            directory.chmod(0o700)
            certfile = directory / "client.pem"
            keyfile = directory / "client.key"
            certfile.write_bytes(cert_chain)
            keyfile.write_bytes(key_pem)
            certfile.chmod(0o600)
            keyfile.chmod(0o600)
            return create_gwm_ssl_context(
                ca_data=ca_data,
                certfile=certfile,
                keyfile=keyfile,
            )
    except (OSError, ssl.SSLError, ValueError) as error:
        raise LivePocError("tls_material_invalid") from error


def _load_stored_identity(
    state: ReusedPocState,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    if state.client_certificate is None or state.client_private_key is None:
        raise LivePocError("eu_client_identity_required")
    try:
        certificate = load_certificate(_decode_secret_base64(state.client_certificate))
        loaded_key = serialization.load_der_private_key(
            _decode_secret_base64(state.client_private_key),
            password=None,
        )
    except (ValueError, TypeError, binascii.Error) as error:
        raise LivePocError("eu_client_identity_invalid") from error
    if not isinstance(loaded_key, rsa.RSAPrivateKey):
        raise LivePocError("eu_client_identity_invalid")
    return certificate, loaded_key


def _load_bootstrap_identity(
    settings: _RegionSettings,
    resource_dir: Path,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    if settings.bootstrap_certificate is None or settings.bootstrap_key is None:
        raise LivePocError("tls_material_invalid")
    try:
        certificate_data = (resource_dir / settings.bootstrap_certificate).read_bytes()
        key_data = (resource_dir / settings.bootstrap_key).read_bytes()
        return (
            load_certificate(certificate_data),
            recover_transformed_private_key(certificate_data, key_data),
        )
    except (OSError, TypeError, ValueError, binascii.Error) as error:
        raise LivePocError("tls_material_invalid") from error


def _validate_identity(
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
) -> None:
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise LivePocError("tls_material_invalid")
    if public_key.public_numbers() != private_key.public_key().public_numbers():
        raise LivePocError("tls_identity_mismatch")
    not_valid_before, not_valid_after = _certificate_validity_utc(certificate)
    now = datetime.now(UTC)
    if not_valid_before > now + timedelta(minutes=5):
        raise LivePocError("tls_identity_not_yet_valid")
    if not_valid_after <= now + timedelta(days=1):
        raise LivePocError("tls_identity_expired")


def _certificate_validity_utc(
    certificate: x509.Certificate,
) -> tuple[datetime, datetime]:
    not_valid_before = getattr(certificate, "not_valid_before_utc", None)
    not_valid_after = getattr(certificate, "not_valid_after_utc", None)
    if not_valid_before is None or not_valid_after is None:
        not_valid_before = certificate.not_valid_before.replace(tzinfo=UTC)
        not_valid_after = certificate.not_valid_after.replace(tzinfo=UTC)
    return not_valid_before, not_valid_after


def _client_certificate_chain(
    certificate: x509.Certificate,
    ca_data: bytes,
) -> bytes:
    leaf = certificate.public_bytes(serialization.Encoding.PEM)
    issuer_attributes = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not issuer_attributes:
        raise LivePocError("tls_material_invalid")

    issuer_name = issuer_attributes[0].value.strip()
    blocks = _PEM_CERTIFICATE.findall(ca_data)
    if issuer_name == "IOV APP General SubCA":
        matches = [block for block in blocks if b"IOV APP General SubCA" in _pem_der(block)]
    elif issuer_name == "IOV APP SubCA":
        matches = [
            block
            for block in blocks
            if b"IOV APP SubCA" in _pem_der(block)
            and b"IOV APP General SubCA" not in _pem_der(block)
        ]
    else:
        raise LivePocError("tls_material_invalid")
    if len(matches) != 1:
        raise LivePocError("tls_material_invalid")
    return leaf + matches[0]


def _pem_der(block: bytes) -> bytes:
    lines = [line for line in block.splitlines() if not line.startswith(b"-----")]
    try:
        return base64.b64decode(b"".join(lines), validate=True)
    except binascii.Error as error:
        raise LivePocError("tls_material_invalid") from error


def _get_enveloped_data(
    *,
    alias: str,
    base_url: str,
    relative_url: str,
    settings: _RegionSettings,
    headers: Mapping[str, str],
    context: ssl.SSLContext,
    timeout: float,
    response_reader: ResponseReader,
) -> Any:
    unsigned_url = base_url + relative_url
    signed = sign_request(settings.profile, "GET", unsigned_url)
    request = Request(
        signed.url,
        headers={**headers, **signed.headers},
        method="GET",
    )
    _assert_allowed_request(alias, request, settings)
    try:
        encoded = response_reader(request, context, timeout)
    except _TransportError as error:
        if error.category == "http_auth_rejected":
            raise LivePocError("auth_rejected") from None
        category = (
            error.category
            if error.category in _SAFE_TRANSPORT_CATEGORIES
            else "transport_error"
        )
        raise LivePocError(category) from None
    except Exception:
        raise LivePocError("transport_error") from None

    try:
        envelope = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LivePocError(f"{alias}_schema_error") from None
    if not isinstance(envelope, Mapping):
        raise LivePocError(f"{alias}_schema_error")

    code = envelope.get("code")
    if code != "000000":
        category = (
            "auth_or_vehicle_discovery_rejected"
            if alias == "acquire_vehicles"
            else f"{alias}_rejected"
        )
        raise LivePocError(category)
    if "data" not in envelope:
        raise LivePocError(f"{alias}_schema_error")
    return envelope["data"]


def _assert_allowed_request(
    alias: str,
    request: Request,
    settings: _RegionSettings,
) -> None:
    if request.get_method() != "GET":
        raise LivePocError("write_request_blocked")

    parsed = urlsplit(request.full_url)
    expected = {
        "acquire_vehicles": (
            urlsplit(settings.app_base_url).hostname,
            "/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        ),
        "last_status": (
            urlsplit(settings.app_base_url).hostname,
            "/app-api/api/v1.0/vehicle/getLastStatus",
        ),
    }.get(alias)
    try:
        port = parsed.port
    except ValueError:
        raise LivePocError("request_not_allowlisted") from None
    if (
        expected is None
        or parsed.scheme != "https"
        or parsed.hostname != expected[0]
        or parsed.path != expected[1]
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise LivePocError("request_not_allowlisted")

    if alias == "acquire_vehicles":
        if parsed.query:
            raise LivePocError("request_not_allowlisted")
        return
    if alias == "last_status":
        tokens = parsed.query.split("&")
        expected_count = 2 if settings.region == "eu" else 1
        if len(tokens) != expected_count:
            raise LivePocError("request_not_allowlisted")
        vin_key, separator, encoded_vin = tokens[0].partition("=")
        try:
            decoded_vin = unquote(
                encoded_vin,
                encoding="utf-8",
                errors="strict",
            )
        except UnicodeDecodeError:
            raise LivePocError("request_not_allowlisted") from None
        expected_query = f"vin={encoded_vin}" + (
            "&seqNo=" if settings.region == "eu" else ""
        )
        if (
            vin_key != "vin"
            or separator != "="
            or _INVALID_PERCENT_ESCAPE.search(encoded_vin) is not None
            or quote(decoded_vin, safe="") != encoded_vin
            or not _is_allowed_vehicle_identifier(decoded_vin)
            or (settings.region == "eu" and tokens[1] != "seqNo=")
            or parsed.query != expected_query
        ):
            raise LivePocError("request_not_allowlisted")


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        raise _TransportError("redirect_rejected")


def _read_https_response(
    request: Request,
    context: ssl.SSLContext,
    timeout: float,
) -> bytes:
    opener = build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=context),
        _RejectRedirects(),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            content = response.read(_MAX_RESPONSE_BYTES + 1)
    except _TransportError:
        raise
    except HTTPError as error:
        category = "http_auth_rejected" if error.code in {401, 403} else "http_error"
        raise _TransportError(category) from None
    except (ssl.SSLError, ssl.CertificateError):
        raise _TransportError("tls_error") from None
    except URLError as error:
        category = "tls_error" if isinstance(error.reason, ssl.SSLError) else "network_error"
        raise _TransportError(category) from None
    except TimeoutError:
        raise _TransportError("network_timeout") from None
    except OSError:
        raise _TransportError("network_error") from None

    if len(content) > _MAX_RESPONSE_BYTES:
        raise _TransportError("response_too_large")
    return content


def _tls_policy_fingerprint(context: ssl.SSLContext) -> tuple[Any, ...]:
    return (
        context.security_level,
        context.minimum_version,
        context.maximum_version,
        context.check_hostname,
        context.verify_mode,
        tuple(
            (
                cipher["name"],
                cipher["protocol"],
                cipher["strength_bits"],
            )
            for cipher in context.get_ciphers()
        ),
    )


def _is_allowed_vehicle_identifier(value: str) -> bool:
    return (
        0 < len(value) <= _MAX_VEHICLE_IDENTIFIER_LENGTH
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _required_secret_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LivePocError("state_missing_required_fields")
    return value.strip()


def _optional_secret_string(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _decode_secret_base64(value: str) -> bytes:
    return base64.b64decode("".join(value.split()), validate=True)


def _default_resource_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "resources"


def main() -> int:
    """Run the guarded POC from environment-only configuration."""

    if os.environ.get("GWM_POC_LIVE_READ_APPROVED") != "yes":
        print('{"category":"live_read_not_acknowledged","status":"failed"}', file=sys.stderr)
        return 2

    state_path = os.environ.get("GWM_POC_STATE_PATH")
    region = os.environ.get("GWM_POC_REGION")
    country = os.environ.get("GWM_POC_COUNTRY")
    if not state_path or not region or not country:
        print('{"category":"configuration_missing","status":"failed"}', file=sys.stderr)
        return 2

    try:
        state = load_reused_poc_state(
            state_path,
            repository_root=Path(__file__).resolve().parents[3],
        )
        evidence = run_reused_state_poc(
            region=region,
            country=country,
            state=state,
        )
    except LivePocError as error:
        print(
            json.dumps({"category": error.category, "status": "failed"}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    except Exception:
        print('{"category":"unexpected_error","status":"failed"}', file=sys.stderr)
        return 1

    print(evidence.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
