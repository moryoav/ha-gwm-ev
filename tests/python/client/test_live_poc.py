"""Offline safety and contract tests for the disposable Task 3 live proof."""

from __future__ import annotations

import base64
import json
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from custom_components.gwm_ora.gwm_client import live_poc
from custom_components.gwm_ora.gwm_client.crypto import load_certificate

RESOURCE_DIR = (
    Path(__file__).resolve().parents[3]
    / "custom_components"
    / "gwm_ora"
    / "resources"
)
DEVICE_ID = "01234567-89ab-cdef-0123-456789abcdef"
NORMALIZED_DEVICE_ID = "0123456789abcdef"
ACCESS_TOKEN = "task3-token.SENSITIVE_+/="
VIN = "LGWEEUA50NK123456"
SYNTHETIC_EU_VEHICLE_ID = (
    # Hex-encoded ``SYNTHETIC-OPAQUE-VEHICLE-ID-001``.
    "53594e5448455449432d4f50415155452d56454849434c452d49442d303031"
)
MODEL = "SENSITIVE VEHICLE MODEL"
LOCATION = "31.778,35.235"


class _CapturingReader:
    def __init__(self, *responses: object) -> None:
        self._responses = iter(responses)
        self.requests: list[Request] = []
        self.contexts: list[ssl.SSLContext] = []
        self.timeouts: list[float] = []

    def __call__(
        self,
        request: Request,
        context: ssl.SSLContext,
        timeout: float,
    ) -> bytes:
        self.requests.append(request)
        self.contexts.append(context)
        self.timeouts.append(timeout)
        return json.dumps(next(self._responses)).encode()


def _success(data: object) -> dict[str, object]:
    return {"code": "000000", "description": "success", "data": data}


def _vehicle_response(
    *,
    metadata: object = MODEL,
    vehicle_identifier: str = VIN,
) -> dict[str, object]:
    return _success(
        [
            {
                "defaultVehicle": True,
                "vin": vehicle_identifier,
                "modelName": metadata,
                "licenseNumber": "SENSITIVE-LICENSE",
            }
        ]
    )


def _status_response() -> dict[str, object]:
    return _success(
        {
            "latitude": 31.778,
            "longitude": 35.235,
            "acquisitionTime": 1_786_119_079_000,
            "updateTime": 1_786_119_080_000,
            "items": [
                {"code": "2013021", "value": "SENSITIVE-SOC"},
                {"code": "2041142", "value": "SENSITIVE-CHARGING"},
            ],
        }
    )


def _issued_eu_state(*, issuer_common_name: str = "IOV APP SubCA") -> live_poc.ReusedPocState:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Task 3 disposable test")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return live_poc.ReusedPocState(
        device_id=DEVICE_ID,
        access_token=ACCESS_TOKEN,
        client_certificate=base64.b64encode(
            certificate.public_bytes(serialization.Encoding.DER)
        ).decode("ascii"),
        client_private_key=base64.b64encode(
            private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ).decode("ascii"),
    )


def _headers(request: Request) -> dict[str, str]:
    return {name.lower(): value for name, value in request.header_items()}


def test_external_state_loads_only_reusable_fields_without_modifying_file(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    state_path = external / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "device_id": DEVICE_ID,
                "access_token": ACCESS_TOKEN,
                "refresh_token": "SENSITIVE-REFRESH",
                "api_token": "SENSITIVE-LOCAL-API-TOKEN",
                "client_certificate": " SENSITIVE-CERTIFICATE ",
                "client_private_key": " SENSITIVE-PRIVATE-KEY ",
                "charging_plans_set_by_addon": {VIN: {"plan_id": 1}},
            }
        ),
        encoding="utf-8",
    )
    before_bytes = state_path.read_bytes()
    before_stat = state_path.stat()

    state = live_poc.load_reused_poc_state(
        state_path,
        repository_root=repository,
    )

    assert state.device_id == DEVICE_ID
    assert state.access_token == ACCESS_TOKEN
    assert state.client_certificate == "SENSITIVE-CERTIFICATE"
    assert state.client_private_key == "SENSITIVE-PRIVATE-KEY"
    representation = repr(state)
    for secret in (
        DEVICE_ID,
        ACCESS_TOKEN,
        "SENSITIVE-CERTIFICATE",
        "SENSITIVE-PRIVATE-KEY",
        "SENSITIVE-REFRESH",
        "SENSITIVE-LOCAL-API-TOKEN",
        VIN,
    ):
        assert secret not in representation
    assert state_path.read_bytes() == before_bytes
    after_stat = state_path.stat()
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert after_stat.st_mode == before_stat.st_mode


def test_state_inside_repository_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    state_path = repository / "state.json"
    state_path.write_text(
        json.dumps({"device_id": DEVICE_ID, "access_token": ACCESS_TOKEN}),
        encoding="utf-8",
    )

    with pytest.raises(
        live_poc.LivePocError,
        match="^state_must_be_outside_repository$",
    ):
        live_poc.load_reused_poc_state(
            state_path,
            repository_root=repository,
        )


@pytest.mark.parametrize(
    ("device_id", "access_token"),
    [
        ("not-a-hex-device", ACCESS_TOKEN),
        ("a" * 65, ACCESS_TOKEN),
        (DEVICE_ID, "token\r\nInjected: value"),
        (DEVICE_ID, "token with spaces"),
        (DEVICE_ID, "x" * (16 * 1024 + 1)),
    ],
)
def test_header_unsafe_state_is_rejected_before_transport(
    device_id: str,
    access_token: str,
) -> None:
    called = False

    def reader(
        request: Request,
        context: ssl.SSLContext,
        timeout: float,
    ) -> bytes:
        nonlocal called
        called = True
        raise AssertionError((request, context, timeout))

    with pytest.raises(live_poc.LivePocError, match="^state_invalid$"):
        live_poc.run_reused_state_poc(
            region="aus",
            country="AU",
            state=live_poc.ReusedPocState(device_id, access_token),
            response_reader=reader,
        )

    assert not called


def test_anz_workflow_uses_two_allowlisted_gets_and_default_tls() -> None:
    reader = _CapturingReader(_vehicle_response(), _status_response())
    before = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    evidence = live_poc.run_reused_state_poc(
        region="aus",
        country="AU",
        state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
        response_reader=reader,
    )

    assert evidence.status == "success"
    assert evidence.region == "aus"
    assert evidence.authenticated
    assert not evidence.mutual_tls
    assert not evidence.scoped_legacy_tls
    assert evidence.default_tls_unchanged
    assert evidence.request_count == 2
    assert evidence.endpoint_aliases == ("acquire_vehicles", "last_status")
    assert evidence.vehicle_found
    assert evidence.vehicle_metadata_present
    assert evidence.status_received
    assert evidence.status_items_present
    assert evidence.status_values_present
    assert evidence.location_fields_present
    assert evidence.state_timestamps_present
    assert evidence.soc_signal_present
    assert evidence.charging_signal_present
    assert len(reader.requests) == 2
    assert reader.timeouts == [20.0, 20.0]
    assert all(request.get_method() == "GET" for request in reader.requests)
    assert [urlsplit(request.full_url).hostname for request in reader.requests] == [
        "aus-h5-gateway.gwmcloud.com",
        "aus-h5-gateway.gwmcloud.com",
    ]
    assert [urlsplit(request.full_url).path for request in reader.requests] == [
        "/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        "/app-api/api/v1.0/vehicle/getLastStatus",
    ]
    assert urlsplit(reader.requests[0].full_url).query == ""
    assert urlsplit(reader.requests[1].full_url).query == f"vin={VIN}"
    for request in reader.requests:
        headers = _headers(request)
        assert headers["accesstoken"] == ACCESS_TOKEN
        assert headers["deviceid"] == NORMALIZED_DEVICE_ID
        assert headers["iccid"] == NORMALIZED_DEVICE_ID
        assert headers["country"] == "AU"
        assert headers["regioncode"] == "AU"
        assert "bt-auth-sign" in headers
        assert not any(name.startswith("gwm-auth-") for name in headers)
    assert all(context.security_level == before.security_level for context in reader.contexts)
    assert all(context.check_hostname for context in reader.contexts)
    assert all(context.verify_mode == ssl.CERT_REQUIRED for context in reader.contexts)

    serialized = evidence.to_json()
    for sensitive in (
        DEVICE_ID,
        NORMALIZED_DEVICE_ID,
        ACCESS_TOKEN,
        VIN,
        MODEL,
        LOCATION,
        "31.778",
        "35.235",
        "SENSITIVE-SOC",
        "SENSITIVE-CHARGING",
        "SENSITIVE-LICENSE",
    ):
        assert sensitive not in serialized


def test_eu_workflow_preserves_empty_sequence_and_scopes_legacy_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_poc, "_IS_POSIX", True)
    reader = _CapturingReader(
        _vehicle_response(vehicle_identifier=SYNTHETIC_EU_VEHICLE_ID),
        _status_response(),
    )

    evidence = live_poc.run_reused_state_poc(
        region="eu",
        country="IL",
        state=_issued_eu_state(),
        resource_dir=RESOURCE_DIR,
        response_reader=reader,
    )

    assert evidence.region == "eu"
    assert evidence.mutual_tls
    assert evidence.scoped_legacy_tls
    assert evidence.default_tls_unchanged
    assert len(reader.requests) == 2
    assert all(
        urlsplit(request.full_url).hostname == "eu-app-gateway.gwmcloud.com"
        for request in reader.requests
    )
    assert urlsplit(reader.requests[1].full_url).query == (
        f"vin={SYNTHETIC_EU_VEHICLE_ID}&seqNo="
    )
    assert all(context.security_level == 0 for context in reader.contexts)
    for request in reader.requests:
        headers = _headers(request)
        assert "bt-auth-sign" in headers
        assert headers["deviceid"] == NORMALIZED_DEVICE_ID
    assert SYNTHETIC_EU_VEHICLE_ID not in evidence.to_json()


def test_russia_workflow_uses_app_gateway_gwm_auth_and_original_device_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_poc, "_IS_POSIX", True)
    reader = _CapturingReader(_vehicle_response(), _status_response())

    evidence = live_poc.run_reused_state_poc(
        region="rus",
        country="RU",
        state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
        resource_dir=RESOURCE_DIR,
        response_reader=reader,
    )

    assert evidence.region == "rus"
    assert evidence.mutual_tls
    assert evidence.scoped_legacy_tls
    assert evidence.default_tls_unchanged
    assert len(reader.requests) == 2
    assert all(
        urlsplit(request.full_url).hostname == "rus-app-gateway.gwmcloud.com"
        for request in reader.requests
    )
    assert urlsplit(reader.requests[1].full_url).query == f"vin={VIN}"
    assert all(context.security_level == 0 for context in reader.contexts)
    for request in reader.requests:
        headers = _headers(request)
        assert "gwm-auth-sign" in headers
        assert not any(name.startswith("bt-auth-") for name in headers)
        assert headers["deviceid"] == DEVICE_ID
        assert headers["iccid"] == DEVICE_ID
        assert headers["brandid"] == "CCZ001"
        assert headers["communitybrand"] == "1"


def test_mutual_tls_live_run_requires_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_poc, "_IS_POSIX", False)
    called = False

    def reader(
        request: Request,
        context: ssl.SSLContext,
        timeout: float,
    ) -> bytes:
        nonlocal called
        called = True
        raise AssertionError((request, context, timeout))

    with pytest.raises(live_poc.LivePocError, match="^posix_runtime_required$"):
        live_poc.run_reused_state_poc(
            region="eu",
            country="IL",
            state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
            response_reader=reader,
        )

    assert not called


@pytest.mark.parametrize(
    ("region", "country"),
    [("aus", "IL"), ("rus", "IL")],
)
def test_region_country_mismatch_is_rejected(region: str, country: str) -> None:
    with pytest.raises(live_poc.LivePocError, match="^country_region_mismatch$"):
        live_poc.run_reused_state_poc(
            region=region,
            country=country,
            state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
            response_reader=lambda request, context, timeout: b"",
        )


def test_discovery_rejection_stops_without_leaking_response() -> None:
    description = "SENSITIVE CLOUD ERROR WITH ACCOUNT DATA"
    reader = _CapturingReader(
        {"code": "607501", "description": description, "data": None}
    )

    with pytest.raises(
        live_poc.LivePocError,
        match="^auth_or_vehicle_discovery_rejected$",
    ) as raised:
        live_poc.run_reused_state_poc(
            region="aus",
            country="AU",
            state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
            response_reader=reader,
        )

    assert len(reader.requests) == 1
    assert description not in str(raised.value)
    assert ACCESS_TOKEN not in repr(raised.value)


def test_numeric_zero_response_is_not_accepted_as_protocol_success() -> None:
    reader = _CapturingReader({"code": 0, "description": "numeric", "data": []})

    with pytest.raises(
        live_poc.LivePocError,
        match="^auth_or_vehicle_discovery_rejected$",
    ):
        live_poc.run_reused_state_poc(
            region="aus",
            country="AU",
            state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
            response_reader=reader,
        )

    assert len(reader.requests) == 1


@pytest.mark.parametrize(
    ("vehicles", "category"),
    [
        ([], "no_vehicle_available"),
        ([{"defaultVehicle": True}], "vehicle_identity_schema_error"),
        ([{"defaultVehicle": True, "vin": "unsafe\nidentifier"}], "vehicle_identity_schema_error"),
        ([{"defaultVehicle": True, "vin": "x" * 513}], "vehicle_identity_schema_error"),
    ],
)
def test_invalid_vehicle_discovery_stops_before_status(
    vehicles: list[object],
    category: str,
) -> None:
    reader = _CapturingReader(_success(vehicles))

    with pytest.raises(live_poc.LivePocError, match=f"^{category}$"):
        live_poc.run_reused_state_poc(
            region="aus",
            country="AU",
            state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
            response_reader=reader,
        )

    assert len(reader.requests) == 1


def test_malformed_metadata_cannot_raise_or_escape_evidence() -> None:
    reader = _CapturingReader(
        _vehicle_response(metadata={"secret": MODEL}),
        _status_response(),
    )

    evidence = live_poc.run_reused_state_poc(
        region="aus",
        country="AU",
        state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
        response_reader=reader,
    )

    assert evidence.vehicle_metadata_present
    assert MODEL not in evidence.to_json()


def test_opaque_vehicle_identifier_is_canonically_encoded_and_redacted() -> None:
    opaque_identifier = "ENCODED+123/="
    reader = _CapturingReader(
        _vehicle_response(vehicle_identifier=opaque_identifier),
        _status_response(),
    )

    evidence = live_poc.run_reused_state_poc(
        region="aus",
        country="AU",
        state=live_poc.ReusedPocState(DEVICE_ID, ACCESS_TOKEN),
        response_reader=reader,
    )

    assert urlsplit(reader.requests[1].full_url).query == "vin=ENCODED%2B123%2F%3D"
    assert opaque_identifier not in evidence.to_json()
    assert "ENCODED%2B123%2F%3D" not in evidence.to_json()


def test_injected_transport_category_is_allowlisted() -> None:
    settings = live_poc._settings_for_region("aus")

    def reader(
        request: Request,
        context: ssl.SSLContext,
        timeout: float,
    ) -> bytes:
        raise live_poc._TransportError("SENSITIVE ARBITRARY CATEGORY")

    with pytest.raises(live_poc.LivePocError, match="^transport_error$") as raised:
        live_poc._get_enveloped_data(
            alias="acquire_vehicles",
            base_url=settings.app_base_url,
            relative_url="globalapp/vehicle/acquireVehicles",
            settings=settings,
            headers={},
            context=ssl.create_default_context(),
            timeout=1,
            response_reader=reader,
        )

    assert "SENSITIVE" not in str(raised.value)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_non_get_methods_are_blocked(method: str) -> None:
    settings = live_poc._settings_for_region("aus")
    request = Request(
        settings.app_base_url + "globalapp/vehicle/acquireVehicles",
        method=method,
    )

    with pytest.raises(live_poc.LivePocError, match="^write_request_blocked$"):
        live_poc._assert_allowed_request("acquire_vehicles", request, settings)


@pytest.mark.parametrize(
    "relative_url",
    [
        "vehicle/T5/sendCmd",
        "vehicle/modifyVehicleRemoteCtlInfo",
        "vehicleCharge/setChargingPlan",
        "user/loginAccount",
        "user/refreshToken",
        "userAuth/sendVerificationCode",
    ],
)
def test_mutation_and_session_routes_never_reach_transport(relative_url: str) -> None:
    settings = live_poc._settings_for_region("aus")
    called = False

    def reader(
        request: Request,
        context: ssl.SSLContext,
        timeout: float,
    ) -> bytes:
        nonlocal called
        called = True
        raise AssertionError((request, context, timeout))

    with pytest.raises(live_poc.LivePocError, match="^request_not_allowlisted$"):
        live_poc._get_enveloped_data(
            alias="last_status",
            base_url=settings.app_base_url,
            relative_url=relative_url,
            settings=settings,
            headers={},
            context=ssl.create_default_context(),
            timeout=1,
            response_reader=reader,
        )

    assert not called


@pytest.mark.parametrize(
    ("alias", "url"),
    [
        (
            "acquire_vehicles",
            "http://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        ),
        (
            "acquire_vehicles",
            "https://evil.example/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        ),
        (
            "acquire_vehicles",
            "https://aus-h5-gateway.gwmcloud.com:443/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        ),
        (
            "acquire_vehicles",
            "https://user@aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        ),
        (
            "acquire_vehicles",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles#fragment",
        ),
        (
            "acquire_vehicles",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles?extra=1",
        ),
        (
            "acquire_vehicles",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles?&",
        ),
        (
            "unknown_alias",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        ),
        (
            "last_status",
            f"https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin={VIN}&extra=1",
        ),
        (
            "last_status",
            f"https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin={VIN}&",
        ),
    ],
)
def test_request_origin_path_and_query_are_exactly_allowlisted(
    alias: str,
    url: str,
) -> None:
    settings = live_poc._settings_for_region("aus")

    with pytest.raises(live_poc.LivePocError, match="^request_not_allowlisted$"):
        live_poc._assert_allowed_request(alias, Request(url, method="GET"), settings)


@pytest.mark.parametrize(
    "query",
    [
        f"vin={VIN}&seqNo=unexpected",
        f"vin={VIN}&vin={VIN}",
        f"vin={VIN}=extra&seqNo=",
        "vin=&seqNo=",
        f"vin=%4C{VIN[1:]}&seqNo=",
        "vin=%ZZ&seqNo=",
        f"vin={VIN}",
        f"&vin={VIN}&seqNo=",
        f"vin={VIN}&seqNo=&",
    ],
)
def test_eu_status_query_rejects_noncanonical_shapes(query: str) -> None:
    settings = live_poc._settings_for_region("eu")
    request = Request(
        settings.app_base_url + "vehicle/getLastStatus?" + query,
        method="GET",
    )

    with pytest.raises(live_poc.LivePocError, match="^request_not_allowlisted$"):
        live_poc._assert_allowed_request("last_status", request, settings)


def test_status_query_accepts_only_each_regions_signed_shape() -> None:
    eu = live_poc._settings_for_region("eu")
    anz = live_poc._settings_for_region("aus")

    live_poc._assert_allowed_request(
        "last_status",
        Request(
            eu.app_base_url + f"vehicle/getLastStatus?vin={VIN}&seqNo=",
            method="GET",
        ),
        eu,
    )
    live_poc._assert_allowed_request(
        "last_status",
        Request(
            anz.app_base_url + f"vehicle/getLastStatus?vin={VIN}",
            method="GET",
        ),
        anz,
    )


def test_redirect_handler_fails_closed_without_exposing_location() -> None:
    destination = "https://evil.example/SENSITIVE-REDIRECT"
    handler = live_poc._RejectRedirects()

    with pytest.raises(live_poc._TransportError, match="^redirect_rejected$") as raised:
        handler.redirect_request(
            Request("https://example.invalid"),
            None,
            302,
            "Found",
            {},
            destination,
        )

    assert destination not in str(raised.value)


def test_response_reader_disables_proxies_and_bounds_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers: tuple[object, ...] = ()

    class OversizedResponse:
        def __enter__(self) -> OversizedResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            assert size == live_poc._MAX_RESPONSE_BYTES + 1
            return b"x" * size

    class Opener:
        def open(self, request: Request, *, timeout: float) -> OversizedResponse:
            assert request.full_url == "https://example.invalid/read"
            assert timeout == 3
            return OversizedResponse()

    def fake_build_opener(*received: object) -> Opener:
        nonlocal handlers
        handlers = received
        return Opener()

    monkeypatch.setattr(live_poc, "build_opener", fake_build_opener)

    with pytest.raises(live_poc._TransportError, match="^response_too_large$"):
        live_poc._read_https_response(
            Request("https://example.invalid/read"),
            ssl.create_default_context(),
            3,
        )

    assert len(handlers) == 3
    assert isinstance(handlers[0], ProxyHandler)
    assert handlers[0].proxies == {}
    assert isinstance(handlers[1], HTTPSHandler)
    assert isinstance(handlers[2], live_poc._RejectRedirects)


@pytest.mark.parametrize(
    ("certificate_name", "ca_name"),
    [
        ("gwm_general.cer", "gwm_root.pem"),
        ("gwm_general_rus.cer", "gwm_root_rus.pem"),
    ],
)
def test_client_chain_contains_only_leaf_and_direct_issuer(
    certificate_name: str,
    ca_name: str,
) -> None:
    certificate = load_certificate((RESOURCE_DIR / certificate_name).read_bytes())

    chain = live_poc._client_certificate_chain(
        certificate,
        (RESOURCE_DIR / ca_name).read_bytes(),
    )

    assert chain.count(b"-----BEGIN CERTIFICATE-----") == 2
    assert chain.startswith(certificate.public_bytes(serialization.Encoding.PEM))


def test_unknown_client_issuer_is_rejected() -> None:
    state = _issued_eu_state(issuer_common_name="Unexpected Issuer")
    certificate = load_certificate(base64.b64decode(state.client_certificate or ""))

    with pytest.raises(live_poc.LivePocError, match="^tls_material_invalid$"):
        live_poc._client_certificate_chain(
            certificate,
            (RESOURCE_DIR / "gwm_root.pem").read_bytes(),
        )


def test_eu_temporary_identity_files_are_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temp_root = tmp_path / "temporary-identities"
    temp_root.mkdir()
    monkeypatch.setattr(live_poc.tempfile, "tempdir", str(temp_root))

    context = live_poc._build_app_context(
        live_poc._settings_for_region("eu"),
        _issued_eu_state(),
        RESOURCE_DIR,
    )

    assert context.security_level == 0
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert list(temp_root.iterdir()) == []


def test_main_requires_explicit_live_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in (
        "GWM_POC_LIVE_READ_APPROVED",
        "GWM_POC_STATE_PATH",
        "GWM_POC_REGION",
        "GWM_POC_COUNTRY",
    ):
        monkeypatch.delenv(name, raising=False)

    assert live_poc.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "category": "live_read_not_acknowledged",
        "status": "failed",
    }


def test_main_redacts_unexpected_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "SENSITIVE INTERNAL EXCEPTION"
    monkeypatch.setenv("GWM_POC_LIVE_READ_APPROVED", "yes")
    monkeypatch.setenv("GWM_POC_STATE_PATH", "external-state.json")
    monkeypatch.setenv("GWM_POC_REGION", "aus")
    monkeypatch.setenv("GWM_POC_COUNTRY", "AU")

    def fail_load(*args: object, **kwargs: object) -> live_poc.ReusedPocState:
        raise RuntimeError(secret)

    monkeypatch.setattr(live_poc, "load_reused_poc_state", fail_load)

    assert live_poc.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "category": "unexpected_error",
        "status": "failed",
    }
    assert secret not in captured.err
