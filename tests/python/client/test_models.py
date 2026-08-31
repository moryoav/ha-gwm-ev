"""Typed cloud-model and redaction tests."""

from __future__ import annotations

import ssl
from collections.abc import Mapping

import pytest

from gwm_client.models import (
    CloudVehicle,
    GwmSession,
    VehicleIdentifier,
    parse_cloud_vehicle_basics,
    parse_cloud_vehicle_status,
    parse_cloud_vehicles,
)


def test_vehicle_identifier_is_opaque_canonical_and_repr_hidden() -> None:
    raw = "SYNTHETIC+OPAQUE/ID="
    identifier = VehicleIdentifier(raw)

    assert identifier.value == raw
    assert identifier.encoded == "SYNTHETIC%2BOPAQUE%2FID%3D"
    assert raw not in repr(identifier)
    assert raw not in str(identifier)


@pytest.mark.parametrize("value", ["", "with space", "line\nbreak", "x" * 513])
def test_vehicle_identifier_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(ValueError, match="^vehicle_identifier_invalid$"):
        VehicleIdentifier(value)


def test_session_repr_hides_authentication_and_tls_material() -> None:
    context = ssl.create_default_context()
    session = GwmSession(
        country="IL",
        device_id="SENSITIVE-DEVICE",
        access_token="SENSITIVE-TOKEN",
        app_ssl_context=context,
        gw_id="SENSITIVE-GW-ID",
    )

    rendered = repr(session)
    assert "IL" in rendered
    assert "SENSITIVE-DEVICE" not in rendered
    assert "SENSITIVE-TOKEN" not in rendered
    assert "SENSITIVE-GW-ID" not in rendered
    assert repr(context) not in rendered


def test_vehicle_parser_keeps_only_typed_fields_and_ignores_unknown_pii() -> None:
    vehicles = parse_cloud_vehicles(
        [
            {
                "vin": "SYNTHETIC-OPAQUE-ID",
                "defaultVehicle": True,
                "appShowSeriesName": "Synthetic series",
                "vehicleNick": "Synthetic nickname",
                "modelName": "Synthetic model",
                "brandName": "Synthetic brand",
                "otBrandName": "Synthetic other brand",
                "vtype": "BEV",
                "vTypeName": "Synthetic type",
                "vehicleId": "SYNTHETIC-CLOUD-ID",
                "licenseNumber": "MUST-NOT-BE-RETAINED",
                "engineNo": "MUST-NOT-BE-RETAINED",
                "simIccid": "MUST-NOT-BE-RETAINED",
            }
        ],
        allow_numbers_for_strings=False,
    )

    assert len(vehicles) == 1
    vehicle = vehicles[0]
    assert isinstance(vehicle, CloudVehicle)
    assert vehicle.identifier.value == "SYNTHETIC-OPAQUE-ID"
    assert vehicle.default_vehicle
    serialized = repr(vehicle)
    assert "MUST-NOT-BE-RETAINED" not in serialized
    assert "SYNTHETIC-OPAQUE-ID" not in serialized
    assert not hasattr(vehicle, "license_number")
    assert not hasattr(vehicle, "engine_number")


def test_russia_vehicle_parser_preserves_large_numeric_identifier_exactly() -> None:
    vehicle = parse_cloud_vehicles(
        [{"vin": "SYNTHETIC-VIN", "vehicleId": 9_007_199_254_740_993}],
        allow_numbers_for_strings=True,
    )[0]

    assert vehicle.vehicle_id == "9007199254740993"


def test_strict_vehicle_parser_rejects_numeric_string_properties() -> None:
    with pytest.raises(ValueError, match="^payload_schema_invalid$"):
        parse_cloud_vehicles(
            [{"vin": "SYNTHETIC-VIN", "vehicleId": 9_007_199_254_740_993}],
            allow_numbers_for_strings=False,
        )


def test_vehicle_parser_rejects_duplicate_or_invalid_identifiers() -> None:
    with pytest.raises(ValueError, match="^vehicle_schema_invalid$"):
        parse_cloud_vehicles(
            [{"vin": "DUPLICATE"}, {"vin": "DUPLICATE"}],
            allow_numbers_for_strings=False,
        )
    with pytest.raises(ValueError, match="^vehicle_identifier_invalid$"):
        parse_cloud_vehicles(
            [{"vin": "delete\x7f"}],
            allow_numbers_for_strings=False,
        )


def test_status_parser_freezes_every_supported_json_value() -> None:
    status = parse_cloud_vehicle_status(
        {
            "deviceId": "SENSITIVE-DEVICE",
            "acquisitionTime": 1_721_462_400_123,
            "updateTime": 1_721_462_401_234,
            "latitude": 12.5,
            "longitude": -45.25,
            "items": [
                {
                    "code": "SYNTHETIC-CODE",
                    "unit": "synthetic-unit",
                    "value": {
                        "none": None,
                        "boolean": True,
                        "integer": 1,
                        "float": 2.5,
                        "string": "synthetic",
                        "array": [1, "two"],
                    },
                }
            ],
        },
        allow_stringified_numbers=False,
        allow_numbers_for_strings=False,
    )

    assert status.acquisition_time_ms == 1_721_462_400_123
    assert status.latitude == 12.5
    assert len(status.items) == 1
    value = status.items[0].value
    assert isinstance(value, Mapping)
    assert value["array"] == (1, "two")
    with pytest.raises(TypeError):
        value["new"] = "blocked"  # type: ignore[index]
    rendered = repr(status)
    assert "SENSITIVE-DEVICE" not in rendered
    assert "12.5" not in rendered
    assert "synthetic-unit" not in rendered
    assert "SYNTHETIC-CODE" not in rendered
    assert "SYNTHETIC-CODE" not in repr(status.items[0])


def test_regional_numeric_tolerance_is_explicit() -> None:
    payload = {
        "acquisitionTime": "1721462400123",
        "updateTime": "1721462401234",
        "latitude": "12.5",
        "longitude": "-45.25",
        "items": [{"code": "2013021", "value": "50"}],
    }

    anz = parse_cloud_vehicle_status(
        payload,
        allow_stringified_numbers=True,
        allow_numbers_for_strings=False,
    )
    assert anz.acquisition_time_ms == 1_721_462_400_123
    assert anz.items[0].code == "2013021"

    numeric_code = {**payload, "items": [{"code": 2013021, "value": "50"}]}
    with pytest.raises(ValueError, match="^payload_schema_invalid$"):
        parse_cloud_vehicle_status(
            numeric_code,
            allow_stringified_numbers=True,
            allow_numbers_for_strings=False,
        )
    russia = parse_cloud_vehicle_status(
        numeric_code,
        allow_stringified_numbers=True,
        allow_numbers_for_strings=True,
    )
    assert russia.items[0].code == "2013021"

    with pytest.raises(ValueError, match="^payload_schema_invalid$"):
        parse_cloud_vehicle_status(
            payload,
            allow_stringified_numbers=False,
            allow_numbers_for_strings=False,
        )


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"items": "not-a-list"},
        {"longitude": float("inf")},
        {"acquisitionTime": 1 << 63},
    ],
)
def test_status_parser_rejects_malformed_shapes(payload: object) -> None:
    with pytest.raises(ValueError):
        parse_cloud_vehicle_status(
            payload,
            allow_stringified_numbers=False,
            allow_numbers_for_strings=False,
        )


def test_status_parser_preserves_raw_values_for_later_snapshot_mapping() -> None:
    status = parse_cloud_vehicle_status(
        {
            "acquisitionTime": -1,
            "updateTime": -(1 << 63),
            "latitude": 91,
            "longitude": -181,
            "items": [
                None,
                {"code": None, "value": "ignored"},
                {"code": "  ", "value": "ignored"},
                {"code": "  RAW-CODE  ", "value": "preserved"},
            ],
        },
        allow_stringified_numbers=False,
        allow_numbers_for_strings=False,
    )

    assert status.acquisition_time_ms == -1
    assert status.update_time_ms == -(1 << 63)
    assert status.latitude == 91.0
    assert status.longitude == -181.0
    assert tuple(item.code for item in status.items) == ("  RAW-CODE  ",)

    null_items = parse_cloud_vehicle_status(
        {"items": None},
        allow_stringified_numbers=False,
        allow_numbers_for_strings=False,
    )
    assert null_items.items == ()


def test_basics_parser_is_typed_and_redacted() -> None:
    basics = parse_cloud_vehicle_basics(
        {
            "config": {
                "airConditionerTemperature": "22.0",
                "airConditionerStatusTime": "15",
                "engineStatusTime": "10",
                "userId": "MUST-NOT-BE-RETAINED",
                "vin": "MUST-NOT-BE-RETAINED",
            }
        },
        allow_numbers_for_strings=False,
    )

    assert basics.climate is not None
    assert basics.climate.temperature == "22.0"
    assert "22.0" not in repr(basics)
    assert "MUST-NOT-BE-RETAINED" not in repr(basics)


def test_basics_parser_accepts_absent_config_but_rejects_wrong_shape() -> None:
    assert parse_cloud_vehicle_basics({}, allow_numbers_for_strings=False).climate is None
    with pytest.raises(ValueError, match="^basics_schema_invalid$"):
        parse_cloud_vehicle_basics({"config": []}, allow_numbers_for_strings=False)
