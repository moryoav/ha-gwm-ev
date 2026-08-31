"""Golden-vector tests for the regional request signers."""

from __future__ import annotations

import pytest

from gwm_client.signing import (
    ANZ_BT_AUTH,
    EU_BT_AUTH,
    EU_GWM_AUTH,
    RUSSIA_GWM_AUTH,
    SigningProfile,
    sign_request,
)

SYNTHETIC_TIMESTAMP = "1721462400123"
SYNTHETIC_EU_VEHICLE_ID = (
    # Hex-encoded ``SYNTHETIC-OPAQUE-VEHICLE-ID-001``.
    "53594e5448455449432d4f50415155452d56454849434c452d49442d303031"
)


@pytest.mark.parametrize(
    (
        "profile",
        "method",
        "url",
        "body",
        "timestamp",
        "nonce",
        "expected_signature",
        "expected_url",
    ),
    [
        pytest.param(
            EU_GWM_AUTH,
            "GET",
            "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/complaintsComments/appInitConfig",
            None,
            "1786109613161",
            "e9f40a6b66f5f765",
            "0f01647b577c905cd442476d771106ca37baf60db389bc76f7c8994a02f22c36",
            "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/complaintsComments/appInitConfig",
            id="eu-gwm-auth-get",
        ),
        pytest.param(
            EU_GWM_AUTH,
            "POST",
            "https://eu-h5-gateway.gwmcloud.com/app-api/api/v2.0/userAuth/loginWithPassword",
            '{"account":"owner@example.com","password":"secret"}',
            SYNTHETIC_TIMESTAMP,
            "0123456789abcdef",
            "b58c8529abf47969497b2486169d024858c77735074fd3c7ed299226c1b08ab2",
            "https://eu-h5-gateway.gwmcloud.com/app-api/api/v2.0/userAuth/loginWithPassword",
            id="eu-gwm-auth-post",
        ),
        pytest.param(
            EU_BT_AUTH,
            "GET",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
            None,
            "1786119081976",
            "810FF2B7B31516FD",
            "44eb1744ae2a0d162ca84cd9a99b8de6e2664772afbd48662291d45fa9aeb506",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
            id="eu-bt-auth-acquire-vehicles",
        ),
        pytest.param(
            EU_BT_AUTH,
            "GET",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus"
            f"?vin={SYNTHETIC_EU_VEHICLE_ID}"
            "&seqNo=&modelId=",
            None,
            "1786119094170",
            "38AA045BAECB0A9B",
            "72e02850d26c284a0a409e0468c9dc635bd93e549cf440fbe6c945e3811fb82e",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus"
            f"?vin={SYNTHETIC_EU_VEHICLE_ID}"
            "&seqNo=&modelId=",
            id="eu-bt-auth-synthetic-vehicle-keeps-empty-parameters",
        ),
        pytest.param(
            EU_BT_AUTH,
            "GET",
            "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/complaintsComments/findLastVersion"
            "?type=Android&versionNum=1.3.0",
            None,
            "1786109619155",
            "311FD65FFE955342",
            "32eb4ab7b917c478867c128a327dc6d690690307decd1219406fcd9738e2847f",
            "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/complaintsComments/findLastVersion"
            "?type=Android&versionNum=1.3.0",
            id="eu-bt-auth-multiple-parameters",
        ),
        pytest.param(
            EU_BT_AUTH,
            "GET",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/test?z=hello%20world&empty=&A=One%2FTwo",
            None,
            SYNTHETIC_TIMESTAMP,
            "0123456789ABCDEF",
            "d43ac09bf68b7ad87be78a756c43b96616b0aa4cb0d7a1fffd65c768d8834f76",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/test?z=hello%20world&empty=&A=One%2FTwo",
            id="eu-bt-auth-decodes-for-signing-only",
        ),
        pytest.param(
            EU_BT_AUTH,
            "POST",
            "https://eu-app-gateway-common.gwmcloud.com/app-api/api/v1.0/appAuth/applyCertificate",
            '{"csr":"ABC","phone":"123"}',
            SYNTHETIC_TIMESTAMP,
            "0123456789ABCDEF",
            "67ce44d071cac2ee24d3e3a3b9eeb3ebd24149e461078fa420412b4d83db4971",
            "https://eu-app-gateway-common.gwmcloud.com/app-api/api/v1.0/appAuth/applyCertificate",
            id="eu-bt-auth-post",
        ),
        pytest.param(
            ANZ_BT_AUTH,
            "GET",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin=ABC&seqNo=",
            None,
            SYNTHETIC_TIMESTAMP,
            "0123456789abcdef",
            "5b2e9804a106e7d9dd7bacaee1a99c3a9bd23b4904840caa96d387cf17f24c05",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin=ABC",
            id="anz-drops-empty-parameters",
        ),
        pytest.param(
            ANZ_BT_AUTH,
            "GET",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/vehicleBasicsInfo?vin=ABC&flag=true",
            None,
            SYNTHETIC_TIMESTAMP,
            "0123456789abcdef",
            "79e40a17b69ec1023c30774b7b2ffa583f6e5c0718de8597289f222a73bc3797",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/vehicleBasicsInfo?flag=true&vin=ABC",
            id="anz-sorts-parameters",
        ),
        pytest.param(
            ANZ_BT_AUTH,
            "GET",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5?seqNo=ABC123",
            None,
            SYNTHETIC_TIMESTAMP,
            "0123456789abcdef",
            "42b6afb5a71da918b9cc4863a4b867d1b079c49abee6cb89d389d179486f4a63",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5?seqNo=ABC123",
            id="anz-lowercases-key-for-signing",
        ),
        pytest.param(
            ANZ_BT_AUTH,
            "POST",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/loginAccount",
            '{"account":"owner@example.com","password":"secret"}',
            SYNTHETIC_TIMESTAMP,
            "0123456789abcdef",
            "29245b8fa2a982d774f547775393019b7c351e0a75dd91a2fec0696268fc929b",
            "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/loginAccount",
            id="anz-post",
        ),
        pytest.param(
            RUSSIA_GWM_AUTH,
            "POST",
            "https://rus-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/loginAccount",
            '{"account":"owner@example.com","password":"secret"}',
            SYNTHETIC_TIMESTAMP,
            "0123456789abcdef",
            "b2884756e4e1e7bd4137929a1bdd7243f360ce666822e9ac0d7d13fe67452e2b",
            "https://rus-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/loginAccount",
            id="russia-post",
        ),
        pytest.param(
            RUSSIA_GWM_AUTH,
            "GET",
            "https://rus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin=ABC&seqNo=",
            None,
            SYNTHETIC_TIMESTAMP,
            "0123456789abcdef",
            "20129a1e63495078ff01094752dd2dadcce144778e4fbb1358f25470d8934edd",
            "https://rus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin=ABC",
            id="russia-get",
        ),
    ],
)
def test_current_csharp_golden_vectors(
    profile: SigningProfile,
    method: str,
    url: str,
    body: str | None,
    timestamp: str,
    nonce: str,
    expected_signature: str,
    expected_url: str,
) -> None:
    """The Python signer must remain byte-for-byte compatible with C# vectors."""

    signed = sign_request(
        profile,
        method,
        url,
        body,
        timestamp=timestamp,
        nonce=nonce,
    )

    prefix = profile.prefix
    assert signed.url == expected_url
    assert signed.body == body
    assert signed.headers[f"{prefix}-auth-appkey"] == profile.app_key
    assert signed.headers[f"{prefix}-auth-timestamp"] == timestamp
    assert signed.headers[f"{prefix}-auth-nonce"] == nonce
    assert signed.headers[f"{prefix}-auth-sign"] == expected_signature
    assert set(signed.headers) == {
        f"{prefix}-auth-appkey",
        f"{prefix}-auth-nonce",
        f"{prefix}-auth-timestamp",
        f"{prefix}-auth-sign",
    }


def test_eu_bt_auth_keeps_query_tokens_without_equals() -> None:
    url = "https://example.test/path?flag&&empty=&value=a=b"

    signed = sign_request(
        EU_BT_AUTH,
        "GET",
        url,
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789ABCDEF",
    )

    assert signed.url == url
    assert signed.headers["bt-auth-sign"] == "91f01c24ea20ef87d3dd09905858928d3ae5ed10b6edce5b71467f053bb0857c"


def test_generic_profiles_drop_empty_tokens_and_split_on_first_equals() -> None:
    signed = sign_request(
        ANZ_BT_AUTH,
        "GET",
        "https://example.test/path?empty=&value=a=b&&flag",
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef",
    )

    assert signed.url == "https://example.test/path?value=a=b"
    assert signed.headers["bt-auth-sign"] == "9b0d9d6ad44ffd070bb45994044a6d4acf60ae309037243975a6f9a61231f83e"


def test_generic_profile_reconstructs_empty_path_as_root() -> None:
    signed = sign_request(
        ANZ_BT_AUTH,
        "GET",
        "https://example.test?x=1",
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef",
    )

    assert signed.url == "https://example.test/?x=1"
    assert signed.headers["bt-auth-sign"] == "469b6993cfec72eadd61caef97a40aeca0836e48a680c5f328cc180b960359bc"


def test_current_anz_dart_uri_component_signing_keeps_legacy_punctuation_safe() -> None:
    body = '{"account":"owner@example.com","password":"SYNTHETIC!~*\'()"}'
    signed = sign_request(
        ANZ_BT_AUTH,
        "POST",
        "https://aus-h5-gateway.gwmcloud.com/app-api/api/v2.0/userAuth/loginWithPassword",
        body,
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef0123456789abcdef",
        uri_component_safe="-._~!*'()",
        whitespace_policy="preserve",
        request_target_policy="absolute-url",
        query_policy="dart-current",
    )

    assert signed.headers["bt-auth-sign"] == ("5e291e86fb88f1deaee8aec072edc4f26a154da9e2756dc0c044076971cabe0c")


def test_current_anz_signing_preserves_non_ascii_space_in_json_values() -> None:
    body = '{"account":"owner@example.com","password":"two\u00a0words"}'
    signed = sign_request(
        ANZ_BT_AUTH,
        "POST",
        "https://aus-h5-gateway.gwmcloud.com/app-api/api/v2.0/userAuth/loginWithPassword",
        body,
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef0123456789abcdef",
        uri_component_safe="-._~!*'()",
        whitespace_policy="preserve",
        request_target_policy="absolute-url",
        query_policy="dart-current",
    )

    assert signed.headers["bt-auth-sign"] == ("c8f6a388573e38ad5ac5ffaf68c89b013c387f74445c9ac5445aaf6e9e0d2ece")


def test_current_anz_signing_keeps_empty_query_and_signs_decoded_pairs() -> None:
    url = "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin=SYNTHETIC%2BID&seqNo="
    signed = sign_request(
        ANZ_BT_AUTH,
        "GET",
        url,
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef0123456789abcdef",
        uri_component_safe="-._~!*'()",
        whitespace_policy="preserve",
        request_target_policy="absolute-url",
        query_policy="dart-current",
    )

    assert signed.url == url
    assert signed.headers["bt-auth-sign"] == ("274f1afffc6dea98655a08ede8468fc30072112279dd7766b4d5e99453acfd51")


def test_method_case_is_preserved_for_csharp_parity() -> None:
    lower = sign_request(
        EU_GWM_AUTH,
        "post",
        "https://example.test/path",
        "abc",
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef",
    )
    upper = sign_request(
        EU_GWM_AUTH,
        "POST",
        "https://example.test/path",
        "abc",
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef",
    )

    assert lower.method == "post"
    assert lower.headers["gwm-auth-sign"] == "1e8370aaa6d2b2f7208ae562f79abf7697002c55cc66f8fcba0311cb5b89a166"
    assert upper.headers["gwm-auth-sign"] == "15e0e7f27642496d55833abcf38c2705be525ed1db4eef53561773df9e4950ff"


@pytest.mark.parametrize("method", ["", "GE T", "GET\n"])
def test_signer_rejects_invalid_http_methods(method: str) -> None:
    with pytest.raises(ValueError, match="method"):
        sign_request(
            EU_GWM_AUTH,
            method,
            "https://example.test/path",
            timestamp=SYNTHETIC_TIMESTAMP,
            nonce="0123456789abcdef",
        )


@pytest.mark.parametrize(
    "url",
    [
        "/relative/path",
        "ftp://example.test/path",
        "https://example.test/path#fragment",
        "https://example.test/raw space",
        "https://example.test/unicode/é",
        "https://example.test/bad%escape",
    ],
)
def test_signer_rejects_non_http_request_urls(url: str) -> None:
    with pytest.raises(ValueError):
        sign_request(
            EU_GWM_AUTH,
            "GET",
            url,
            timestamp=SYNTHETIC_TIMESTAMP,
            nonce="0123456789abcdef",
        )


def test_signed_request_repr_redacts_url_headers_and_body() -> None:
    body = '{"password":"do-not-log"}'
    signed = sign_request(
        EU_GWM_AUTH,
        "POST",
        "https://example.test/path?vin=do-not-log",
        body,
        timestamp=SYNTHETIC_TIMESTAMP,
        nonce="0123456789abcdef",
    )

    representation = repr(signed)
    assert "do-not-log" not in representation
    assert "gwm-auth-sign" not in representation
    assert representation == "SignedRequest(method='POST')"
