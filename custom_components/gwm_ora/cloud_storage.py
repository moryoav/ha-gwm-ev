"""Private, account-bound GWM cloud state and command journal storage."""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from gwm_client import (
    AnzAuthState,
    ChinaAuthState,
    EuAuthState,
    EuIssuedIdentity,
    RussiaAuthState,
)

from .cloud_auth import (
    CloudAuthState,
    GwmCloudCredentials,
    cloud_unique_id,
)
from .const import (
    ANZ_AUTHENTICATION_METHOD_LEGACY,
    CONF_ACCOUNT,
    CONF_AUTHENTICATION_METHOD,
    CONF_COUNTRY,
    CONF_PASSWORD,
    CONF_REGION,
    DOMAIN,
    REGION_ANZ,
    REGION_CHINA,
    REGION_EU,
    REGION_RUSSIA,
)

_STORAGE_VERSION = 1
_STORAGE_CACHE_KEY = f"{DOMAIN}_direct_cloud_stores"
_STORAGE_KEY_PREFIX = f"{DOMAIN}.direct_cloud"
_PLACEHOLDER_DEVICE_ID = "0" * 32
_HASH = re.compile(r"[0-9a-f]{64}")
_JOURNAL_ID = re.compile(r"[0-9a-f]{32}")
_COMMAND_STATES = frozenset({"accepted", "polling", "completed", "failed"})
_COMMAND_TRANSITIONS = {
    "accepted": frozenset({"accepted", "polling", "completed", "failed"}),
    "polling": frozenset({"polling", "completed", "failed"}),
    "completed": frozenset({"completed"}),
    "failed": frozenset({"failed"}),
}
_MAX_COMMANDS = 100
_MAX_CHARGING_PLANS = 100
_MAX_COMMAND_IDENTIFIER_LENGTH = 512
_MAX_COMMAND_NAME_LENGTH = 80
# This persisted hash-domain value is a compatibility contract, not a vehicle-scope name.
_LEGACY_DIRECT_CONTEXT_DOMAIN = b"gwm-ora-direct-auth-context-v1\0"


@dataclass(frozen=True, slots=True, repr=False)
class GwmCommandJournalEntry:
    """One accepted cloud command retained for restart reconciliation."""

    journal_id: str
    vehicle_id: str = field(repr=False)
    command_name: str
    cloud_command_id: str = field(repr=False)
    state: str
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if (
            not isinstance(self.journal_id, str)
            or _JOURNAL_ID.fullmatch(self.journal_id) is None
            or not _bounded_command_text(
                self.vehicle_id,
                _MAX_COMMAND_IDENTIFIER_LENGTH,
            )
            or not _bounded_command_name(self.command_name, _MAX_COMMAND_NAME_LENGTH)
            or not _bounded_command_text(
                self.cloud_command_id,
                _MAX_COMMAND_IDENTIFIER_LENGTH,
            )
            or self.state not in _COMMAND_STATES
        ):
            raise ValueError("command_journal_invalid")
        created_at = _normalized_datetime(self.created_at)
        updated_at = _normalized_datetime(self.updated_at)
        if updated_at < created_at:
            raise ValueError("command_journal_invalid")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "updated_at", updated_at)


@dataclass(frozen=True, slots=True, repr=False)
class GwmOwnedChargingPlan:
    """The exact charging plan written by this integration for one vehicle."""

    vehicle_id: str = field(repr=False)
    plan_id: int | None
    plan_type: int
    start_time_ms: int
    end_time_ms: int
    weeks: str = ""

    def __post_init__(self) -> None:
        if (
            not _bounded_command_text(self.vehicle_id, _MAX_COMMAND_IDENTIFIER_LENGTH)
            or self.plan_id is not None
            and not _int64(self.plan_id)
            or not _int32(self.plan_type)
            or not _int64(self.start_time_ms)
            or not _int64(self.end_time_ms)
            or self.end_time_ms - self.start_time_ms < 5 * 60 * 1000
            or not isinstance(self.weeks, str)
            or len(self.weeks) > 64
            or any(ord(character) < 0x20 for character in self.weeks)
        ):
            raise ValueError("owned_charging_plan_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class _GwmCloudRecord:
    region: str
    account_binding: str = field(repr=False)
    context_binding: str = field(repr=False)
    auth_state: CloudAuthState | None = field(default=None, repr=False)
    commands: tuple[GwmCommandJournalEntry, ...] = field(
        default=(),
        repr=False,
    )
    charging_plans: tuple[GwmOwnedChargingPlan, ...] = field(
        default=(),
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            self.region not in {REGION_EU, REGION_ANZ, REGION_RUSSIA, REGION_CHINA}
            or not isinstance(self.account_binding, str)
            or _HASH.fullmatch(self.account_binding) is None
            or not isinstance(self.context_binding, str)
            or _HASH.fullmatch(self.context_binding) is None
            or not isinstance(self.commands, tuple)
            or len(self.commands) > _MAX_COMMANDS
            or any(type(command) is not GwmCommandJournalEntry for command in self.commands)
            or len({command.journal_id for command in self.commands}) != len(self.commands)
            or not isinstance(self.charging_plans, tuple)
            or len(self.charging_plans) > _MAX_CHARGING_PLANS
            or any(type(plan) is not GwmOwnedChargingPlan for plan in self.charging_plans)
            or len({plan.vehicle_id.casefold() for plan in self.charging_plans}) != len(self.charging_plans)
        ):
            raise ValueError("direct_cloud_state_invalid")
        if self.auth_state is not None:
            _validate_regional_state(self.region, self.account_binding, self.auth_state)


class GwmCloudStateStore:
    """Serialize one direct account's auth state and future command journal."""

    def __init__(self, hass: HomeAssistant, unique_id: str) -> None:
        if not isinstance(unique_id, str) or not unique_id.startswith("cloud:"):
            raise ValueError("direct_cloud_store_invalid")
        digest = hashlib.sha256(unique_id.encode("utf-8")).hexdigest()
        self.unique_id = unique_id
        self._store = Store[dict[str, Any]](
            hass,
            _STORAGE_VERSION,
            f"{_STORAGE_KEY_PREFIX}.{digest}",
            private=True,
            atomic_writes=True,
            serialize_in_event_loop=False,
        )
        self._lock = asyncio.Lock()
        self._loaded = False
        self._invalid_loaded_data = False
        self._record: _GwmCloudRecord | None = None

    def __repr__(self) -> str:
        return "GwmCloudStateStore()"

    async def async_load_auth_state(
        self,
        entry_data: dict[str, object],
    ) -> CloudAuthState | None:
        """Load auth state only when every account-context field still matches."""

        credentials = _credentials_from_entry(entry_data)
        async with self._lock:
            await self._async_ensure_loaded()
            if not self._record_matches(credentials):
                if self._record is not None or self._invalid_loaded_data:
                    await self._async_replace_for_context(credentials, auth_state=None)
                return None
            return self._record.auth_state if self._record is not None else None

    async def async_save_auth_state(
        self,
        credentials: GwmCloudCredentials,
        auth_state: CloudAuthState,
    ) -> None:
        """Atomically publish a complete or recoverable partial state revision."""

        _validate_credentials_for_store(self.unique_id, credentials)
        _validate_regional_state(
            credentials.region,
            credentials.account_binding,
            auth_state,
            credentials=credentials,
        )
        async with self._lock:
            await self._async_ensure_loaded()
            commands = self._record.commands if self._record_matches(credentials) and self._record is not None else ()
            charging_plans = (
                self._record.charging_plans if self._record_matches(credentials) and self._record is not None else ()
            )
            record = _record_for_credentials(
                credentials,
                auth_state=auth_state,
                commands=commands,
                charging_plans=charging_plans,
            )
            await self._async_save(record)

    async def async_clear_auth_state(
        self,
        entry_data: dict[str, object],
    ) -> None:
        """Retire rejected auth state without discarding same-account commands."""

        credentials = _credentials_from_entry(entry_data)
        async with self._lock:
            await self._async_ensure_loaded()
            commands = self._record.commands if self._record_matches(credentials) and self._record is not None else ()
            charging_plans = (
                self._record.charging_plans if self._record_matches(credentials) and self._record is not None else ()
            )
            await self._async_save(
                _record_for_credentials(
                    credentials,
                    auth_state=None,
                    commands=commands,
                    charging_plans=charging_plans,
                )
            )

    async def async_get_command_journal(
        self,
        entry_data: dict[str, object],
    ) -> tuple[GwmCommandJournalEntry, ...]:
        """Return the bounded same-account journal after restart."""

        credentials = _credentials_from_entry(entry_data)
        async with self._lock:
            await self._async_ensure_loaded()
            if not self._record_matches(credentials):
                if self._record is not None or self._invalid_loaded_data:
                    await self._async_replace_for_context(credentials, auth_state=None)
                return ()
            return self._record.commands if self._record is not None else ()

    async def async_record_accepted_command(
        self,
        credentials: GwmCloudCredentials,
        *,
        vehicle_id: str,
        command_name: str,
        cloud_command_id: str,
        accepted_at: datetime,
    ) -> GwmCommandJournalEntry:
        """Persist an accepted cloud identifier before future result polling."""

        _validate_credentials_for_store(self.unique_id, credentials)
        accepted_at = _normalized_datetime(accepted_at)
        entry = GwmCommandJournalEntry(
            journal_id=secrets.token_hex(16),
            vehicle_id=vehicle_id,
            command_name=command_name,
            cloud_command_id=cloud_command_id,
            state="accepted",
            created_at=accepted_at,
            updated_at=accepted_at,
        )
        async with self._lock:
            await self._async_ensure_loaded()
            if not self._record_matches(credentials) or self._record is None or self._record.auth_state is None:
                raise ValueError("direct_cloud_state_invalid")
            commands = (*self._record.commands, entry)[-_MAX_COMMANDS:]
            await self._async_save(
                _record_for_credentials(
                    credentials,
                    auth_state=self._record.auth_state,
                    commands=commands,
                    charging_plans=self._record.charging_plans,
                )
            )
        return entry

    async def async_update_command(
        self,
        credentials: GwmCloudCredentials,
        journal_id: str,
        *,
        state: str,
        updated_at: datetime,
    ) -> GwmCommandJournalEntry:
        """Persist one future polling transition under the same account lock."""

        _validate_credentials_for_store(self.unique_id, credentials)
        updated_at = _normalized_datetime(updated_at)
        if state not in _COMMAND_STATES:
            raise ValueError("command_journal_invalid")
        async with self._lock:
            await self._async_ensure_loaded()
            if not self._record_matches(credentials) or self._record is None:
                raise ValueError("direct_cloud_state_invalid")
            commands = list(self._record.commands)
            for index, current in enumerate(commands):
                if current.journal_id != journal_id:
                    continue
                if state not in _COMMAND_TRANSITIONS[current.state] or updated_at < current.updated_at:
                    raise ValueError("command_journal_invalid")
                updated = GwmCommandJournalEntry(
                    journal_id=current.journal_id,
                    vehicle_id=current.vehicle_id,
                    command_name=current.command_name,
                    cloud_command_id=current.cloud_command_id,
                    state=state,
                    created_at=current.created_at,
                    updated_at=updated_at,
                )
                commands[index] = updated
                await self._async_save(
                    _record_for_credentials(
                        credentials,
                        auth_state=self._record.auth_state,
                        commands=tuple(commands),
                        charging_plans=self._record.charging_plans,
                    )
                )
                return updated
        raise KeyError("command_not_found")

    async def async_get_owned_charging_plans(
        self,
        entry_data: dict[str, object],
    ) -> tuple[GwmOwnedChargingPlan, ...]:
        """Return exact same-account charging plans owned by the integration."""

        credentials = _credentials_from_entry(entry_data)
        async with self._lock:
            await self._async_ensure_loaded()
            if not self._record_matches(credentials):
                if self._record is not None or self._invalid_loaded_data:
                    await self._async_replace_for_context(credentials, auth_state=None)
                return ()
            return self._record.charging_plans if self._record is not None else ()

    async def async_set_owned_charging_plan(
        self,
        credentials: GwmCloudCredentials,
        plan: GwmOwnedChargingPlan,
    ) -> None:
        """Atomically remember one exact plan after GWM accepts the write."""

        _validate_credentials_for_store(self.unique_id, credentials)
        if type(plan) is not GwmOwnedChargingPlan:
            raise ValueError("owned_charging_plan_invalid")
        async with self._lock:
            await self._async_ensure_loaded()
            if not self._record_matches(credentials) or self._record is None:
                raise ValueError("direct_cloud_state_invalid")
            retained = tuple(
                current
                for current in self._record.charging_plans
                if current.vehicle_id.casefold() != plan.vehicle_id.casefold()
            )
            charging_plans = (*retained, plan)[-_MAX_CHARGING_PLANS:]
            await self._async_save(
                _record_for_credentials(
                    credentials,
                    auth_state=self._record.auth_state,
                    commands=self._record.commands,
                    charging_plans=charging_plans,
                )
            )

    async def async_remove_owned_charging_plan(
        self,
        credentials: GwmCloudCredentials,
        vehicle_id: str,
    ) -> None:
        """Forget one owned plan without touching any vehicle-side schedule."""

        _validate_credentials_for_store(self.unique_id, credentials)
        if not _bounded_command_text(vehicle_id, _MAX_COMMAND_IDENTIFIER_LENGTH):
            raise ValueError("owned_charging_plan_invalid")
        async with self._lock:
            await self._async_ensure_loaded()
            if not self._record_matches(credentials) or self._record is None:
                raise ValueError("direct_cloud_state_invalid")
            charging_plans = tuple(
                plan for plan in self._record.charging_plans if plan.vehicle_id.casefold() != vehicle_id.casefold()
            )
            if charging_plans == self._record.charging_plans:
                return
            await self._async_save(
                _record_for_credentials(
                    credentials,
                    auth_state=self._record.auth_state,
                    commands=self._record.commands,
                    charging_plans=charging_plans,
                )
            )

    async def async_remove(self) -> None:
        """Remove all persisted state for a deleted or replaced config entry."""

        async with self._lock:
            await self._store.async_remove()
            self._record = None
            self._invalid_loaded_data = False
            self._loaded = True

    async def _async_ensure_loaded(self) -> None:
        if self._loaded:
            return
        raw = await self._store.async_load()
        try:
            self._record = None if raw is None else _decode_record(raw)
        except (KeyError, TypeError, ValueError):
            self._record = None
            self._invalid_loaded_data = True
        self._loaded = True

    def _record_matches(self, credentials: GwmCloudCredentials) -> bool:
        record = self._record
        return record is not None and (
            record.region == credentials.region
            and record.account_binding == credentials.account_binding
            and record.context_binding == cloud_authentication_context_binding(credentials)
            and cloud_unique_id(credentials) == self.unique_id
            and (record.auth_state is None or _auth_state_matches_credentials(record.auth_state, credentials))
        )

    async def _async_replace_for_context(
        self,
        credentials: GwmCloudCredentials,
        *,
        auth_state: CloudAuthState | None,
    ) -> None:
        await self._async_save(
            _record_for_credentials(
                credentials,
                auth_state=auth_state,
                commands=(),
                charging_plans=(),
            )
        )

    async def _async_save(self, record: _GwmCloudRecord) -> None:
        await self._store.async_save(_encode_record(record))
        self._record = record
        self._invalid_loaded_data = False


def cloud_state_store(
    hass: HomeAssistant,
    unique_id: str,
) -> GwmCloudStateStore:
    """Return the one serialized state owner for a direct unique ID."""

    stores = hass.data.setdefault(_STORAGE_CACHE_KEY, {})
    if not isinstance(stores, dict):
        raise ValueError("direct_cloud_store_invalid")
    existing = stores.get(unique_id)
    if isinstance(existing, GwmCloudStateStore):
        return existing
    store = GwmCloudStateStore(hass, unique_id)
    stores[unique_id] = store
    return store


async def async_remove_cloud_state(
    hass: HomeAssistant,
    unique_id: str | None,
) -> None:
    """Delete one direct account store and its in-process owner."""

    if not isinstance(unique_id, str):
        return
    stores = hass.data.get(_STORAGE_CACHE_KEY)
    store = stores.get(unique_id) if isinstance(stores, dict) else None
    if not isinstance(store, GwmCloudStateStore):
        store = GwmCloudStateStore(hass, unique_id)
    await store.async_remove()
    if isinstance(stores, dict) and stores.get(unique_id) is store:
        stores.pop(unique_id, None)


def cloud_authentication_context_binding(
    credentials: GwmCloudCredentials,
) -> str:
    """Bind durable state to credentials and the selected ANZ authentication method."""

    if type(credentials) is not GwmCloudCredentials:
        raise ValueError("credentials_invalid")
    digest = hashlib.sha256()
    digest.update(_LEGACY_DIRECT_CONTEXT_DOMAIN)
    values = [
        credentials.region,
        credentials.country,
        credentials.account,
        credentials.password or "",
    ]
    if credentials.region == REGION_ANZ and credentials.authentication_method != ANZ_AUTHENTICATION_METHOD_LEGACY:
        values.append(credentials.authentication_method or "")
    for value in values:
        encoded = value.encode("utf-8", errors="strict")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _credentials_from_entry(entry_data: dict[str, object]) -> GwmCloudCredentials:
    if not isinstance(entry_data, dict):
        raise ValueError("credentials_invalid")
    return GwmCloudCredentials(
        region=str(entry_data.get(CONF_REGION, "")),
        country=str(entry_data.get(CONF_COUNTRY, "")),
        account=str(entry_data.get(CONF_ACCOUNT, "")),
        password=(str(entry_data[CONF_PASSWORD]) if isinstance(entry_data.get(CONF_PASSWORD), str) else None),
        authentication_method=(
            str(entry_data[CONF_AUTHENTICATION_METHOD])
            if isinstance(entry_data.get(CONF_AUTHENTICATION_METHOD), str)
            else None
        ),
        device_id=_PLACEHOLDER_DEVICE_ID,
    )


def credentials_for_auth_state(
    entry_data: dict[str, object],
    auth_state: CloudAuthState,
) -> GwmCloudCredentials:
    """Rebuild normalized credentials with the persisted device identity."""

    if not isinstance(
        auth_state,
        (EuAuthState, AnzAuthState, RussiaAuthState, ChinaAuthState),
    ):
        raise ValueError("auth_state_invalid")
    base = _credentials_from_entry(entry_data)
    return GwmCloudCredentials(
        region=base.region,
        country=base.country,
        account=base.account,
        password=base.password,
        device_id=auth_state.device_id,
        authentication_method=base.authentication_method,
    )


def _record_for_credentials(
    credentials: GwmCloudCredentials,
    *,
    auth_state: CloudAuthState | None,
    commands: tuple[GwmCommandJournalEntry, ...],
    charging_plans: tuple[GwmOwnedChargingPlan, ...],
) -> _GwmCloudRecord:
    return _GwmCloudRecord(
        region=credentials.region,
        account_binding=credentials.account_binding,
        context_binding=cloud_authentication_context_binding(credentials),
        auth_state=auth_state,
        commands=commands,
        charging_plans=charging_plans,
    )


def _validate_credentials_for_store(
    unique_id: str,
    credentials: GwmCloudCredentials,
) -> None:
    if type(credentials) is not GwmCloudCredentials or cloud_unique_id(credentials) != unique_id:
        raise ValueError("credentials_invalid")


def _validate_regional_state(
    region: str,
    account_binding: str,
    state: CloudAuthState,
    *,
    credentials: GwmCloudCredentials | None = None,
) -> None:
    expected_type = {
        REGION_EU: EuAuthState,
        REGION_ANZ: AnzAuthState,
        REGION_RUSSIA: RussiaAuthState,
        REGION_CHINA: ChinaAuthState,
    }.get(region)
    if expected_type is None or type(state) is not expected_type or state.account_binding != account_binding:
        raise ValueError("auth_state_invalid")
    if credentials is not None and not state.matches(credentials.client_credentials()):
        raise ValueError("auth_state_invalid")


def _auth_state_matches_credentials(
    state: CloudAuthState,
    credentials: GwmCloudCredentials,
) -> bool:
    try:
        state_credentials = GwmCloudCredentials(
            region=credentials.region,
            country=credentials.country,
            account=credentials.account,
            password=credentials.password,
            device_id=state.device_id,
            authentication_method=credentials.authentication_method,
        )
        _validate_regional_state(
            credentials.region,
            credentials.account_binding,
            state,
            credentials=state_credentials,
        )
    except (TypeError, ValueError):
        return False
    return True


def _encode_record(record: _GwmCloudRecord) -> dict[str, Any]:
    return {
        "region": record.region,
        "account_binding": record.account_binding,
        "context_binding": record.context_binding,
        "auth_state": (None if record.auth_state is None else _encode_auth_state(record.auth_state)),
        "commands": [_encode_command(command) for command in record.commands],
        "charging_plans": [_encode_owned_charging_plan(plan) for plan in record.charging_plans],
    }


def _decode_record(data: object) -> _GwmCloudRecord:
    if not isinstance(data, dict):
        raise ValueError("direct_cloud_state_invalid")
    old_keys = {"region", "account_binding", "context_binding", "auth_state", "commands"}
    new_keys = {*old_keys, "charging_plans"}
    actual_keys = set(data)
    if actual_keys != old_keys and actual_keys != new_keys:
        raise ValueError("direct_cloud_state_invalid")
    value = data
    commands = value["commands"]
    if not isinstance(commands, list) or len(commands) > _MAX_COMMANDS:
        raise ValueError("direct_cloud_state_invalid")
    charging_plans = value.get("charging_plans", [])
    if not isinstance(charging_plans, list) or len(charging_plans) > _MAX_CHARGING_PLANS:
        raise ValueError("direct_cloud_state_invalid")
    auth_data = value["auth_state"]
    region = _required_text(value["region"], 8)
    return _GwmCloudRecord(
        region=region,
        account_binding=_required_text(value["account_binding"], 64),
        context_binding=_required_text(value["context_binding"], 64),
        auth_state=(None if auth_data is None else _decode_auth_state(region, auth_data)),
        commands=tuple(_decode_command(command) for command in commands),
        charging_plans=tuple(_decode_owned_charging_plan(plan) for plan in charging_plans),
    )


def _encode_auth_state(state: CloudAuthState) -> dict[str, Any]:
    common: dict[str, Any] = {
        "account_binding": state.account_binding,
        "device_id": state.device_id,
        "verification_requested_at": _encode_datetime(state.verification_requested_at),
    }
    if type(state) is EuAuthState:
        return {
            **common,
            "kind": REGION_EU,
            "country": state.country,
            "access_token": state.access_token,
            "refresh_token": state.refresh_token,
            "gw_id": state.gw_id,
            "bean_id": state.bean_id,
            "issued_identity": (
                None
                if state.issued_identity is None
                else {
                    "certificate": state.issued_identity.certificate,
                    "private_key": state.issued_identity.private_key,
                }
            ),
        }
    if type(state) is AnzAuthState:
        return {
            **common,
            "kind": REGION_ANZ,
            "country": state.country,
            "authentication_method": state.authentication_method.value,
            "access_token": state.access_token,
            "refresh_token": state.refresh_token,
            "gw_id": state.gw_id,
            "session_reclaim_required": state.session_reclaim_required,
        }
    if type(state) is RussiaAuthState:
        return {
            **common,
            "kind": REGION_RUSSIA,
            "country": state.country,
            "access_token": state.access_token,
            "refresh_token": state.refresh_token,
            "gw_id": state.gw_id,
            "bean_id": state.bean_id,
        }
    if type(state) is ChinaAuthState:
        return {
            **common,
            "kind": REGION_CHINA,
            "g_token": state.g_token,
            "g_refresh_token": state.g_refresh_token,
            "sso_token": state.sso_token,
            "pt_token": state.pt_token,
            "user_id": state.user_id,
            "bean_id": state.bean_id,
            "bean_tech_access_token": state.bean_tech_access_token,
            "bean_tech_refresh_token": state.bean_tech_refresh_token,
            "bean_tech_sso_token": state.bean_tech_sso_token,
            "bean_tech_bean_id": state.bean_tech_bean_id,
            "auto_ai_token_id": state.auto_ai_token_id,
            "auto_ai_user_id": state.auto_ai_user_id,
            "auto_ai_gw_id": state.auto_ai_gw_id,
        }
    raise ValueError("auth_state_invalid")


def _decode_auth_state(region: str, data: object) -> CloudAuthState:
    if not isinstance(data, dict) or data.get("kind") != region:
        raise ValueError("auth_state_invalid")
    common = {
        "account_binding": _required_text(data.get("account_binding"), 64),
        "device_id": _required_text(data.get("device_id"), 128),
        "verification_requested_at": _decode_datetime(data.get("verification_requested_at")),
    }
    if region == REGION_EU:
        _require_keys(
            data,
            {
                *common,
                "kind",
                "country",
                "access_token",
                "refresh_token",
                "gw_id",
                "bean_id",
                "issued_identity",
            },
        )
        identity_data = data["issued_identity"]
        identity = None
        if identity_data is not None:
            identity_value = _exact_dict(identity_data, {"certificate", "private_key"})
            identity = EuIssuedIdentity(
                certificate=_required_text(identity_value["certificate"], 64 * 1024),
                private_key=_required_text(identity_value["private_key"], 64 * 1024),
            )
        return EuAuthState(
            **common,
            country=_required_text(data["country"], 8),
            access_token=_optional_text(data["access_token"], 16 * 1024),
            refresh_token=_optional_text(data["refresh_token"], 16 * 1024),
            gw_id=_optional_text(data["gw_id"], 4 * 1024),
            bean_id=_optional_text(data["bean_id"], 4 * 1024),
            issued_identity=identity,
        )
    if region == REGION_ANZ:
        legacy_keys = {
            *common,
            "kind",
            "country",
            "access_token",
            "refresh_token",
            "session_reclaim_required",
        }
        current_keys = {*legacy_keys, "authentication_method", "gw_id"}
        if set(data) not in (legacy_keys, current_keys):
            raise ValueError("auth_state_invalid")
        return AnzAuthState(
            **common,
            country=_required_text(data["country"], 8),
            authentication_method=(
                _required_text(data["authentication_method"], 32)
                if "authentication_method" in data
                else ANZ_AUTHENTICATION_METHOD_LEGACY
            ),
            access_token=_optional_text(data["access_token"], 16 * 1024),
            refresh_token=_optional_text(data["refresh_token"], 16 * 1024),
            gw_id=(_optional_text(data["gw_id"], 16 * 1024) if "gw_id" in data else None),
            session_reclaim_required=_required_bool(data["session_reclaim_required"]),
        )
    if region == REGION_RUSSIA:
        _require_keys(
            data,
            {
                *common,
                "kind",
                "country",
                "access_token",
                "refresh_token",
                "gw_id",
                "bean_id",
            },
        )
        return RussiaAuthState(
            **common,
            country=_required_text(data["country"], 8),
            access_token=_optional_text(data["access_token"], 16 * 1024),
            refresh_token=_optional_text(data["refresh_token"], 16 * 1024),
            gw_id=_optional_text(data["gw_id"], 4 * 1024),
            bean_id=_optional_text(data["bean_id"], 4 * 1024),
        )
    if region == REGION_CHINA:
        names = {
            "g_token",
            "g_refresh_token",
            "sso_token",
            "pt_token",
            "user_id",
            "bean_id",
            "bean_tech_access_token",
            "bean_tech_refresh_token",
            "bean_tech_sso_token",
            "bean_tech_bean_id",
            "auto_ai_token_id",
            "auto_ai_user_id",
            "auto_ai_gw_id",
        }
        _require_keys(data, {*common, "kind", *names})
        return ChinaAuthState(
            **common,
            **{name: _optional_text(data[name], 16 * 1024) for name in names},
        )
    raise ValueError("auth_state_invalid")


def _encode_command(command: GwmCommandJournalEntry) -> dict[str, Any]:
    return {
        "journal_id": command.journal_id,
        "vehicle_id": command.vehicle_id,
        "command_name": command.command_name,
        "cloud_command_id": command.cloud_command_id,
        "state": command.state,
        "created_at": _encode_datetime(command.created_at),
        "updated_at": _encode_datetime(command.updated_at),
    }


def _decode_command(data: object) -> GwmCommandJournalEntry:
    value = _exact_dict(
        data,
        {
            "journal_id",
            "vehicle_id",
            "command_name",
            "cloud_command_id",
            "state",
            "created_at",
            "updated_at",
        },
    )
    return GwmCommandJournalEntry(
        journal_id=_required_text(value["journal_id"], 32),
        vehicle_id=_required_text(value["vehicle_id"], _MAX_COMMAND_IDENTIFIER_LENGTH),
        command_name=_required_text(value["command_name"], _MAX_COMMAND_NAME_LENGTH),
        cloud_command_id=_required_text(
            value["cloud_command_id"],
            _MAX_COMMAND_IDENTIFIER_LENGTH,
        ),
        state=_required_text(value["state"], 16),
        created_at=_required_datetime(value["created_at"]),
        updated_at=_required_datetime(value["updated_at"]),
    )


def _encode_owned_charging_plan(plan: GwmOwnedChargingPlan) -> dict[str, Any]:
    return {
        "vehicle_id": plan.vehicle_id,
        "plan_id": plan.plan_id,
        "plan_type": plan.plan_type,
        "start_time": plan.start_time_ms,
        "end_time": plan.end_time_ms,
        "weeks": plan.weeks,
    }


def _decode_owned_charging_plan(data: object) -> GwmOwnedChargingPlan:
    value = _exact_dict(
        data,
        {"vehicle_id", "plan_id", "plan_type", "start_time", "end_time", "weeks"},
    )
    plan_id = value["plan_id"]
    if plan_id is not None and not _int64(plan_id):
        raise ValueError("owned_charging_plan_invalid")
    return GwmOwnedChargingPlan(
        vehicle_id=_required_text(value["vehicle_id"], _MAX_COMMAND_IDENTIFIER_LENGTH),
        plan_id=plan_id,
        plan_type=_required_int32(value["plan_type"]),
        start_time_ms=_required_int64(value["start_time"]),
        end_time_ms=_required_int64(value["end_time"]),
        weeks=_required_bounded_string(value["weeks"], 64),
    )


def _exact_dict(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("direct_cloud_state_invalid")
    return value


def _require_keys(value: dict[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        raise ValueError("auth_state_invalid")


def _required_text(value: object, maximum: int) -> str:
    if not _bounded_text(value, maximum):
        raise ValueError("direct_cloud_state_invalid")
    return value


def _optional_text(value: object, maximum: int) -> str | None:
    if value is None:
        return None
    return _required_text(value, maximum)


def _bounded_text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum


def _bounded_command_text(value: object, maximum: int) -> bool:
    return _bounded_text(value, maximum) and all(0x21 <= ord(character) <= 0x7E for character in value)


def _bounded_command_name(value: object, maximum: int) -> bool:
    return _bounded_text(value, maximum) and all(0x20 <= ord(character) <= 0x7E for character in value)


def _required_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("direct_cloud_state_invalid")
    return value


def _int64(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and -(2**63) <= value < 2**63


def _int32(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and -(2**31) <= value < 2**31


def _required_int64(value: object) -> int:
    if not _int64(value):
        raise ValueError("direct_cloud_state_invalid")
    return cast(int, value)


def _required_int32(value: object) -> int:
    if not _int32(value):
        raise ValueError("direct_cloud_state_invalid")
    return cast(int, value)


def _required_bounded_string(value: object, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or any(ord(character) < 0x20 for character in value):
        raise ValueError("direct_cloud_state_invalid")
    return value


def _encode_datetime(value: datetime | None) -> str | None:
    return None if value is None else _normalized_datetime(value).isoformat()


def _decode_datetime(value: object) -> datetime | None:
    return None if value is None else _required_datetime(value)


def _required_datetime(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("direct_cloud_state_invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("direct_cloud_state_invalid") from None
    return _normalized_datetime(parsed)


def _normalized_datetime(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("direct_cloud_state_invalid")
    return value.astimezone(UTC)


__all__ = [
    "GwmCloudStateStore",
    "GwmCommandJournalEntry",
    "GwmOwnedChargingPlan",
    "async_remove_cloud_state",
    "credentials_for_auth_state",
    "cloud_authentication_context_binding",
    "cloud_state_store",
]
