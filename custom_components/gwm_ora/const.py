"""Constants for the GWM integration."""

from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "gwm_ora"
DEFAULT_NAME = "GWM"
CONF_CONNECTION_TYPE = "connection_type"
CONNECTION_TYPE_CLOUD = "cloud"
CONF_REGION = "region"
CONF_COUNTRY = "country"
CONF_ACCOUNT = "account"
CONF_PASSWORD = "password"
CONF_AUTHENTICATION_METHOD = "authentication_method"
CONF_VERIFICATION_CODE = "verification_code"
CONF_ALLOW_SESSION_RECLAIM = "allow_session_reclaim"
CONF_ENABLE_REMOTE_COMMANDS = "enable_remote_commands"
CONF_ENABLE_CHARGING_CONTROL = "enable_charging_control"
CONF_SECURITY_PIN = "security_pin"
CONF_BEANTECH_ENCRYPTED_SECURITY_PIN = "beantech_encrypted_security_pin"
CONF_POLL_INTERVAL_SECONDS = "poll_interval_seconds"
CONF_LOG_LEVEL = "log_level"

REGION_EU = "eu"
REGION_ANZ = "aus"
REGION_RUSSIA = "rus"
REGION_CHINA = "cn"
SUPPORTED_CLOUD_REGIONS = (REGION_EU, REGION_ANZ, REGION_RUSSIA, REGION_CHINA)
CONFIGURABLE_CLOUD_REGIONS = SUPPORTED_CLOUD_REGIONS

ANZ_AUTHENTICATION_METHOD_CURRENT = "current_v2"
ANZ_AUTHENTICATION_METHOD_LEGACY = "legacy_v1"

DEFAULT_POLL_INTERVAL_SECONDS = 60
MIN_POLL_INTERVAL_SECONDS = 30
MAX_POLL_INTERVAL_SECONDS = 3600
DEFAULT_LOG_LEVEL = "info"
LOG_LEVELS = ("trace", "debug", "info", "warning", "error")

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.DEVICE_TRACKER,
    Platform.CLIMATE,
    Platform.LOCK,
    Platform.BUTTON,
    Platform.NUMBER,
    Platform.SWITCH,
]

# Charging schedule control (behind the integration option).
SERVICE_SET_CHARGING_PLAN = "set_charging_plan"
SERVICE_CLEAR_CHARGING_PLAN = "clear_charging_plan"
ATTR_VIN = "vin"
ATTR_START_TIME = "start_time"
ATTR_END_TIME = "end_time"
MIN_CHARGE_WINDOW_MINUTES = 5
# Duration of the window the manual switch sets when turned on.
DEFAULT_CHARGE_WINDOW_HOURS = 8
