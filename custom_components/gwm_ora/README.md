# GWM

This custom integration connects Home Assistant directly to supported GWM cloud regions. It does not require the retired Docker add-on.

The setup flow supports Europe, Australia and New Zealand, Russia, and mainland China. Mainland-China accounts use their registered phone number and SMS verification.

## Setup

1. Install the integration files under `/config/custom_components/gwm_ora`.
2. Restart Home Assistant.
3. Open **Settings** > **Devices & services** > **Add integration**.
4. Search for **GWM**.
5. Select the account region and complete the sign-in and verification flow.

For Australia and New Zealand, use **Current GWM ANZ app login** for a new setup. Choose **Legacy add-on-compatible login** only when the same account previously worked with the retired add-on.

Existing add-on entries are not migrated. Remove the previous entry and add GWM again. No password, token, certificate, or add-on state is imported.

See the repository [README](https://github.com/moryoav/ha-gwm-ev/blob/main/README.md) for HACS installation instructions, account-region guidance, safety notes, and troubleshooting.

## Options

The integration options provide:

- Cloud polling interval.
- Explicit remote-command opt-in.
- Write-only vehicle security PIN outside mainland China.
- Independent charging-control opt-in.
- Integration log level.

Keep command options disabled until read-only polling and entity values have been checked against the official GWM app.

## Platforms

- Sensor
- Binary sensor
- Device tracker
- Climate
- Number
- Lock
- Button
- Switch

Vehicle models and regions expose different values. Missing signals remain unavailable without interrupting other entities. Optional model-specific diagnostic entities are disabled by default where appropriate.

The optional **Scheduled charging** switch and `gwm_ora.set_charging_plan` and `gwm_ora.clear_charging_plan` actions require charging control to be enabled in the integration options.

On supported overseas vehicles, I expose a **Front defroster** switch and a **Start air circulation** button when the matching status signals are present. Front defrost runs for 15 minutes unless it is stopped early. Air circulation runs the official app's fixed 60-second external-air cabin-clean cycle and cannot be stopped once started.

## Diagnostics

Diagnostics redact known credentials, tokens, security PINs, vehicle identifiers, and locations. Review every diagnostic file before sharing it.

## Quality Scale

Progress toward Home Assistant Integration Quality Scale rules is tracked in `quality_scale.yaml`.
