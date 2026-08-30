# GWM for Home Assistant

[![GitHub Release][release-badge]][release-url]
[![HACS][hacs-badge]][hacs-url]
[![License][license-badge]][license-url]
[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/moryoav)

This custom integration connects Home Assistant directly to supported regional GWM cloud services. It discovers vehicles on the account, creates native Home Assistant entities, polls vehicle status, and provides explicitly enabled remote controls.

This repository is the integration-only successor to `ha-gwm`. The previous Docker add-on is not required. Europe, Australia and New Zealand, Russia, and mainland China are available in the setup flow.

## Important Upgrade Note

This integration does not import credentials, tokens, or state from the retired add-on.

If you are updating an existing installation, you must:

1. Remove the existing **GWM** integration entry from **Settings** > **Devices & services**.
2. Stop the old GWM add-on.
3. Install this integration from the `ha-gwm-ev` custom HACS repository.
4. Restart Home Assistant.
5. Add **GWM** again and complete a fresh sign-in.
6. Confirm that polling and entities work before enabling remote commands.
7. Uninstall the old add-on after you no longer need it as a rollback reference.

I chose a fresh sign-in because it is simpler, easier to audit, and avoids transferring passwords, tokens, certificates, device identities, and command state between two different storage designs.

## Supported Accounts

The setup flow currently offers:

- Europe, including EU countries, the United Kingdom, and Israel.
- Australia and New Zealand.
- Russia.
- Mainland China, using the phone number registered in the official GWM app.

The account region must match the region used by the official GWM app. It is not based on the vehicle's current location.

The project has been tested with these vehicles:

- GWM ORA 03, model year 2023.
- GWM ORA 05, model year 2023.
- GWM ORA 5, Australia and New Zealand model.
- GWM ORA 1, Russia model.
- WEY VV6, mainland-China NavInfo platform.
- Tank 300 Hi4-T, mainland-China BeanTech platform.

Other compatible GWM vehicles may also work. If you test another model, please [open an issue](https://github.com/moryoav/ha-gwm-ev/issues/new/choose) with the model, account region, and features you verified. Never include credentials, tokens, verification codes, VINs, or exact locations.

## Installation

This is currently installed as a custom HACS repository. Back up Home Assistant before replacing the previous add-on based installation.

1. Open HACS.
2. Open **Custom repositories**.
3. Add `https://github.com/moryoav/ha-gwm-ev` as an **Integration** repository.
4. Find **GWM** in HACS and install the latest release.
5. Restart Home Assistant.
6. Open **Settings** > **Devices & services** > **Add integration**.
7. Search for **GWM**.
8. Select the account region and complete authentication.

Home Assistant installs the bundled `gwm-client` dependency from the same immutable GitHub release tag recorded in the integration manifest. The dependency cannot silently change when `main` advances.

The integration requires Home Assistant 2026.1.0 or newer.

## Authentication

Enter the account details used by the official GWM app. The integration authenticates directly with the selected GWM cloud.

GWM may send a one-time verification code during first setup or reauthentication. Enter the code in the Home Assistant flow. Verification codes are not stored.

For European accounts, the message may come from `noreply@gwm-eu.com` with the subject `GWM Verification Code`.

<img src="https://raw.githubusercontent.com/moryoav/ha-gwm-ev/main/docs/images/gwm-verification-code-email.jpeg" alt="Example GWM verification code email" width="320">

Australia and New Zealand accounts normally permit one active session. The setup flow requires explicit confirmation before it can replace the official app session. I recommend a dedicated account that has been shared access to the vehicle.

Mainland-China accounts use the registered phone number and an SMS verification flow. They do not use an account password or vehicle security PIN in this integration. If GWM requests a risk-control challenge, complete it in the official app before trying again.

The integration privately stores the generated device identity and account-bound authentication state so it can resume after a Home Assistant restart. Passwords and the optional vehicle security PIN are redacted from diagnostics.

## Options

Open the GWM integration entry and select **Configure** to set:

- **Polling interval**: 30 to 3600 seconds. The default is 60 seconds.
- **Enable remote commands**: Off by default.
- **Vehicle security PIN**: Required for remote commands outside mainland China.
- **Enable charging control**: Off by default and independent of remote commands.
- **Log level**: Integration-specific diagnostic verbosity.

Start with both control options disabled. Confirm read-only vehicle data first. Enable one control family at a time only while the vehicle is parked somewhere safe and visible.

## Entities

Depending on the vehicle and region, the integration can create:

- Sensors for battery state of charge, range, odometer, charging state, remaining charging time, tire values, timestamps, fuel values, comfort values, and diagnostic status codes.
- Binary sensors for charging, charge plug, climate, locks, windows, doors, trunk, air circulation, and defrosters.
- A device tracker when the cloud supplies a valid location.
- A climate entity for remote A/C.
- A number entity for the next climate run time.
- A lock entity for door lock and unlock.
- A button for closing all windows.
- A scheduled charging switch.

Missing vehicle signals remain unavailable without interrupting the other entities. Model-specific diagnostic entities are disabled by default where appropriate.

## Remote Commands

Remote commands are slower than ordinary Home Assistant operations because the request travels through the GWM cloud and then waits for the vehicle result. The **Remote command status** sensor shows the current progress.

Set **Climate run time** and the target temperature before starting A/C. Changing either setting only saves it for the next start. It does not start the climate system, and neither setting can be changed after A/C has started.

Remote operations can affect a real vehicle. Test them manually before using them in automations.

## Charging Schedule Control

Charging control has its own opt-in. It does not use the vehicle security PIN.

The **Scheduled charging** switch is a convenience control:

- Turning it on creates an eight-hour charging window starting now.
- Turning it off clears the schedule. This is not a hard stop command, so a connected vehicle may begin charging after the schedule is cleared.

For an exact window, use `gwm_ora.set_charging_plan`:

```yaml
action: gwm_ora.set_charging_plan
data:
  vin: "LGWTEST00XX000001"
  start_time: "2026-08-30 23:00:00+03:00"
  end_time: "2026-08-31 06:00:00+03:00"
```

To clear it:

```yaml
action: gwm_ora.clear_charging_plan
data:
  vin: "LGWTEST00XX000001"
```

The integration records the exact plan it writes. If charging control is later disabled, it retries cleanup only while that exact plan is still present. It leaves schedules changed by the official app untouched.

Charging control was live-tested on an Australia and New Zealand ORA 5 through the previous implementation. The Python integration path is fixture-tested but still needs direct live confirmation.

## evcc

The **Charging status** sensor reports `disconnected`, `connected`, `charging`, `charging_complete`, `awaiting_charging`, `waiting_for_power`, or `error`.

For evcc, include the two GWM waiting states in status B:

```yaml
vehicles:
  - name: gwm_vehicle
    type: template
    template: homeassistant
    uri: http://homeassistant.local:8123
    soc: sensor.gwm_vehicle_soc
    status: sensor.gwm_vehicle_charging_status
    statusB: awaiting_charging, waiting_for_power
```

Replace the example entity IDs with the IDs from your Home Assistant installation.

## Troubleshooting

### The integration does not appear

- Confirm that `/config/custom_components/gwm_ora/manifest.json` exists.
- Restart Home Assistant after replacing the integration folder.
- Clear the browser cache if the integration list is stale.
- Check the Home Assistant log for dependency installation or import errors.

### An old entry requests reauthentication

The previous add-on entry cannot be converted. Remove that entry and add GWM again. The new flow will ask for the GWM account directly.

### Sign-in fails

- Confirm the same account works in the official GWM app.
- Confirm that the selected cloud region and registration country are correct.
- Enter any requested one-time code before it expires.
- For Australia and New Zealand, confirm the single-session warning if you want the integration to take the active session.
- For mainland China, use the registered phone number and complete the SMS flow. If GWM requests a risk-control challenge, complete it in the official app first.

### Entities are unavailable

- Wait for the first complete account poll.
- Confirm that the official app currently shows the vehicle.
- Check whether the vehicle supplies the related signal.
- Review Home Assistant logs after removing personal or secret values.

### Remote controls are unavailable

- Enable remote commands in the integration options.
- Enter the correct vehicle security PIN outside mainland China.
- Reload the integration after changing options.
- Confirm read-only polling works before testing a command.

## Mainland China

Mainland China is available in the setup flow. The integration uses the registered phone number, SMS authentication, and separate G-App, BeanTech, and AutoAI sessions. Remote commands do not use a vehicle security PIN.

The integration preserves the released add-on capability boundaries:

- NavInfo vehicles provide status polling, climate cooling and heating, climate stop and parameter changes, lock and unlock, close windows, the full China vehicle-control button set, and charging schedules when the matching options are enabled.
- BeanTech vehicles provide status polling, lock and unlock, close windows, remote start and stop, horn, flashing lights, and close sunroof when remote commands are enabled.
- BeanTech does not expose climate control, charging schedules, tailgate actions, other sunroof positions, or combined horn and lights.
- Missing or unknown China platforms fail closed instead of using another platform's route.

Start with remote commands and charging control disabled. Compare read-only values with the official app before enabling any operation that affects the vehicle.

## Removal

1. Remove the **GWM** integration entry from Home Assistant.
2. Remove the integration from HACS, or delete `/config/custom_components/gwm_ora`.
3. Restart Home Assistant.

Removing the entry also removes its private integration-owned authentication and command state.

## Privacy and Safety

The integration handles GWM account credentials, authentication tokens, a generated device identity, an optional vehicle security PIN, vehicle identifiers, and potentially precise location data.

Diagnostics redact known credentials, tokens, identifiers, and locations. Review every diagnostic file before sharing it.

Never publish raw cloud responses, packet captures, account data, verification codes, private keys, VINs, or exact vehicle locations.

## Naming and Compatibility

I use **GWM** for the project and new code because support is not limited to ORA vehicles. The Python distribution is `gwm-client`, and the import package is `gwm_client`.

I retain `gwm_ora` as the Home Assistant domain and action namespace. Changing the domain would break entity and device registry links, automations, dashboards, and existing Home Assistant references. The compatibility identifier does not limit supported vehicle brands or models.

Historical ORA test results and attribution to `ora2mqtt` remain named where they are factually relevant.

## Protocol Materials

Some protocol values and bootstrap materials were obtained through interoperability research on official GWM applications. I record their sources, hashes, certificate renewal deadlines, and unresolved redistribution conditions in [Third-Party and Protocol Material Notice](THIRD_PARTY_NOTICES.md).

This remains an early integration release. Publishing the standalone client through a public package index remains blocked until the recorded permission or authorized-replacement conditions are resolved.

## Disclaimer

This project is unofficial and is not affiliated with or endorsed by Great Wall Motor, GWM, or Home Assistant. Vehicle cloud APIs and remote command behavior may change without notice.

Use it at your own risk. You are responsible for protecting credentials, keeping backups, validating behavior, and deciding whether remote commands are appropriate for your vehicle and environment.

## Special Thanks

Special thanks to [zivillian](https://github.com/zivillian) and [zivillian/ora2mqtt](https://github.com/zivillian/ora2mqtt) for the original interoperability work that helped make this project possible.

Thanks to [AlexandrErohin](https://github.com/AlexandrErohin) for the initial model-specific sensors and Russia support.

Deep thanks to [wilberforce](https://github.com/wilberforce) for the Australia and New Zealand authentication and signing work, vehicle status mappings, and live validation.

[hacs-badge]: https://img.shields.io/badge/HACS-Custom-41BDF5.svg?style=flat-square
[hacs-url]: https://github.com/moryoav/ha-gwm-ev
[release-badge]: https://img.shields.io/github/v/release/moryoav/ha-gwm-ev?style=flat-square
[release-url]: https://github.com/moryoav/ha-gwm-ev/releases
[license-badge]: https://img.shields.io/github/license/moryoav/ha-gwm-ev?style=flat-square
[license-url]: https://github.com/moryoav/ha-gwm-ev/blob/main/LICENSE
