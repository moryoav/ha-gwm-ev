# GTSP read-only testing

GTSP support is experimental. It uses the existing mainland-China SMS sign-in
and shared account tokens, then a separate signed status GET to
`https://apgdm.gwmcloudcn.com/mabdm/app-bff-vehicle/app-api/api/v2.0/vehicle/getLastStatus`.
Only vehicles discovered as `gtsp` use this route. GTSP remote commands and
charging controls remain unavailable, even when the corresponding integration
options are enabled.

## First test

1. Install v0.17.9 or newer through HACS and restart Home Assistant. Use the
   published files without local patches. The integration manifest installs the
   matching client version automatically.
2. Keep **Enable remote commands** and charging control disabled. Use the
   dedicated account with the shared vehicle and the normal China SMS sign-in.
3. Compare battery SOC, electric range, odometer, and the location tracker with
   the official app. Check whether the map position is correct, without sharing
   coordinates. Allow at least two normal polling cycles. Do not send vehicle
   commands for this test.
4. On the GWM device page, show disabled entities and enable **Acquisition time**
   and any relevant raw diagnostic sensors listed below. Compare acquisition
   time with the app's vehicle update time, including after a normal journey.
   Inspect results after parking; no interaction while driving is needed.
5. Enable debug logging from the GWM integration menu, reproduce one refresh,
   then disable it to download the log. If setup fails before that menu is
   available, temporarily add this to the existing Home Assistant logger config
   and restart:

   ```yaml
   logger:
     logs:
       gwm_client.china_gtsp: debug
       custom_components.gwm_ora: debug
   ```

6. Send the `GWM GTSP response`, `GWM GTSP fields`, `GWM GTSP schema`,
   `GWM GTSP transport failure`,
   and relevant `GWM cloud refresh failed` lines, plus whether the readings match
   the app. Review the log before sharing. Remove tokens, phone numbers, VINs,
   identifiers, credentials, and locations. Do not send raw captures, request
   headers, certificates, or private keys.

## What this version can establish

- Response diagnostics report HTTP status, a sanitized API code, whether `data`
  exists, and its type. Receiving an HTTP response establishes that TLS completed;
  it does not prove that the request was authorized.
- Field diagnostics list mapping outcomes. Schema diagnostics report fixed,
  recognized property paths, their types, and allowlisted unit suffixes. Unknown
  property names are counted, not logged, because names can contain identifiers.
  Neither diagnostic logs field values, coordinates, VINs, or tokens. Candidate
  paths can appear even when no interpreted sensor is supported for them.
- SOC prefers `vehicleStatusInfo.powerBatteryPercent`, then
  `charge.powerBatteryPercent`, then `vehicleStatusInfo.remainElectricPercent`.
  Accepted values are finite numbers from 0 through 100, optionally with `,%`.
- Electric range uses `vehicleStatusInfo.evContnsDistance`, falling back to
  `charge.evContnsDistance`. Plain numbers provisionally mean kilometres;
  explicit `,km` is also accepted. Values outside 0 through 10,000 or with a
  different unit stay unavailable. These limits reject common invalid values,
  but the complete GTSP sentinel set still needs live confirmation.
- Odometer uses `vehicleStatusInfo.mileage`. Plain numbers provisionally mean
  kilometres; explicit `,km` is accepted. Other units, negative values, and
  values above 10,000,000 remain unknown. Compare against the app before relying
  on recorded distance.
- Location uses numeric root-level `latitude` and `longitude`. Both must be
  finite and within geographic bounds; the pair `(0, 0)` is rejected. An explicit
  false or malformed `gpsSwitchOn` suppresses location. Missing coordinates
  clear the location. No coordinate-system conversion or GPS-fix time is
  inferred; report a map offset if present, without sending actual coordinates.
- Only a plausible integer millisecond `acquisitionTime` is retained. Missing
  or ambiguous timestamps stay unknown. The existing update-time sensor mirrors
  acquisition time for GTSP; it is not an independent server timestamp.

## New measurements and provisional states in v0.17.9

The following mappings run only in the GTSP adapter. Availability depends on
the vehicle supplying each field. Missing or invalid values become unknown.

| Reading | GTSP field and accepted interpretation |
| --- | --- |
| Four tire pressures | `tirePress.{lf,rf,lb,rb}TirePressVal`, explicit `kPa`, 0–600 |
| Four tire temperatures | `tireTemp.{lf,rf,lb,rb}TireTempVal`, explicit `℃`, `°C`, or `C`, −40–125 |
| Fuel volume | `remainOil`, explicit `L`, 0–300; never derived from `oilQty` gauge bars |
| Fuel range (provisional) | `preMileage`, explicit `km`, 0–10,000; `charge.preMileage` only when the top field is absent |
| Four doors (provisional) | `door.{mainDrveDoorSts,viceDoorSts,lbDoorSts,rbDoorSts}`: 0 closed, 1 open |
| Lock status (provisional) | `door.mainDrveDoorLockSts`: 0 locked, 1 unlocked |
| Four side windows (provisional) | `windows.{lf,rf,lb,rb}WinPosnSts`: 5 closed, 0–4 open |

All paths above are beneath `vehicleStatusInfo`. The door/window interpretations
are based on the similar BeanTech fields, not confirmed GTSP enums. Other codes
remain unknown. The lock reading appears in the **Lock open** binary sensor;
the lock control remains unavailable. Do not rely on provisional states for
security or automations before comparing both states with the actual vehicle.

Compare all tire readings and fuel volume/range with the app, including units.
While parked, note each door closed/open, lock locked/unlocked, and each window
fully closed/partly open/fully open during normal use. Record the raw code,
Home Assistant reading, actual state, and acquisition time for each observation.
Check physical rear-left/right positions too. Note whether acquisition time
advances; a cached sample cannot establish a state transition. Include the
vehicle model, year, powertrain, and whether this is a shared or owner account.

## Optional raw diagnostics

These 44 GTSP-only entities are disabled by default. Enable them from the device
page as needed. They show bounded numeric values, without assigning another
platform's units, enum labels, or unavailable-value conventions. Missing,
nonnumeric, or malformed fields remain unknown. Values such as `-1` or `65535`
may be sentinels and are retained only as raw diagnostics. These are not confirmed
fuel measurements, charging states, or control entities.

| Entity | Response field |
| --- | --- |
| Fuel quantity (raw) | `oilQty` |
| Secondary fuel quantity (raw) | `secOilQty` |
| T-Box status code | `tboxStatus` |
| Charging status code | `vehicleStatusInfo.charge.chargeStatus` |
| Charging mode code | `vehicleStatusInfo.charge.chargeMode` |
| Charge connected code | `vehicleStatusInfo.charge.chargeConnected` |
| Connection status code | `vehicleStatusInfo.charge.connectSts` |
| DC charge connection code | `vehicleStatusInfo.charge.bmsDcChrgConnect` |
| Charge limit (raw) | `vehicleStatusInfo.charge.bmsBattSocLim` |
| Charging time (raw) | `vehicleStatusInfo.charge.chargingTime` |
| Charge duration (raw) | `vehicleStatusInfo.charge.chargeDurationTime` |
| Reported range (raw) | `vehicleStatusInfo.preMileage`, falling back to `charge.preMileage` when absent |
| Engine / powertrain / gear codes | `vehicleStatusInfo.engineSts`, `powertrainSts`, `hcuGearSts` |
| Cabin temperature (raw) | `vehicleStatusInfo.cbnTemp` |
| Battery voltage / current (raw) | `vehicleStatusInfo.bmsPackVolt`, `bmsPackCurr` |
| Charging power / reported power (raw) | `vehicleStatusInfo.vcuChrgPowerDisp`, `power` |
| A/C status code | `vehicleStatusInfo.airConditionSts` |
| Lock and four door codes | The five `door` fields listed above |
| Back door code | `vehicleStatusInfo.door.backDoorSts` |
| Sunroof code | `vehicleStatusInfo.windows.skyLightSts` |
| Four side-window codes | `vehicleStatusInfo.windows.{lf,rf,lb,rb}WinPosnSts` |
| Four window learning codes | `vehicleStatusInfo.windows.{lf,rf,lb,rb}WinLearnSts` |
| Four tire pressure indicator codes | `vehicleStatusInfo.tirePress.{lf,rf,lb,rb}TirePressIndcrSts` |
| Four tire temperature status codes | `vehicleStatusInfo.tireTemp.{lf,rf,lb,rb}TireTempSts` |

Where convenient during normal use, note the charging codes when unplugged,
plugged in but idle, actively charging, and finished. Compare fuel, charge limit,
time, and reported range with the app, including its displayed units. Only share
the non-sensitive readings you choose to share. These values do not appear in
the schema log. `preMileage` is provisionally used as fuel range, based on the
reported app comparison, and is never used as electric range. Raw sensors have
no unit or statistics class; a recognized
wire unit is retained in the redacted diagnostic download and schema log.

Some new fields are known only from model declarations and may remain unknown
on this vehicle. For cabin temperature, voltage/current, and charging power,
send the schema unit label and the corresponding app value/unit. For current,
compare charging and discharging to establish sign and scaling. For the other
raw codes, pair observations with the app state. Also identify invalid or
unavailable values; do not assume every numeric value is meaningful.

## History and next steps

The normal polling interval is 60 seconds, but `getLastStatus` may return cached
vehicle data. Compare acquisition timestamps across refreshes before using
Home Assistant history or a NAS recorder for trips. A successful poll does not
establish a new GPS fix, speed sample, or ignition transition. SOC and distance
alone do not establish accurate trip energy consumption. This release does not
add a trip recorder or NAS service.

To extend telemetry further, sanitized GTSP model declarations or getter/adapter
code showing exact field paths, types, units, enum meanings, invalid values, and
timestamp/coordinate conventions would help. Speed and ignition/driving state
need this evidence before becoming interpreted entities.

## Information needed for actions

Start with lock/unlock, A/C start/stop and temperature, windows, and charging
start/stop or limits. Include other actions offered by this vehicle's app, such
as lights/horn, defrost, seats, sunroof, or battery heating. An action being
present in another region does not establish GTSP support.

For each supported action, provide sanitized declarations/request-builder code
or synthetic examples showing:

1. App action name, availability on owner versus shared accounts, and any
   required vehicle state or permission. Note actions missing from this model.
2. Exact HTTP method, host/path, command identifier, and request body fields.
   Include start/stop values, allowed ranges, units, duration, optional fields,
   and separate builders for related actions.
3. Authentication and PIN flow, any temporary authorization token, body
   encryption, and how POST bodies enter signing/canonicalization. Use dummy
   values, never real PINs, tokens, keys, VINs, or personal identifiers.
4. Initial acknowledgement format and command ID, followed by result polling
   route/body or push-message models. Include pending, success, failure,
   timeout, permission denied, and vehicle-offline codes. Distinguish accepted
   from executed, and document polling intervals and any retry/idempotency rules.
5. Status fields that confirm completion, including before/after examples
   already available from normal official-app use, with timestamps redacted
   consistently. A successful acknowledgement alone does not confirm an action.

The GTSP Retrofit/service interface, callers/request builders, response models,
and enum/adapter code are more useful than field names alone. Include relevant
helper definitions so parameter construction can be traced. Existing BeanTech
and Navinfo command implementations can guide comparison, but their endpoints,
PIN handling, and result formats must not be assumed for GTSP. Shared signing
keys do not establish command parity.

Static declarations and synthetic examples are enough to begin. Do not issue
commands through this release, send unredacted captures, or share certificates
or private keys. Controls remain disabled until a GTSP-specific contract is
implemented and its acknowledgement/result handling can be tested.

The initial client uses verified server TLS and the existing HTTP/1.1 China
transport. No digital-key certificates are installed. Repeated read-only polling
and SOC/range were reported working on a shared GTSP vehicle with v0.17.7.
New telemetry, field meanings, units, and unavailable values remain subject to
live testing. A TLS or HTTP
failure will be reported without switching to another platform or weakening TLS.

## Evidence

The protocol contract comes from issue #34's sanitized static bundle and the
contributor's private follow-up for official package `com.gwm.fusion` 2.1.8
(version code 2180). The production environment getters were reported as
runtime-confirmed on September 19, 2026. Signing was checked privately against
the supplied golden vector using existing repository constants. Public tests
use synthetic constants and synthetic vehicle data; private email contents,
canonical strings, and signing vectors are not included.
