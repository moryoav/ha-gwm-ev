# GTSP read-only testing

GTSP support is experimental. It uses the existing mainland-China SMS sign-in
and shared account tokens, then a separate signed status GET to
`https://apgdm.gwmcloudcn.com/mabdm/app-bff-vehicle/app-api/api/v2.0/vehicle/getLastStatus`.
Only vehicles discovered as `gtsp` use this route. GTSP remote commands and
charging controls remain unavailable, even when the corresponding integration
options are enabled.

## First test

1. Install v0.17.7 or newer through HACS and restart Home Assistant. Use the
   published files without local patches. The integration manifest installs the
   matching client version automatically.
2. Keep **Enable remote commands** and charging control disabled. Use the
   dedicated account with the shared vehicle and the normal China SMS sign-in.
3. Check whether the vehicle loads, then compare battery SOC and electric range
   with the official app. Allow at least two normal polling cycles and check
   whether the values update. Do not send vehicle commands for this test.
4. Enable debug logging from the GWM integration menu, reproduce one refresh,
   then disable it to download the log. If setup fails before that menu is
   available, temporarily add this to the existing Home Assistant logger config
   and restart:

   ```yaml
   logger:
     logs:
       gwm_client.china_gtsp: debug
       custom_components.gwm_ora: debug
   ```

5. Send the `GWM GTSP response`, `GWM GTSP fields`, `GWM GTSP transport failure`,
   and relevant `GWM cloud refresh failed` lines, plus whether SOC/range match
   the app. Review the log before sharing. Remove tokens, phone numbers, VINs,
   identifiers, credentials, and locations. Do not send raw captures, request
   headers, certificates, or private keys.

## What this version can establish

- Response diagnostics report HTTP status, a sanitized API code, whether `data`
  exists, and its type. Receiving an HTTP response establishes that TLS completed;
  it does not prove that the request was authorized.
- Field diagnostics list only recognized SOC/range field names and mapping
  outcomes. They never log field values, VINs, or tokens.
- SOC prefers `vehicleStatusInfo.powerBatteryPercent`, then
  `charge.powerBatteryPercent`, then `vehicleStatusInfo.remainElectricPercent`.
  Accepted values are finite numbers from 0 through 100, optionally with `,%`.
- Electric range uses `vehicleStatusInfo.evContnsDistance`, falling back to
  `charge.evContnsDistance`. Plain numbers provisionally mean kilometres;
  explicit `,km` is also accepted. Values outside 0 through 10,000 or with a
  different unit stay unavailable. These limits reject common invalid values,
  but the complete GTSP sentinel set still needs live confirmation.
- `preMileage` is not used as electric range because it may represent combined
  range. Its presence is recorded without its value. If it is the only range
  field, a follow-up sanitized structure will be needed.
- Only a plausible integer millisecond `acquisitionTime` is retained. Missing
  or ambiguous timestamps stay unknown. Location and other status fields are
  not mapped.

The initial client uses verified server TLS and the existing HTTP/1.1 China
transport. No digital-key certificates are installed. Actual status-endpoint
mTLS requirements, HTTP/2 requirements, session acceptance, field meanings,
units, and unavailable values remain subject to live testing. A TLS or HTTP
failure will be reported without switching to another platform or weakening TLS.

## Evidence

The protocol contract comes from issue #34's sanitized static bundle and the
contributor's private follow-up for official package `com.gwm.fusion` 2.1.8
(version code 2180). The production environment getters were reported as
runtime-confirmed on September 19, 2026. Signing was checked privately against
the supplied golden vector using existing repository constants. Public tests
use synthetic constants and synthetic vehicle data; private email contents,
canonical strings, and signing vectors are not included.
