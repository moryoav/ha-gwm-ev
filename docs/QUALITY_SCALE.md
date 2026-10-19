# Home Assistant Quality Scale

This repository tracks Home Assistant Integration Quality Scale progress in `custom_components/gwm_ora/quality_scale.yaml`.

The goal is Gold-level behavior for users while this remains a custom integration distributed through HACS.

## Current Position

- Bronze: implemented or exempted. I bundle the client source in the integration and HACS ZIP, with no separate GWM client requirement.
- Silver: implemented except measured >95% Python module coverage.
- Gold: implemented or documented, with one safety exemption for automatic stale-device deletion.
- Platinum: partly implemented; strict typing enforcement is still future work.

## Important Notes

This is not an official Home Assistant Core quality-scale rating. Home Assistant Core assigns official ratings after review inside `home-assistant/core`.

The tracker is still useful because it keeps the custom integration aligned with the same rules and makes any future Core submission easier.

## Intentional Exemptions

### Service Actions

The integration does not register custom service actions. Remote commands use native Home Assistant entity actions:

- Climate entity for A/C mode and target temperature.
- Lock entity for lock and unlock.
- Button entity for close windows.

### Entity Events

The integration does not subscribe entity instances to external events. Data is delivered through the shared `DataUpdateCoordinator`.

### Stale Devices

The integration does not immediately delete a vehicle device if the GWM cloud omits it from a response. Temporary GWM outages, account synchronization issues, and backend changes can make a vehicle disappear briefly. Deleting the device would also delete user customizations and history.

Instead:

- Existing entities become unavailable when their VIN is not present.
- Newly discovered vehicles are added dynamically.
- Users can remove the integration if a vehicle is permanently removed from the GWM account.

## Remaining Work

- Add Home Assistant fixture-based tests for config flow, reauth, reconfigure, repairs, diagnostics, and every platform.
- Enforce measured Python coverage above 95%.
- Enable strict Python type checking.
- Consider a safe stale-device cleanup policy if real-world behavior shows vehicle removals are stable and distinguishable from cloud outages.
