# GWM Client

I use this internal alpha package as the Home Assistant independent protocol boundary for the GWM integration. It provides typed async clients for the EU, Australia and New Zealand, Russia, and isolated mainland China cloud strategies.

The package requires Python 3.13 or newer plus `aiohttp`, `cryptography`, and `yarl`. It does not import Home Assistant. Home Assistant owns the client session and lifecycle when the integration uses it.

The Australia and New Zealand strategy keeps the legacy v1 login contract and the current GWM ANZ app v2 password-login contract separate. Callers must choose one method explicitly. The client never sends an automatic password fallback request. The current method applies the same password input filtering and 40-character limit as the signed GWM ANZ 1.0.6 app before it creates a login request. Current-app sessions can be rotated through the app's native v1 refresh route without resubmitting the account password.

Version `0.1.0` is installed by the custom integration from the same immutable repository release tag. I have not published this package through a public package index.

The overseas command boundary includes typed climate, door-lock, close-window, front-defroster, and fixed-duration cabin-clean requests. I keep mainland China commands in their separate regional client.
The climate command contract exposes only `auto` and `off`; each regional client translates `auto` to its existing A/C-on request with the selected target temperature.

For BeanTech horn/light and comfort actions, I use the PIN-exempt v3 timely endpoint. When polling these commands with `ChinaClient.get_remote_command_results`, pass the original action as `control_action` to select its v3 result stream. Use `control_action="climate"` for A/C and `control_action="comfort_mode"` for the dynamic one-touch modes. Omit this argument for existing legacy commands. Home Assistant retains the action through its command journal so polling continues after a restart. Command submission does not automatically retry or fall back to another endpoint.

BeanTech A/C uses the tested `AIR_CONDITIONER_START` body with `allowStartEng=1`, a 17–31 °C temperature, and a duration in seconds. A companion configuration save follows an accepted start; a failed save preserves the accepted command ID. Comfort-mode IDs come from the vehicle's one-touch configuration. Cabin-clean appointments use integer epoch milliseconds and a synchronous acknowledgement; they do not enter the immediate-command result journal.

BeanTech charging mode and window writes read the current `charge/setting` response under the client operation lock. I preserve `chargeStrategy`, all `chargeSetParam` fields, and the unedited window boundary. `chargingMode=0` selects scheduled charging and `1` selects plug-and-charge. Window bounds are `HH:MM` strings in the vehicle app's clock, and an omitted bound must exist in the read response. Missing or malformed settings abort the write. The charge-limit command accepts integers from 50 to 100 in steps of 10.

For result polling, use `control_action="charging_mode"` or `"charge_window"` for the `msgType=charge` stream. Use `"charge_soc"`, `"battery_appointment"`, or the original battery-heating action for the timely `msgType=remote` stream. These operations require an explicitly discovered BeanTech vehicle and do not accept a security token or retry an ambiguous submission. Pending result codes `2` and `3` remain pending.

Battery-heating appointment writes use epoch milliseconds in `useCarTime`. Their configuration read reports only whether the appointment is armed: `switchType=0` means enabled and `1` means disabled. An absent appointment or heating-switch field remains unknown. The available endpoints do not read back a charge limit or the battery departure time; Home Assistant keeps only values confirmed during its current session.

Some protocol values were obtained through interoperability research on official GWM apps. The repository records their provenance and unresolved distribution conditions in [Third-Party and Protocol Material Notice](https://github.com/moryoav/ha-gwm-ev/blob/main/THIRD_PARTY_NOTICES.md). I do not claim that the project MIT license grants rights in those materials.
