# GWM Client

I use this internal alpha package as the Home Assistant independent protocol boundary for the GWM integration. It provides typed async clients for the EU, Australia and New Zealand, Russia, and isolated mainland China cloud strategies.

The package requires Python 3.13 or newer plus `aiohttp`, `cryptography`, and `yarl`. It does not import Home Assistant. Home Assistant owns the client session and lifecycle when the integration uses it.

The Australia and New Zealand strategy keeps the legacy v1 login contract and the current GWM ANZ app v2 password-login contract separate. Callers must choose one method explicitly. The client never sends an automatic password fallback request. The current method applies the same password input filtering and 40-character limit as the signed GWM ANZ 1.0.6 app before it creates a login request. Current-app sessions can be rotated through the app's native v1 refresh route without resubmitting the account password.

Version `0.1.0` is installed by the custom integration from the same immutable repository release tag. I have not published this package through a public package index.

The overseas command boundary includes typed climate, door-lock, close-window, front-defroster, and fixed-duration cabin-clean requests. I keep mainland China commands in their separate regional client.
The climate command contract exposes only `auto` and `off`; each regional client translates `auto` to its existing A/C-on request with the selected target temperature.

Some protocol values were obtained through interoperability research on official GWM apps. The repository records their provenance and unresolved distribution conditions in [Third-Party and Protocol Material Notice](https://github.com/moryoav/ha-gwm-ev/blob/main/THIRD_PARTY_NOTICES.md). I do not claim that the project MIT license grants rights in those materials.
