# GWM Client

I use this internal alpha package as the Home Assistant independent protocol boundary for the GWM integration. It provides typed async clients for the EU, Australia and New Zealand, Russia, and isolated mainland China cloud strategies.

The package requires Python 3.13 or newer plus `aiohttp`, `cryptography`, and `yarl`. It does not import Home Assistant. Home Assistant owns the client session and lifecycle when the integration uses it.

Version `0.1.0` is installed by the custom integration from the same immutable repository release tag. I have not published this package through a public package index.

Some protocol values were obtained through interoperability research on official GWM apps. The repository records their provenance and unresolved distribution conditions in [Third-Party and Protocol Material Notice](https://github.com/moryoav/ha-gwm-ev/blob/main/THIRD_PARTY_NOTICES.md). I do not claim that the project MIT license grants rights in those materials.
