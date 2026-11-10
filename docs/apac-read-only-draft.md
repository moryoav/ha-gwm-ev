# Asia-Pacific setup and testing

Asia-Pacific covers Pakistan (`PK`), Thailand (`TH`), Malaysia (`MY`), and Indonesia (`ID`). The setup defaults to read-only access.

In the integration settings, **Vehicle controls** enables supported climate, lock, window, seat, and other vehicle commands. **Charging control** separately enables starting and stopping charging. Both options are off by default and require a vehicle security PIN. A seat-stop command may stop more than one seat because it sends zeroes for both front and rear seats. Authentication and vehicle requests use distinct TLS contexts.

## Installation and sign-in

The integration includes the shared APAC authentication files. Add the GWM integration, choose **Asia-Pacific**, select the account's registration country, and enter the account credentials. Complete a verification code when requested.

The integration stores account-bound session state privately in Home Assistant storage. On restart it restores the issued identity and renews an expired session when possible.

## Development testing

Offline tests cover setup and restart using the bundled files with a simulated GWM service. Synthetic tests also cover setup continuation, account and device binding, private state storage, read-only safeguards, response mapping, token expiry and refresh, and existing regional behavior.

Development builds assembled without the bundle can use `.storage/gwm_apac_material/` inside the Home Assistant configuration directory. Keep those local files outside the source checkout.

The contributor tested a clean install with the bundled files and confirmed fresh sign-in, vehicle discovery, sensor readings, command acceptance, and resumed updates after a Home Assistant restart. The test used a 2026 Haval H6 PHEV. [Test report](https://github.com/moryoav/ha-gwm-ev/issues/44#issuecomment-6762005377)
