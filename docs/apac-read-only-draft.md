# APAC development setup

This development branch adds a shared APAC Home Assistant setup with read-only access by default for Pakistan (`PK`), Thailand (`TH`), Malaysia (`MY`) and Indonesia (`ID`), the countries listed in My GWM (`com.gwm.tha`). All four countries use the same regional implementation.

In the integration settings, **Vehicle controls** enables supported climate, locks, windows, seats and other vehicle commands. **Charging control** separately enables direct start/stop charging. Both toggles default to off and require a vehicle security PIN. The former climate-only toggle is no longer used; users of that test package must explicitly enable Vehicle controls. These implementations use the earlier prototype's APAC command formats and require validation of each command on the submitted branch. Scheduled charging remains unavailable. The seat-stop request in the earlier implementation contains zeroes for both front and rear seats and may stop more than one seat; test with this behavior in mind. Other regions retain their existing policies. Authentication and vehicle requests use distinct, strictly validated TLS contexts.

## Installation and sign-in

The integration includes the shared APAC authentication files. Add the GWM integration, choose **Asia-Pacific (experimental)**, select the account's registration country, and enter the account credentials. Complete a verification code when requested.

The integration stores account-bound session state privately in Home Assistant storage. On restart it attempts to restore the issued identity and renew an expired session. Packaged sign-in still needs a live test.

## Development testing

Offline tests cover setup and restart using the bundled files with a simulated GWM service. Synthetic tests also cover setup continuation, account and device binding, private state storage, read-only safeguards, response mapping, token expiry and refresh, and existing regional behavior.

Development builds assembled without the bundle can use `.storage/gwm_apac_material/` inside the Home Assistant configuration directory. Keep those local files outside the source checkout.

The contributor's live test with a Pakistan account and a 2026 Haval H6 PHEV covered setup, vehicle discovery, readings, subsequent updates, and reconnection after a Home Assistant restart.

Live testing of token expiry and refresh is still needed before release.

## Remote-control testing limits

Latest contributor-reported testing status on the Pakistan Haval H6 PHEV: **No issues found so far.**

The consolidated settings and review fixes still need live verification on the feature branch.
