# Changelog

All notable changes to this project will be documented in this file.

This project follows semantic versioning. HACS uses the latest GitHub release tag as the remote version, so every released version must have both a tag and a GitHub release.

<!-- Use direct release-note language. Do not begin changelog bullets with first-person "I". -->

## [Unreleased]

## [0.16.19] - 2026-09-02

### Added

- Added the captured NavInfo cabin-purge and force-refresh controls for mainland-China vehicles.

### Fixed

- Corrected the NavInfo sunroof positions to use the official app's confirmed tilt, half-open, and fully-open angle values.
- Matched the official NavInfo climate start contract: every start or temperature change now uses the start function, command code `6`, engine control enabled, and the confirmed 17 to 31 C range.
- Added the official app's signed companion climate-configuration request after each accepted NavInfo climate start. If that follow-up request fails, the integration preserves the already accepted provider command ID so Home Assistant can continue tracking the physical command safely.

## [0.16.18] - 2026-09-01

### Fixed

- Corrected the overseas air-circulation request so its confirmed cabin-clean fields are sent directly under command flag `0x11`. This removes the invalid extra wrapper that GWM rejected with API code `550002`.
- Added privacy-safe service-call logging for the client error type, category, operation, API code, HTTP status, and retry delay. Request bodies, credentials, tokens, VINs, and provider descriptions remain excluded.

## [0.16.17] - 2026-09-01

### Added

- Added BeanTech battery-pack current and voltage sensors using the read-only fields researched in the retired repository's PR #27. These values remain unknown when the vehicle does not report them, which is expected while some vehicles are parked and powered off.

### Changed

- Exposed the existing BeanTech power value as an enabled measurement sensor in kilowatts. Battery current, voltage, and power remain isolated to mainland-China BeanTech vehicles.

## [0.16.16] - 2026-08-31

### Added

- Added a capability-gated **Front defroster** switch for overseas vehicles that report front-defroster status. It uses the official app's 15-minute start request, supports an explicit stop request, and follows the existing restart-safe command journal and result polling.
- Added a capability-gated **Start air circulation** button for overseas vehicles that report the matching status. It runs the official app's fixed 60-second external-air cabin-clean action and follows the same command journal and result polling.

## [0.16.15] - 2026-08-31

### Fixed

- Switched to Home Assistant's supported public `TrackerEntity` API, with a compatibility fallback for older supported Home Assistant releases. This shared platform fix applies to every region and removes the warning about the deprecated alias being removed in Home Assistant Core 2027.6.

## [0.16.14] - 2026-08-31

### Fixed

- Added automatic access-token renewal for EU, legacy ANZ, and Russia, and kept the existing current ANZ renewal path. A rejected access token now triggers one serialized refresh, saves both rotated tokens before retrying the interrupted request, and asks for reauthentication only when GWM rejects the refresh.
- Recognized GWM's `550004` expired-session response during startup and normal polling. This fixes EU entries that previously stayed in setup retry after their 24-hour access token expired.
- Restored the stable `deviceId` in the current ANZ refresh request to match the working add-on contract. This addresses the `550002` refresh error reported with the current GWM ANZ authentication method.

## [0.16.13] - 2026-08-31

### Fixed

- Added automatic session renewal for the current GWM ANZ app login method. When GWM reports an expired access token, the integration now uses the official app's native refresh route, atomically rotates and privately persists both returned tokens, and retries the interrupted poll or command once.
- Serialized ANZ renewal so concurrent requests cannot rotate the same refresh token more than once. If the account has no usable refresh token, GWM rejects renewal, or a renewed session is immediately rejected again, Home Assistant now requests reauthentication instead of retrying the expired session indefinitely.

## [0.16.12] - 2026-08-31

### Fixed

- Separated current ANZ authentication signing from native vehicle-read signing. Current-v2 sessions keep their full device ID, access token, `gwId`, and current app headers, while discovery, status, and basics reads now use the official app's native 16-character nonce and regional query canonicalization. This addresses the exact `607099` signature rejection reported at `getLastStatus` after login and vehicle discovery had already succeeded.

## [0.16.11] - 2026-08-31

### Changed

- Added privacy-safe metadata for vehicle refresh failures and displayed GWM's sanitized API result code in Home Assistant's failed-setup message. This lets the ANZ current-app beta distinguish a signing or request-contract mismatch without logging account details, tokens, VINs, headers, signatures, or response text.

## [0.16.10] - 2026-08-31

### Fixed

- Matched the current GWM ANZ app's password input behavior before login. Current-app authentication now removes characters that the official app silently filters out and applies its 40-character limit, while the legacy ANZ method remains unchanged.

## [0.16.9] - 2026-08-31

### Fixed

- Changed current GWM ANZ request signing to use the gateway-accepted URL path. A controlled live probe confirmed that the full URL returns `607099` (`sign is inconformity`), while the same synthetic login signed with the path reaches account validation.
- Classified the exact ANZ authentication response `607099` as a sanitized signature error, making any remaining signing failure clear without logging credentials, request data, signatures, or cloud response text.

## [0.16.8] - 2026-08-31

### Fixed

- Aligned the beta current GWM ANZ password and verification requests with the signed GWM ANZ 1.0.6 app. This includes full absolute-URL signing, its decoded query rules, 32-character nonce, URI encoding, compact JSON, headers, full device ID, content type, account type, nullable push token, and verification result handling.
- Retained the current app's `gwId` with its access token and carried the selected ANZ method through authentication state, Home Assistant restart recovery, polling, commands, and command-result polling.
- Published a successful current-app session directly from the v2 login response, as the signed app does. Current login no longer makes an unevidenced legacy v1 profile request or requires an unevidenced `refreshToken` field.
- Kept the legacy add-on-compatible ANZ authentication request unchanged.

### Changed

- Added the selected region and authentication method to the sanitized setup failure log. Account details, passwords, codes, tokens, device IDs, request data, and response data remain excluded.

## [0.16.7] - 2026-08-31

### Added

- Added a beta authentication method that follows the current signed GWM ANZ app's v2 password and verification flow.

### Changed

- New Australia and New Zealand setups default to the current app method. Existing entries remain on the legacy add-on-compatible method, and the integration never retries a password automatically across both methods.

## [0.16.6] - 2026-08-31

### Changed

- Logged only sanitized authentication failure metadata, including the operation and GWM result code, so setup failures can be investigated without exposing credentials, tokens, request data, or response bodies.

## [0.16.5] - 2026-08-31

### Fixed

- Preserved explicit Australia/New Zealand single-session consent while continuing through e-mail verification, preventing setup from returning to the consent form without submitting the code.

## [0.16.4] - 2026-08-30

### Fixed

- Kept the latest remote-command result visible across normal vehicle refreshes instead of immediately resetting it to "No remote command has run yet".

## [0.16.3] - 2026-08-30

### Changed

- Displayed the stored vehicle security PIN in the options form as a masked, revealable password value.

## [0.16.2] - 2026-08-30

### Fixed

- Kept a newly saved climate run time for the next A/C command while the GWM cloud read model catches up.

## [0.16.1] - 2026-08-30

### Fixed

- Moved overseas and mainland-China system trust loading off the Home Assistant event loop.

## [0.16.0] - 2026-08-30

### Added

- Added the standalone Home Assistant setup flow for Europe, Australia and New Zealand, Russia, and mainland China.
- Added an immutable `gwm-client` source dependency for testing this branch before the client is published separately.
- Added mainland-China SMS setup, restart-safe session handoff, direct polling, no-PIN controls, and platform-specific NavInfo and BeanTech capabilities.

### Changed

- Changed the integration to authenticate, poll, and send enabled commands directly through the GWM cloud client.
- Existing add-on based entries now require removal and a new GWM setup. Credentials, tokens, certificates, and add-on state are not imported.
- Renamed the reusable Python package and surviving internal Python types to brand-neutral GWM names while preserving the public `gwm_ora` Home Assistant domain and action namespace.
- Matched the released add-on capability boundaries for mainland-China NavInfo and BeanTech vehicles in the standalone integration.

### Removed

- Removed the Docker add-on, .NET solution and tests, Supervisor discovery, local proxy API, and add-on build workflows.

## [0.13.0] - 2026-08-28

### Added

- Added live-tested BeanTech vehicle status reading for mainland-China accounts, including the Tank 300 Hi4-T.
- Added BeanTech status values for fuel, charging, doors, windows, tires, lights, battery details, and other model-specific diagnostics.
- Added Simplified Chinese translations for the Home Assistant integration.
- Added initial BeanTech remote-command routing for lock, unlock, close windows, remote start and stop, horn, flashing lights, and closing the sunroof. These commands are disabled by default and still need live verification.

### Fixed

- Kept NavInfo, BeanTech, and unsupported China vehicle platforms on explicit and isolated request paths.
- Kept the existing SOCE meaning for other regions and exposed BeanTech remaining usable charge as a separate value.
- Kept BeanTech-only entities and charging controls from appearing on unsupported vehicle platforms.
- Added offline regression tests for BeanTech status, commands, result polling, invalid values, and platform isolation.

Thanks to @tyj365888 for the research, protocol details, and live status testing.

## [0.12.0] - 2026-08-27

### Added

- Added experimental China-only controls for remote engine start/stop, horn, flashing lights, combined vehicle search, tailgate open/close, and sunroof close/tilt/half/full positions.
- Added experimental heating mode to the China climate entity using the mainland app's separate cooling and heating switches.

### Fixed

- Use the China app's dedicated A/C parameter-update command when changing temperature or mode while climate control is already running, instead of repeating the start command.

## [0.11.6] - 2026-08-27

### Fixed

- Bound stored authentication sessions to the configured region, country, username, and password. Changing accounts now clears the previous account's tokens, identity, certificate, verification throttle, and add-on-owned charging-plan tracking before starting the new login flow.
- Detect a changed mainland-China phone number when upgrading from an earlier version, discard the mismatched China session, and request a fresh SMS code for the newly configured account.

## [0.11.5] - 2026-08-27

### Fixed

- Corrected mainland-China WEY VV6 status mapping against the official app: read battery SoC from `carStatus.soc` when `battSts.battSoc` is absent, treat `remainFuel` as liters, expose the displayed remaining range as fuel range, and recognize its locked-state encoding.

## [0.11.4] - 2026-08-27

### Fixed

- Routed experimental mainland-China vehicle discovery through the live G-App gateway. Controlled read-only testing showed that `gapp-api.gwmapp-h.com` returns the vehicle list while the previously used `car-api.gwmapp-h.com` route returns an empty HTTP 404 for the same authenticated request.

## [0.11.3] - 2026-08-27

### Fixed

- Matched the official mainland-China Android app's request profile more closely by using gzip-only response encoding, the exact JSON content type and length, and app-style header placement for China cloud requests.

### Added

- Added privacy-safe China gateway diagnostics for request header shape, credential lengths and session relationships, response metadata, and DNS candidates. Credential values, phone numbers, VINs, and request bodies remain omitted.

## [0.11.2] - 2026-08-27

### Fixed

- Aligned experimental China cloud requests with the official Android app's `okhttp/4.2.2` user agent and HTTP/2 preference to address the vehicle-list endpoint returning HTTP 404 to the add-on while succeeding in the app.

### Added

- Added privacy-safe diagnostics for unsuccessful China cloud responses, including the service, method, route, status, negotiated HTTP version, content type, header names, and sanitized error fields without logging request bodies, header values, tokens, phone numbers, or VINs.

## [0.11.1] - 2026-08-26

### Fixed

- Fixed experimental China vehicle-service login in the Alpine add-on image by generating mainland-China timestamps with a fixed UTC+08:00 offset instead of depending on operating-system time-zone data.
- Preserved rotated China account tokens when later BeanTech or AutoAI initialization fails, so a recoverable vehicle-service error does not leave an obsolete refresh token on disk.
- Prevented the add-on from submitting the same one-time China SMS verification code again on a later polling cycle after it has already been accepted or rejected.

## [0.11.0] - 2026-08-25

### Added

- Added experimental, untested mainland-China cloud support with `region: cn` and `country: CN`, using the account's registered phone number and SMS login.
- Added isolated China G-App, BeanTech, and AutoAI authentication, signing, token persistence, vehicle discovery, and NavInfo/AutoAI status polling based on the mainland-China GWM Android app.
- Translated China vehicle status into the existing Home Assistant battery, range, odometer, charging, tire, lock, window, door, trunk, A/C, comfort, and location entities where the vehicle supplies those fields.
- Added experimental China A/C, lock, unlock, close-window, command-result, and charging-schedule support behind the existing command opt-ins. The China app protocol does not send the vehicle security PIN.
- Added offline signing vectors and an end-to-end fake-service test covering China login, discovery, status mapping, controls, and charging without contacting a GWM account or vehicle.

China support currently accepts only vehicles reported as using the `navinfo` platform. It must be validated by a mainland-China user before it can be considered supported. Europe, Australia/New Zealand, and the already verified Russia implementation remain unchanged.

## [0.10.0] - 2026-08-22

### Added

- Added optional charging-schedule control behind a separate `enable_charging_control` opt-in that defaults to off and does not require a security PIN. Home Assistant now provides a **Scheduled charging** switch plus `gwm_ora.set_charging_plan` and `gwm_ora.clear_charging_plan` actions for exact charging windows.
- Added per-vehicle ownership tracking and retry-safe cleanup for schedules written by the add-on. A schedule changed in the official GWM app is preserved when charging control is later disabled.

The charging API uses the H5 gateway in every region, with the additional `vin` header required by AU/NZ. The feature was verified end-to-end on an ANZ ORA 5; other regions have not yet been independently tested.

Thanks to [@wilberforce](https://github.com/wilberforce) for researching, implementing, and live-testing charging control.

## [0.9.0] - 2026-08-22

### Changed

- Renamed the user-facing project, add-on, and integration from **GWM ORA** to **GWM** to reflect support for compatible vehicles available through the official GWM app.
- Renamed the GitHub repository from `ha-gwm_ora` to `ha-gwm` and updated installation buttons, documentation, metadata, badges, and community links to the new URL.
- Replaced ORA-specific examples and presentation assets with generic GWM names and official GWM branding.
- Automatically rename existing config entries that still use the old default title while preserving user-customized titles.
- Kept the `gwm_ora` integration domain, add-on slug, folders, discovery identifier, API environment variables, and internal code namespaces unchanged so existing installations continue working without identifier migration or reconfiguration.

## [0.8.0] - 2026-08-21

### Added

- Added Russia cloud support with `region: rus` and `country: RU`, including authentication, verification, vehicle discovery, status polling, and remote A/C, lock, unlock, and close-window commands.
- Added Russia-specific request signing, client certificates, gateway routing, and tolerant string-or-number response decoding.

### Fixed

- Applied the Russia-specific security PIN check, command type, VIN headers, close-window payload, and result polling behavior without changing the existing EU or AU/NZ command paths.
- Kept AU/NZ response parsing isolated from Russia's flexible response format and aligned Russia verification-code logins with the correct agreements.

Thanks to [@AlexandrErohin](https://github.com/AlexandrErohin) for implementing and testing Russia support.

## [0.7.0] - 2026-08-21

### Added

- Added optional fuel level and fuel range sensors, door and trunk binary sensors, rear defroster and GPS authorization states, seat heating and ventilation levels, steering-wheel and windscreen heater states, and disabled diagnostic tire, window-learning, engine, and sunroof state-code sensors.
- Added market-safe driver/passenger door data and aliases for the already released window data so the same entities work on left-hand-drive and right-hand-drive cars.
- Added defensive telemetry and entity-contract tests for missing, malformed, duplicate, non-finite, and unsupported vehicle values.

### Changed

- Keep car-specific fuel, comfort, and raw diagnostic entities disabled by default where appropriate. Missing signals remain unknown and do not interrupt polling or other entities.
- Label engine and sunroof values as raw state codes because those mappings still need live confirmation. Steering-wheel heating and front-seat heating and ventilation mappings include live ANZ ORA 5 validation.

### Fixed

- Prevent malformed or duplicate GWM status items, invalid seat levels, non-finite numbers, and out-of-range timestamps from breaking an entire vehicle refresh or API response.
- Use driver/passenger naming for the contributed door mappings instead of physical left/right labels that invert between LHD and RHD markets.

Thanks to [@AlexandrErohin](https://github.com/AlexandrErohin) for the initial sensor implementation and [@wilberforce](https://github.com/wilberforce) for the decoded mappings, RHD guidance, live testing, and front-seat ventilation contribution.

## [0.6.1] - 2026-08-10

### Fixed

- Show neutral polling progress for GWM result code `2000` instead of the backend's misleading failure and retry message while the add-on automatically waits for the vehicle result.

## [0.6.0] - 2026-08-09

### Fixed

- AU/NZ: send the required `vin` request header when polling remote-command results (`getRemoteCtrlResultT5`). Without it the ANZ gateway rejected the poll with `002 Missing request header 'vin'`, so a command that actually succeeded on the vehicle was reported as failed in Home Assistant. Verified end-to-end on an ANZ ORA 5. EU is unaffected.

## [0.5.1] - 2026-08-09

### Added

- Added a translated **Charging status** sensor with disconnected, connected, charging, waiting, and error states, including evcc setup documentation.

### Fixed

- Keep the **Charging active** binary sensor available and off for known GWM waiting and error states.

## [0.5.0] - 2026-08-09

### Changed

- New v2 Authentication code for EU region.

## [0.4.0] - 2026-08-02

### Added

- Added a Home Assistant **Climate run time** number entity that saves a 5-to-30-minute duration for the next A/C command.

### Fixed

- Correctly convert the saved GWM climate duration between the cloud settings endpoint's seconds and the vehicle command's minutes.

## [0.3.0] - 2026-08-02

### Added

- Australia/New Zealand support for the `aus` region: account login against the `aus-h5-gateway` using GWM's `bt-auth` request signing, new-device e-mail verification, token refresh, vehicle discovery, and status polling. Set `region: aus` and the account's registration country (for example `AU` or `NZ`). The existing `eu` behavior remains unchanged.

### Changed

- Keep lock, climate, and close-window controls available for `aus` accounts when remote commands are explicitly enabled with a security PIN.
- Document the ANZ single-session limitation and recommend a dedicated shared vehicle account.

### Fixed

- Accept numeric fields that the ANZ gateway returns as JSON strings, such as `securityTime`, while retaining strict EU deserialization.
- Canonicalize signed ANZ GET parameters using the GWM app-family ordering, lowercase-key, and concatenation rules, while removing empty query parameters rejected by the gateway.
- Treat only the known ANZ `607099` response from optional `vehicleBasicsInfo` calls as non-fatal, including climate-command preflight; all EU and other GWM API errors still surface.
- Recover from ANZ `607501` ("logged in elsewhere") responses with a full re-login because refreshing a token does not reclaim a session taken by another device.

## [0.2.16] - 2026-08-02

### Changed

- Simplified HACS installation instructions now that GWM ORA is available in the default HACS catalog.
- Aligned the integration manifest and add-on metadata with the `v0.2.16` release.

## [0.2.15] - 2026-08-01

### Changed

- Removed duplicate repository-root integration brand assets while keeping the canonical copies alongside the custom integration.

### Fixed

- Aligned the integration manifest and add-on metadata with the `v0.2.15` release.

## [0.2.14] - 2026-06-24

### Fixed

- Fixed the add-on ingress vehicles table so long VIN values wrap without pushing aside SOC, range, and updated columns.

## [0.2.13] - 2026-06-23

### Changed

- Prepared a fresh release after passing HACS and Hassfest validation for HACS default repository submission.

## [0.2.12] - 2026-06-23

### Changed

- Expanded the README and add-on documentation with detailed GWM verification-code setup instructions and screenshots.
- Added special thanks to `zivillian/ora2mqtt` for the original trailblazing work that inspired this integration.

## [0.2.11] - 2026-06-19

### Fixed

- Added the add-on-local `CHANGELOG.md` expected by the Home Assistant Apps/Add-ons UI.
- Added a quality check to keep the add-on changelog synchronized with the repository changelog.

## [0.2.10] - 2026-06-19

### Added

- Added required HACS validation and Hassfest GitHub Actions for HACS default repository readiness.
- Added repository quality checks that keep the HACS metadata and validation workflows in place.

### Changed

- Simplified `hacs.json` to supported HACS manifest keys only.

## [0.2.9] - 2026-06-19

### Fixed

- Restored live remote command status progress in Home Assistant by tracking add-on command IDs until terminal state.
- Updated `/api/v1/vehicles` to overlay the latest remote command status instead of returning only the status captured during the last vehicle cloud poll.
- Refreshed vehicle data immediately after a completed remote command so A/C, lock, and window state can update without waiting for the normal polling interval.

### Changed

- Enabled the remote command status sensor by default because it is the main progress indicator for long-running GWM commands.
- Rewrote the README for normal Home Assistant users and removed developer/release-oriented sections.
- Replaced the README banner with a higher-resolution ORA/GWM image.

## [0.2.8] - 2026-06-19

### Added

- Added a startup log line with the running add-on version and architecture to make stale Home Assistant Docker builds easy to identify.

## [0.2.7] - 2026-06-19

### Added

- Added Home Assistant Ingress support with a small authenticated add-on status page.
- Added a custom AppArmor profile for the add-on container.

### Changed

- Documented the add-on presentation/security posture in line with the Home Assistant app presentation guide.

## [0.2.6] - 2026-06-19

### Added

- Added optional `verification_code` add-on setup support for GWM SMS/e-mail verification when the add-on device is not trusted yet.

### Fixed

- Declared the `gwm_ora` Supervisor discovery service in add-on metadata so discovery publishing is accepted by Supervisor.
- Switched the add-on ASP.NET binding configuration from `ASPNETCORE_URLS` to `ASPNETCORE_HTTP_PORTS` to avoid the startup port override warning.
- Reduced repeated GWM verification failures to a concise action-required warning instead of repeated stack traces.

## [0.2.5] - 2026-06-19

### Fixed

- Fixed Home Assistant add-on option saving by replacing the `country` schema from `str(2,2)` with a regex validator compatible with Supervisor's current schema validation.
- Made `security_pin` truly optional in the add-on metadata by removing its default option value while keeping it available in the setup form.

## [0.2.4] - 2026-06-19

### Fixed

- Fixed Supervisor local add-on builds by moving the .NET add-on source and OpenSSL configuration into `addons/gwm_ora`, which is the actual Docker build context used by Home Assistant Supervisor.
- Updated the add-on build CI workflow to use the same `addons/gwm_ora` Docker context as Supervisor.

## [0.2.3] - 2026-06-19

### Fixed

- Fixed Supervisor local add-on builds by copying `gwm_root.pem` from the Docker build stage instead of reading it again from the source context in the runtime stage.

### Added

- Added a non-publishing multi-architecture add-on Docker build check in CI.

## [0.2.2] - 2026-06-19

### Fixed

- Corrected the maintainer name to Yoav Mor in repository metadata and license text.
- Removed the stale README image-workflow badge after switching the add-on to local Supervisor builds.

## [0.2.1] - 2026-06-19

### Changed

- Removed GHCR image publishing and the add-on `image` setting so Home Assistant Supervisor builds the standalone add-on locally from the repository Dockerfile.
- Added Home Assistant local-build labels to the add-on Dockerfile.

## [0.2.0] - 2026-06-19

### Added

- Added Home Assistant Integration Quality Scale tracking with `custom_components/gwm_ora/quality_scale.yaml`.
- Added Gold-track documentation for supported devices, data updates, diagnostics, troubleshooting, use cases, examples, known limitations, and removal.
- Added GitHub community health files: Code of Conduct, Contributing, Security, Support, issue forms, and pull request template.
- Added reconfigure and reauthentication flows for manual/development add-on API connection updates.
- Added Home Assistant repair issue creation when the add-on API token is rejected.
- Added dynamic entity creation for vehicles discovered after initial setup.
- Added entity icon translations and disabled-by-default diagnostic timestamp/command-status entities.

### Changed

- Distinguished add-on authentication failures from remote-command permission failures.
- Wrapped remote command entity failures in translated Home Assistant errors.
- Declared platform parallel update behavior for all integration platforms.

## [0.1.0] - 2026-06-19

### Added

- Initial native Home Assistant add-on for GWM ORA cloud polling and remote commands.
- Initial Home Assistant custom integration with Supervisor discovery and manual development setup.
- Native sensor, binary sensor, device tracker, climate, lock, and button entities.
- Token-protected internal add-on API with persistent add-on state under `/data`.
- Multi-architecture add-on image builds for `amd64`, `aarch64`, and `armv7`.
- Brand assets and installation documentation for add-on store and HACS setup.
