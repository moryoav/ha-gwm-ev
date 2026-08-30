# Contributing to GWM for Home Assistant

Thanks for your interest in improving GWM for Home Assistant.

This project has two main parts:

- `gwm_client`: the Home Assistant-independent async client for regional GWM cloud protocols.
- `custom_components/gwm_ora`: the Home Assistant integration that owns configuration, private state, polling, entities, and service lifecycle.

Contributions are welcome, including bug reports, documentation improvements, compatibility fixes, security hardening, mapping corrections, and feature ideas.

## Before You Start

Please open an issue before starting large or risky changes. This helps avoid duplicated work and gives maintainers a chance to discuss the approach first.

Small fixes, documentation updates, and clearly scoped bug fixes can usually go straight to a pull request.

## Reporting Bugs

When reporting a bug, please include:

- The GWM for Home Assistant version.
- Your Home Assistant version.
- Whether you installed through HACS, manually, or from a development branch.
- Your architecture, such as `amd64`, `aarch64`, or `armv7`.
- Clear steps to reproduce the issue.
- Relevant Home Assistant logs.
- What you expected to happen.
- What actually happened.

Please remove GWM credentials, access and refresh tokens, security PINs, VINs, exact vehicle locations, private URLs, and personal Home Assistant configuration before sharing logs or screenshots.

## Suggesting Features

Feature requests are welcome. Please describe:

- The problem you want to solve.
- The Home Assistant workflow you expect to use.
- Whether the change belongs in `gwm_client` or the Home Assistant integration.
- The vehicle model/region involved, if relevant.
- Any safety, security, or privacy concerns the feature may introduce.

Features that expand remote vehicle control should include a clear safety rationale and must preserve explicit user opt-in.

## Adding Support for a New GWM Cloud Region

GWM's cloud APIs are private, undocumented, and different between regions. Authentication, gateway addresses, request signing, TLS requirements, headers, payloads, response formats, and remote-command behavior may all vary. Supporting a new region is therefore not as simple as adding another gateway hostname.

The maintainer cannot discover or safely validate a regional implementation without access to that region's official app, a locally registered account, and a compatible vehicle. Only a user who has that access can provide the protocol evidence and real-world testing needed to add reliable support. A feature request by itself is not enough, but the maintainer can review a community implementation, help fit it into the project, and take it forward from a pull request.

Only inspect an app, account, device, and vehicle that you are authorized to use. Follow applicable laws and the app's terms, and begin with read-only operations.

### Start With Public App Information

Before collecting traffic, add the following non-sensitive information to the related issue:

- The official app name and store link.
- The exact app version and, on Android, its package name.
- The phone platform and OS version.
- The broad account-registration country or region.
- The vehicle model and model year, without its VIN.

Do not send credentials or private captures at this stage. This information helps determine the safest and most useful next step.

### Capture the Regional Protocol

Android is generally the easiest platform to inspect. A typical workflow is:

1. Route a test phone or emulator through an HTTPS inspection tool such as mitmproxy, HTTP Toolkit, or Charles Proxy.
2. Record separate, focused sessions for login and SMS/e-mail verification, token refresh or session restoration, vehicle discovery, and vehicle-status refresh.
3. Perform one action at a time so each request can be matched to the corresponding screen or result in the official app.
4. If TLS certificate pinning prevents inspection, use JADX or apktool to examine the legitimately obtained APK for regional gateway configuration, API paths, request-signing code, and certificate handling. On a suitable test device, tools such as Frida or Objection may help inspect the app's own traffic.
5. Leave remote commands until read-only login, discovery, and status retrieval work. Test any command individually, near the vehicle, with explicit user opt-in and a clear way to confirm the physical result.

For each operation, determine as much of the following as possible:

- Gateway hostname, HTTP method, path, and query parameters.
- Required headers and the formats of country, region, app, and device identifiers.
- Request and response structures, including success and error codes.
- Login, verification, session-conflict, and token-refresh behavior.
- Request-signing or encryption algorithm, canonical input, encoding, and nonce/timestamp rules.
- Whether certificate pinning, client certificates, or mutual TLS are used.
- Vehicle discovery, status polling, and, later, command-result polling behavior.

Static analysis and traffic captures should be used together where practical: captures show the real wire format, while app code can explain signatures or values that a proxy cannot interpret.

### Sanitize All Evidence

Never post raw captures or logs without reviewing and sanitizing them. Remove or replace:

- Usernames, passwords, verification codes, security PINs, and answers to security questions.
- Access tokens, refresh tokens, cookies, session identifiers, API tokens, and signing secrets.
- VINs, internal vehicle identifiers, command IDs, device IDs, ICCIDs, and advertising IDs.
- Names, phone numbers, e-mail addresses, exact locations, private URLs, and other personal data.
- Private keys or other reusable client secrets extracted from an app or device.

Keep field names, data types, relevant prefixes, and approximate lengths where they are needed to understand the protocol, but replace values with obviously synthetic examples. Do not upload an APK or proprietary app assets to the repository. If you are unsure whether a value is sensitive, do not publish it; ask the maintainer how to proceed.

### Protocol Materials and Provenance

I do not accept new app-derived certificates, private keys, signing secrets, native libraries, decompiled source, or other proprietary assets in a public pull request. Existing audited files in this repository do not grant permission to add more material. Contact me privately before preparing a change that appears to require one of these items.

For an authorized replacement of an existing shared bootstrap file, I require the official app identity and version, acquisition channel, source package digest, extracted file digest, certificate identity and validity, and the applicable permission or review decision. Perform extraction outside the Git workspace and share only the minimum sanitized evidence needed for review. See [Third-Party and Protocol Material Notice](THIRD_PARTY_NOTICES.md) for the current inventory and release holds.

### Preparing a Pull Request

You may use an AI coding assistant of your choice to analyze sanitized evidence and prepare a pull request. Give it this repository, this contributing guide, and only sanitized captures or notes.

A useful regional pull request should include, as applicable:

- A new region option and its country/region validation.
- Regional gateway routing, authentication, verification, and token refresh.
- Region-specific signing, TLS policy, headers, serialization, and error handling.
- Vehicle discovery and status retrieval before remote commands.
- Sanitized fixtures, golden signing vectors, and focused tests for regional differences.
- Documentation, translations, configuration validation, and changelog updates.

Keep new regional behavior isolated so it does not silently change existing regions. Avoid guessing missing protocol details, and ensure the existing test suite continues to pass. The first pull request does not need to be perfect: a focused read-only implementation with good sanitized evidence and tests is a useful starting point that the maintainer can review and refine.

## Development Setup

Clone the repository:

```bash
git clone https://github.com/moryoav/ha-gwm-ev.git
cd ha-gwm-ev
```

The repository layout is:

```text
custom_components/gwm_ora/      Home Assistant custom integration
gwm_client/                     Home Assistant-independent async GWM cloud client
tests/python/                   Client and Home Assistant integration tests
.github/workflows/              CI and release workflows
```

I use neutral **GWM** names for new user-facing text, Python packages, and internal symbols. The `gwm-client` distribution imports as `gwm_client`. I preserve the existing `gwm_ora` Home Assistant domain and action namespace for compatibility, so do not copy that legacy prefix into new identifiers unless a compatibility contract requires it.

For local Home Assistant testing, install or copy the integration into:

```text
/config/custom_components/gwm_ora
```

## Pull Request Guidelines

Please keep pull requests focused. A good pull request should:

- Explain what changed and why.
- Mention any related issue.
- Keep unrelated formatting or refactoring out of the change.
- Update documentation when behavior, installation, options, entities, or commands change.
- Update `CHANGELOG.md` for user-facing changes.
- Update version fields when preparing a release.
- Include screenshots when changing Home Assistant UI text or setup flow behavior.
- Avoid committing credentials, tokens, security PINs, VINs, private locations, private logs, or personal Home Assistant configuration.

## Testing

Before opening a pull request, test the parts you changed as much as practical.

Run:

```powershell
python -m ruff check gwm_client custom_components tests/python
python -m mypy gwm_client
python -m compileall gwm_client custom_components tests/python
python -m pytest tests/python
```

For integration changes, verify that Home Assistant can:

- Load the `gwm_ora` integration.
- Complete a fresh GWM cloud sign-in and any requested verification.
- Reload or reconfigure the config entry.
- Create entities under the expected vehicle device.
- Download diagnostics without leaking account credentials or tokens.
- Mark entities unavailable when the GWM cloud is unavailable.

Remote commands should be tested only on a real vehicle with explicit user opt-in. Be physically near the vehicle when testing lock, climate, or window commands.

## Security Notes

This project handles GWM account credentials, vehicle cloud tokens, vehicle location, and optional remote commands.

Please be especially careful with changes involving:

- Username, password, security PIN, access token, or refresh token handling.
- Account-bound private storage and session restoration.
- Remote climate, lock, unlock, or close-window commands.
- Diagnostics redaction.
- Logs that may include VINs, precise locations, command IDs, tokens, or raw GWM API payloads.

If you believe you found a security vulnerability, do not open a public issue with exploit details. Follow `SECURITY.md`.

## Documentation

Please update documentation when changing user-facing behavior. Depending on the change, this may include:

- `README.md`
- `custom_components/gwm_ora/README.md`
- `CHANGELOG.md`

Use plain, direct language and include Home Assistant examples where they make the workflow easier to understand.

## Releases

HACS uses GitHub releases for update detection. Release pull requests should:

- Move `CHANGELOG.md` entries from `Unreleased` into the target version.
- Update `custom_components/gwm_ora/manifest.json`.
- Publish and pin the matching `gwm-client` package version.
- Push a `vX.Y.Z` tag after the release commit lands.

The release workflow creates the GitHub release from the matching changelog section. Production releases must use an immutable `gwm-client` version published through the approved package workflow.

## Code of Conduct

Please be respectful, constructive, and patient. This project controls real vehicle-facing features, and contributions should help Home Assistant users operate those features safely.
