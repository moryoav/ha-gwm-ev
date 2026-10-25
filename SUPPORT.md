# Support

Thanks for using GWM for Home Assistant.

## Getting Help

Start with the project documentation:

- `README.md` for installation, setup, entities, use cases, troubleshooting, releases, and security notes.
- `custom_components/gwm_ora/README.md` for integration behavior.
- `CHANGELOG.md` for released changes.

## Reporting Bugs

Use the bug report issue template when something is not working as expected.

Please include:

- Your GWM for Home Assistant version.
- Your Home Assistant version.
- Your installation method.
- Your architecture, such as `amd64`, `aarch64`, or `armv7`.
- Whether the issue affects the client, the integration flow, polling, entities, or commands.
- Clear reproduction steps.
- Relevant logs with sensitive information removed.

Do not include GWM credentials, access or refresh tokens, security PINs, VINs, precise vehicle locations, private URLs, personal paths, or private Home Assistant configuration.

## Feature Requests

Use the feature request issue template for new ideas or improvements.

Please explain the Home Assistant workflow you want to improve and whether you think the change belongs in `gwm_client` or the custom integration.

Remote-command requests must include a safety and privacy rationale.

## Inactive Issues

I mark issues as stale after 23 days without comments or updates and close them 7 days later if there is still no activity. A comment or update before closure removes the stale label and restarts the timer when the daily workflow runs.

I keep issues with the `in-progress` or `keep-open` label open, and I exclude pull requests from this policy. Existing open issues count from their last activity, so an issue that is already inactive receives a warning on the first run and has 7 more days before closure.

If an issue is closed and still needs attention, please comment with an update and ask me to reopen it.

## Security Issues

If you believe you found a security vulnerability, do not open a public issue with exploit details. Follow `SECURITY.md`.

## Scope of Support

This project is provided by the community and may not have immediate support. GWM cloud APIs can change without notice, and vehicle behavior can vary by region, model year, account type, and app backend.

Remote commands affect a real vehicle. Keep the official GWM app available as the source of truth, and test carefully before relying on automations.
