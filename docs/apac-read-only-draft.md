# APAC read-only development setup

This development branch adds a shared APAC read-only Home Assistant setup for Pakistan (`PK`), Thailand (`TH`), Malaysia (`MY`) and Indonesia (`ID`), the countries listed in My GWM (`com.gwm.tha`). All four countries use the same regional implementation.

Remote controls and charging writes are disabled for APAC, including when stale enabled options exist or a direct service call is attempted. Existing region policies remain separate. Authentication and vehicle requests use distinct, strictly validated TLS contexts.

## Private local material

APAC setup loads private material from `.storage/gwm_apac_material/` inside Home Assistant's configuration directory, using `hass.config.path`. For example, if the configuration directory is `/config`, the full path is `/config/.storage/gwm_apac_material/`. Use the actual configuration directory for your installation. It must contain:

- `bootstrap.cer`: the separately supplied bootstrap certificate.
- `bootstrap.key`: the separately supplied transformed bootstrap key.
- `ca.pem`: the separately supplied four-certificate regional CA bundle.
- `signing.json`: an object with `app_key` and `app_secret` string fields.

The directory and its contents must remain outside Git workspaces, the repository and public issue/PR history. Restrict access to the Home Assistant account, account for backups, and follow the maintainer's provenance and permission decision. This project does not provide, extract, download or distribute this material. The loader rejects paths inside the source Git workspace and paths resolving outside the private directory. Don't place personal account information, vehicle identifiers or tokens in `signing.json`.

The format is shown below using deliberately fake values; these do not authenticate:

```json
{"app_key": "synthetic-key", "app_secret": "synthetic-secret"}
```

After supplying authorized material, add the GWM integration, choose **Asia-Pacific (read-only)**, select the account's registration country, and enter the account credentials. Complete a verification code only when requested. The integration stores account-bound session state privately in Home Assistant storage. On restart it attempts to restore an issued identity and renew an expired session without silently falling back to password login or requesting another code.

## Development testing

Synthetic tests cover setup continuation, account/device binding, private state storage, read-only safeguards, response mapping, token expiry and refresh, and existing regional behavior.

The contributor's live test with a Pakistan account and a 2026 Haval H6 PHEV covered setup, vehicle discovery, readings, subsequent updates, and reconnection after a Home Assistant restart.

Live testing of token expiry and refresh is still needed before release.
