# APAC read-only client: draft work

This is an early, unintegrated client draft. It is not a working Home Assistant setup, does not automatically authenticate, and must not be used for a live vehicle test yet. The APAC region has not been enabled in the setup flow. The client requires an explicit country: Thailand (`TH`), Malaysia (`MY`), Indonesia (`ID`) or Pakistan (`PK`), as listed in My GWM (`com.gwm.tha`). These countries share a proposed client implementation, not a claim of verified account or vehicle compatibility. Only Pakistan has contributor-reported live results from the earlier prototype; this draft branch has not been validated live in any country.

The draft provides explicitly invoked authentication primitives, strict identity validation, allowlisted discovery/status request preparation and a read-only transport adapter. It has no remote-control or charging-write API. The read-only components are not yet connected to configuration flow, account-bound private state, refresh/restart recovery, entity creation or Home Assistant service guards; those remain required.

## Private material

No APAC authentication material is included in this branch. The caller must explicitly supply an absolute, private directory outside the repository to `load_apac_material`. The directory is expected to contain `bootstrap.cer`, `bootstrap.key` (the existing transformed format), `ca.pem` (the four-certificate regional bundle) and `signing.json` with `app_key` and `app_secret` strings. The loader performs no downloads, has no default path, and does not log its contents or path. These names describe a proposed local test interface, not a redistribution license or a production setup instruction.

All test inputs in this branch are synthetic. The caller remains responsible for securing any real local files and following the maintainer's provenance decision. Do not copy files or real values into the repository, Git history, logs or issue comments.

## Current checks and limits

The existing EU identity policy remains unchanged. APAC uses separate TLS roles and identity validators. The issued validator checks the expected certificate issuer and cryptographic signature against the supplied chain and fails closed if they do not match. Enrollment and vehicle requests accept only contexts returned by the matching APAC identity validator. Contexts are recorded weakly so the registry does not retain sessions. Default TLS contexts and identities from another region or gateway role cannot substitute for a validated APAC identity. The caller must not mutate a validated context.

Synthetic checks cover every app-listed country's request headers, calling code and CSR country; independent signing vectors; schema and deadline failures; read-only endpoint denial; nonempty status values through the shared snapshot mapper; numeric basics fields; and unchanged EU, ANZ and Russia routing. These checks verify code contracts, not vendor compatibility in the untested countries.

Pending work includes account binding and private persistence, verification and reauthentication in the config flow, session renewal/restart recovery without silent password login, explicit denial of every command and charging write at client and integration/service boundaries, diagnostics redaction, translated UI, documentation, and full regression coverage. A real account and vehicle test for each country must use the exact eventual PR branch after those pieces are wired together.
