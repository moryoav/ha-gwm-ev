# Third-Party and Protocol Material Notice

## Scope

I license the original project code and documentation under the repository MIT license only where I have the right to do so. The MIT license does not grant rights in Great Wall Motor applications, certificates, keys, trademarks, services, or protocol material, and it does not cure missing permission for source-derived work from another repository.

The unpublished `gwm-client` distribution uses `LicenseRef-GWM-Protocol-Materials` in its package metadata as a truthful label for the material described below. It is not a license grant. I have not established redistribution permission for every listed item, so I will not publish the client package or make a production release until I record permission or replace the affected material through a documented authorized path. The immutable source dependency in the development branch is only for controlled installation testing.

## Provenance Record

| Material | Origin and evidence | Current location | Status before publication |
| --- | --- | --- | --- |
| EU bootstrap certificate, transformed key, CA bundle, and RSA recovery behavior | The official EU GWM Android app. The three resource files match the public [`zivillian/ora2mqtt`](https://github.com/zivillian/ora2mqtt) files after newline normalization. That project also documented the app asset names and RSA transformation. The source app version for these exact files was not recorded. | `custom_components/gwm_ora/resources/` | I need written permission or another documented redistribution basis. I also need a replacement certificate before the renewal deadline. |
| Russia bootstrap certificate, transformed key, CA bundle, gateway values, and signing values | The official Russian GWM Android app, contributed in repository commit [`44b6201`](https://github.com/moryoav/ha-gwm/commit/44b6201c0d88aa26b98050f3cc51f917bf4f28a8). The exact source APK version and digest were not recorded. | `custom_components/gwm_ora/resources/` and regional protocol code in `gwm_client/` | I need written permission or another documented redistribution basis before publication. |
| EU, ANZ, and Russia protocol constants and behavior | Static analysis of the official regional apps, sanitized protocol work, and contributor validation recorded in repository history. The earlier ANZ work was contributed in commit `2e17338`. The current ANZ beta also uses static evidence from official package `com.gwm.oceania`, version `1.0.6`, version code `27`, base APK SHA-256 `fa78850af033ee3fa5b1b614bad8a746c365e516e091095487143ad4bd751f33`. The EU and Russia paths are recorded in the migration ledger. | `gwm_client/` | I treat functional protocol facts separately from copied expression, but I do not claim that this audit supplies legal clearance. I need to resolve any source-derived expression that lacks permission before publication. |
| Mainland China signing, encryption, service, and command material | Static analysis of official package `com.gwm.fusion`, version `2.1.5`, version code `2150`, with source APK SHA-256 `5100473a5d9d811781485efe9ae1f4f7a1f6299e9641d996afc1d7f4f041ff32`, plus sanitized fixture and contributed live evidence. I did not add the APK, native libraries, decompiled source, or raw captures to this repository. | `gwm_client/china_*.py` and synthetic fixtures | I need written permission or another documented basis before production package publication or release. The development branch exposes China only for controlled integration testing. This is not legal clearance. |
| RSA recovery implementation informed by `zivillian/ora2mqtt` | The public `ora2mqtt` `CertificateHandler.cs` explained the OEM transformation and linked the standard RSA factor-recovery algorithm. On 2026-08-30 I found no license file in that repository. | Independently structured Python implementation | I need explicit upstream permission or a documented independent replacement before publication. Attribution alone is not permission. |

The machine-readable file `custom_components/gwm_ora/resources/provenance.json` records exact resource hashes, certificate identities, source references, and renewal dates. It hashes canonical UTF-8 content with CRLF normalized to LF so Git checkout settings cannot change the audit result. I keep user-issued certificates, user private keys, account tokens, credentials, verification codes, VINs, locations, APKs, and raw captures out of the repository.

## Runtime Dependencies

The unpublished `gwm-client` distribution declares only direct runtime dependencies. I do not vendor their source or license text into the wheel.

| Dependency | Constraint | Upstream license metadata | Reason |
| --- | --- | --- | --- |
| [`aiohttp`](https://pypi.org/project/aiohttp/) | `>=3.13.3,<4` | Apache-2.0 AND MIT | Async HTTP transport |
| [`cryptography`](https://pypi.org/project/cryptography/) | `>=46.0.2` | Apache-2.0 OR BSD-3-Clause | X.509, RSA, and AES operations |
| [`yarl`](https://pypi.org/project/yarl/) | `>=1.22.0,<2` | Apache-2.0 | Direct URL construction and validation |

These lower bounds match the versions in Home Assistant 2026.1.0, which is the current minimum in `hacs.json`. Home Assistant already requires all three libraries. The development manifest pins the GWM client to an immutable source archive for branch testing. A production release must use a separately published and approved client package.

## Certificate Renewal Control

I do not download or replace shared app identity material at runtime. A runtime download would create an unaudited trust and availability dependency inside Home Assistant.

The current EU bootstrap certificate expires at `2027-01-04T01:52:04Z`; its renewal deadline is `2026-10-06T01:52:04Z`. The current Russia certificate expires at `2030-04-21T08:21:35Z`; its renewal deadline is `2030-01-21T08:21:35Z`. The deadline is 90 days before expiry. Automated tests fail once a deadline is reached.

For a replacement, I must record the official app identity and version, acquisition channel, source package digest, each extracted file digest, certificate identity and validity, and the permission or review decision. I must perform extraction outside the Git workspace, replace the integration resource copy, update the provenance manifest, and pass the offline identity, TLS, packaging, and full regression suites. If I cannot complete that process, the affected region cannot pass final production cutover.

This notice records technical facts and project release conditions. It is not legal advice and does not claim affiliation with or endorsement by Great Wall Motor.
