# Test suite

I keep tests that protect an observable contract or reproduce a distinct failure. I do not use the number of collected cases as a coverage target.

## Boundaries and layout

| Boundary | Tests | What the tests establish |
| --- | --- | --- |
| Regional authentication | `python/client/test_*_auth.py`, identity and crypto tests | Account binding, verification, renewal, TLS identities, exact signing vectors, and finite recovery |
| Cloud client reads and writes | `python/client/test_client.py`, `test_china_client.py`, `test_china_commands.py`, `test_china_comfort.py`, `test_china_charging.py`, regional fixtures | Exact wire requests, response interpretation, acceptance, and regional isolation |
| HTTP and route policy | Transport, GTSP, and charging transport tests | Allowed destinations, methods, headers, signatures, payloads, response limits, cancellation, and session ownership |
| Telemetry | Models, snapshots, China status, and expanded GTSP status tests | Units, unknown values, field precedence, physical sides, and independent measurements |
| Home Assistant polling | `python/test_cloud_journey.py`, coordinator and runtime tests | Real client-to-entity polling, atomic refresh, outage recovery, stale values, and session recovery |
| Home Assistant entities and actions | Entity, window, BeanTech, GTSP, and charging service tests | Registered entities, stable identities, exact commands, independent permissions, readback, and service validation |
| Authentication and command storage | Cloud storage, entry, command, and config flow tests | Durable state, account isolation, restart recovery, cancellation, removal, and command non-replay |
| Diagnostics | Request/auth diagnostics and integration diagnostics tests | Useful bounded metadata without credentials, identifiers, raw responses, or private locations |
| Distribution | HACS release, provenance, and quality file tests | An isolated ZIP installation, audited protocol materials, renewal deadlines, translations, service metadata, and branding |
| Offline proof-of-concept tools | Live POC and China POC tests | Read-only allowlists and safe handling of externally supplied state; the tests do not access a vehicle |

`python/support/` contains shared synthetic sessions, HTTP fakes, and entity contexts. Test modules import these helpers instead of importing another test module. The China transport fake rejects unplanned operations, and the queue fakes reject extra requests. Regional protocol fixtures remain separate because their differences are part of the contract.

## Assertions and parameter tables

- I use independent expected actions, field mappings, and captured protocol vectors. Reading an expected action or state key from the entity under test would hide incorrect wiring.
- I exercise client requests through public methods before mutating the captured request at the transport boundary. The private transport request types represent that boundary; their rejection behavior is intentional coverage.
- I keep the complete conversion truth table for a representative field and separately check each physical field's wiring and unknown state. Repeating every scalar input for every window adds little protection once both contracts are covered.
- I check every independent remote/charging permission combination on the supported platform. Unsupported platforms are checked with permissions enabled, so the platform restriction must enforce the rejection.
- I retain separate protocol, storage, cancellation, and failure regressions even when they execute the same lines. Execution coverage alone cannot prove that an assertion is useful.
- I avoid repository-history assertions and exact source/prose strings. File-content checks remain where the content itself is the contract, such as translations, service schemas, audited hashes, or shipped license notices.

## Running the suite

I run Home Assistant tests on Linux, including WSL on Windows, using the Python and Home Assistant versions in [the Python workflow](../.github/workflows/python.yml). A clean virtual environment avoids unrelated globally installed pytest plugins. The workflow also checks the extracted HACS installation on the minimum supported Home Assistant release.

From the repository root:

```bash
python -m pytest tests/python
python -m pytest tests/python/test_cloud_journey.py tests/python/test_window_entities.py
python -m pytest tests/python/client/test_china_auth.py tests/python/test_cloud_storage.py
```

For a coverage comparison, I put generated data outside the checkout:

```bash
COVERAGE_FILE=/tmp/gwm-tests.coverage python -m pytest tests/python \
  --cov=custom_components/gwm_ora --cov-branch \
  --cov-report=json:/tmp/gwm-tests-coverage.json --cov-report=term-missing
```

When reducing a matrix or rewriting an assertion, I compare executed production lines and branches before and after. I also check sensitivity to the relevant fault, such as a swapped rear window, wrong seat action, wrong consent flag, missing service validation, secret logging, or command replay. Deliberate faults are applied only in isolated offline test processes and never saved to production source.

## Certificate renewal gate

`test_bootstrap_renewal_deadlines_have_not_elapsed` checks the current time against the audited bootstrap renewal deadlines. It remains part of the default suite. An elapsed deadline is a maintenance failure, not an unexpected protocol regression or a reason to skip the check.

Certificate metadata, key matching, validity records, hashes, and bundle contents are tested separately, so a renewal failure does not prevent the remaining audited materials from being checked. Replacing a certificate or changing its deadline requires the provenance process in [CONTRIBUTING.md](../CONTRIBUTING.md).
