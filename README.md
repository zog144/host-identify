# host-identify

**Documentation:** [Technical manual](docs/host-identify/README.md) · [Source traceability](docs/host-identify/TRACEABILITY.md). The manual organizes current concepts; linked detailed sources preserve exact contracts and historical evidence.

Shared Python security library for station-access, host-discover and archive-mirror.
Version **0.3.5** supplies signed host messages, short-lived scoped archive tokens,
protected local credential storage and authorized mirror discovery. It is a
library, not an enrollment server or background daemon.

## Install

Use Linux and Python 3.12+. From this directory:

```sh
python3.12 -m pip install .
```

Dependencies are declared in `pyproject.toml`: http-message-signatures,
cryptography, PyJWT, requests and typing_extensions. Install this local package
before its companion programs; it is not assumed to be on a public package index.

## Interfaces and ownership

| Module | Interface |
| --- | --- |
| `zog.host_identify.signatures` | Ed25519 public-key/fingerprint helpers and HTTP message signing/verification |
| `zog.host_identify.archive` | Issue and verify issuer/audience/operation/collection-scoped archive tokens |
| `zog.host_identify.credential_delivery` | Pure v1 schemas, signatures and durable anti-replay state transitions for separately authorized HTTPS secret delivery |
| `zog.host_identify.storage` | Protected key/grant files, atomic updates and expiry handling |
| `zog.host_identify.mirror_access` | `read_access(...)` validates a grant and returns ready HTTPS candidates |

Host-discover owns a dedicated host key; station-access owns approval, replay
tracking and authorization. A valid signature alone is not enrollment approval.
Archive issuers keep their private signing key centrally; providers receive only
the configured verification keyring. Consumers must supply the expected issuer,
audience, operation, collection and mirror binding when reading grants.

`read_access` returns a bearer token with endpoint/expiry information: do not log
its result. Consumers still need direct HTTPS requests, redirect rejection and
checksum/size verification. The helper does not download archives or decide
which bytes a build should consume. `mirror_fixture.py` is a test fixture, not the
production archive-mirror implementation.

State directories have strict ownership, mode and file-type checks. Preserve
host identities across restarts, isolate them from other hosts, and keep private
keys, tokens and credential directories out of source archives and reusable
images. See the separately maintained station-access signed-host protocol and archive
authorization documentation for authoritative integration details.

## Tests

After installing the package and pytest:

```sh
python -m pytest -q tests
```

These tests exercise local storage and mirror grants. End-to-end signed
registry/replay/approval coverage also lives in station-access's backend tests;
run `python tools/test-backend.py` from the separately installed station-access repository root. Neither
suite is a live host enrollment or archive-provider deployment test.

## Source ownership

Canonical public repository: https://github.com/zog144/host-identify.
Consumers must select a reviewed public source revision explicitly; previously
selected private Git commits have different identities and must not be silently
relabeled. Do not vendor copies into consumer repositories. The installed
import path is `zog.host_identify`.
This component remains independently developed, while public Python publication is
only through the aggregate `zog` distribution assembled by release-build.

## host-install integration foundation

See [HOST-INSTALL.md](docs/host-identify/HOST-INSTALL.md) for explicit identity initialization,
offline contract verification, compatibility and remaining live-admission work.
This pass does not enable a new Zog-host daemon or remote control channel.

Current managed integration: [protocol profiles](docs/host-identify/MANAGED-PROTOCOL.md). The inspect-only managed session does not authorize secrets. Reusable secret transport is defined separately by [HTTPS credential delivery v1](docs/host-identify/CREDENTIAL-DELIVERY.md). Production credential delivery remains disabled.

## Expired-session evidence (0.3.4)

`zog.host_identify.recovery` defines the separate signed expiry-evidence profile and canonical request digest. It verifies exact bindings, key/header, bounded lifetime and expiry. The optional explicit verification time is for already authorized root-owned recovery receipts, never untrusted timestamps. This envelope grants no session/control capability. Operator/storage policy belongs to host-discover; station-access owns authoritative request history.

## Public source and license

Original first-party source and documentation in this repository are available
under `BSD-3-Clause OR GPL-3.0-only`; see [LICENSE](LICENSE),
[LICENSES](LICENSES/) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
The clean public Git history excludes private handoffs and operational evidence.
Local tests do not establish real host enrollment or recovery acceptance.

## Archive credential boundary

Archive authorization keeps short-lived scoped JWT grants separate from durable secret provisioning. Current archive-mirror has no approved durable cross-host credential purpose; issuer signing keys never move to mirrors and current upstream acquisition is credential-free. See [archive credential provisioning boundary](docs/host-identify/ARCHIVE-CREDENTIALS.md).
