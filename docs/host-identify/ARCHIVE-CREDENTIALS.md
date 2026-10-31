# Archive credentials and unified HTTPS delivery

Archive credentials have two separate security planes.

## Short-lived consumer access grants

Archive consumers continue to use `zog-archive-jwt-v1` bearer grants obtained
through the existing authenticated Host-response path. These grants remain
short-lived and are checked on every use for issuer, audience, archive
operation, collection and expiry. They are **not** common HTTPS-delivered
provider credentials and must never be converted into shared passwords.

The archive token authority signing private key remains authority-private.
Mirrors receive public Ed25519 verification keys only.

## Durable upstream-provider credential profile

A durable secret needed by archive-mirror to authenticate to an explicitly
approved upstream archive provider uses the canonical
`zog.host_identify.credential_delivery` protocol with:

- consumer: `archive-mirror`
- purpose: `archive-mirror-upstream-fetch`
- scope schema: `zog-archive-provider-credential-scope-v1`
- provider role: `archive-mirror-provider`
- operation: exactly `fetch`

The nonsecret provider scope binds the exact Host ID and HostIdentity
fingerprint, installation, STATE volume, registry, provider ID and HTTPS origin,
provider-role revision, sorted archive collections, operation, underlying
provider credential ID and credential revision.

The common protocol does not add archive-specific fields to its wire schema.
Instead, the adapter derives the common `credential_id` from SHA-256 of the
exact provider/origin/role/collection/operation/provider-credential scope.
Changing any of those values therefore changes the common authorization binding
and requires a separately approved authorization. Credential rotation retains
the same scope-derived ID and advances the canonical `credential_revision`.

`verify_provider_authorization`, `request` and `validate_delivery` reuse the
canonical signed authorization/request/delivery validation and durable ledger
semantics. The adapter does not open sockets, store secret bytes, mint authority,
or replace the protected receiver.

## Role withdrawal and retained archives

Archive-mirror provider-role withdrawal must disable use of an installed upstream-provider
credential, but it must not delete archive objects, pins, reviewed-source
membership or catalogue history. Archive-mirror's local protected adapter owns
that runtime gate. The common credential authorization/ledger remains separate
from the archive provider-role lease.

## Explicit exclusions

- No archive consumer JWT uses `archive-mirror-upstream-fetch`.
- No mirror receives the archive token issuer private signing key.
- No credential is embedded in an upstream URL or ordinary archive
  configuration.
- No browser/session credential, beacon secret, journal field or command-line
  argument is a provider-secret carrier.
- TLS private keys remain owned by certificate/HTTPS termination.

Source tests in `tests/test_archive_credentials.py` cover exact scope binding,
collection/origin/role revision changes, wrong operation/role, canonical
authorization mismatch, and preservation of the existing short-lived archive
grant semantics.
