# Authenticated enrollment and managed envelopes

## Different security domains

Host Ed25519 signatures prove possession of the registered key; a command center must separately approve its fingerprint and verify the associated Host UUID. Managed sessions use an independently pinned station authority/signing key; they are not archive JWTs or rootfs signing keys.

## Strict managed session profile

The `zog.host_identify.managed` validator permits EdDSA only, closed JWT header/claim types, a pinned key fingerprint, HTTPS issuer, authority audience, host/fingerprint/installation/STATE/registry bindings, process challenge, boot ID, previous checkpoint and short expiry. Unexpected algorithms/remote key URLs are refused, and the profile grants only explicit `inspect` operations, not arbitrary commands.

## Ambiguous acceptance remains ambiguous

A server-issued response received after expiry or wrong checkpoint cannot be accepted as a fresh authorization. The verifier checks all expected identity bindings and preserves exact previous checkpoint; future key rotation requires an explicit transition. A passing cryptographic signature alone is not enrollment authority or a complete managed-host control channel.

## Detailed contracts and original evidence

- [MANAGED-PROTOCOL.md](../MANAGED-PROTOCOL.md)
- [HOST-INSTALL.md](../HOST-INSTALL.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
