# Archive credential provisioning boundary

Archive authorization has two deliberately separate mechanisms.

1. **Short-lived archive access grants** remain the existing
   `zog-archive-jwt-v1` bearer tokens issued by the archive authority and
   delivered through the authenticated Host response path. Every consumer use
   still checks issuer, audience, operation, collection and expiry; mirror
   discovery additionally binds the stored Host identity to the current
   candidate set. These grants are not converted into reusable passwords and
   are not installed through the generic credential-delivery framework.
2. **Durable cross-host secrets**, if archive-mirror ever needs any, must use
   the common authenticated HTTPS credential-delivery framework with an
   explicitly reviewed archive purpose, consumer and protected destination.

Current archive-mirror has **no enabled durable-secret delivery purpose**.

The machine-readable policy is
`zog.host_identify.archive_credentials.inventory()`. Its current classes are:

- `consumer-access-token`: secret but short-lived; existing authenticated Host
  response only.
- `token-issuer-signing-key`: durable authority secret; **never distribute to
  a mirror**. Mirrors receive public verification keys only.
- `verification-keyring`: public rotatable configuration, not a credential.
- `upstream-collection-credential`: unsupported. Current Git and exact-source
  acquisition require credential-free HTTPS URLs.
- `provider-service-credential`: unsupported. Archive serving has no shared
  provider password.
- `tls-private-key`: owned by the certificate/HTTPS termination path, not by
  archive-mirror.

`enabled_https_purposes()` therefore returns an empty tuple, and
`https_delivery_profile(kind)` rejects every current class. This is
intentional fail-closed integration with the unified framework: another
component's purpose (for example `issuer-cloudflare-dns01`) must never be
reused as an archive credential purpose.

When an actual archive-owned durable secret is introduced, the change must
define an explicit HTTPS delivery purpose and bind at least the exact approved
Host/installation identity, archive provider or collection role, credential
revision, consumer, destination and permitted operation. The common [HTTPS credential-delivery v1](CREDENTIAL-DELIVERY.md) framework's
signature verification, anti-replay/revocation handling and protected local
installation interface remain transport/installation owners; host-identify
should only define the archive-specific authorization profile.

Role withdrawal remains separate from storage lifetime. A removed/expired mirror
role makes mirror selection fail but does not delete retained archive contents.
Likewise, changing the approved Host identity invalidates the current local
candidate/token binding rather than migrating a credential implicitly.

Source tests: `tests/test_archive_credentials.py` covers role withdrawal,
expired grants, incorrect collections and Host identity changes, plus the
zero-enabled-purpose policy.
