# Identity ownership and persistent keys

## Host-identify owns identity, not transport

Host-identify handles strict key/identity material and authenticated envelope validation; host-install prepares durable STATE and authorizes first initialization, while host-discover subsequently transports host evidence. A host UUID, key fingerprint, installation UUID, STATE-volume identity and display label are different identifiers and must not be conflated.

## Protected first initialization

The host-install coordinator verifies an actual mounted STATE, account/permission profile and root-owned operation before allowing the host-discover UID/GID to create or load a private Ed25519 key. A `fresh` flag or absent path is not sufficient authority to create a new host identity. Publication binds the consumed authorization and receipt, uses locked/atomic durable writes, and refuses to overwrite a conflicting key/record.

## Recovery and safe reuse

Existing private key and receipt are inspected together. Unsafe symlinks, partial files, mismatched STATE/installation binding or missing original key fail closed rather than silently minting a replacement. Identity migration and station adoption are separately reviewed operations; a cloned disk cannot be assumed to be a new enrolled host.

## Detailed contracts and original evidence

- [HOST-INSTALL.md](../HOST-INSTALL.md)
- [VALIDATION-HOST-INSTALL.md](../VALIDATION-HOST-INSTALL.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
