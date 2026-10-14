# Lifecycle and integration

## Producer-consumer split

Host-install owns root-level STATE layout/admission and the root-owned identity authorization/consumption records. Host-identify owns the private key and signed envelope primitives. Host-discover is the unprivileged daemon responsible for periodic reports; station-access owns fingerprint approval and registry policy. This prevents any consumer from inventing identity from an observed cloud label or a missing file.

## Durability and coordination

Recovery restores the same protected identity and installation binding, retaining private-key mode/ownership and fsynced receipts. A changed host-install STATE volume, restored stale backup, missing authorization or managed checkpoint conflict causes an explicit reconciliation requirement, not an automatic repopulation of the key directory.

## Naming and historical compatibility

The `host-identify` program and `zog.host_identify` import replace the old naming without changing old audit facts. Historical source revisions and package version numbers may not uniquely identify the migration; install exact pinned companion commits and do not depend on implicit `host_identity` aliases.

## Detailed contracts and original evidence

- [HOST-INSTALL.md](../HOST-INSTALL.md)
- [RENAMING.md](../RENAMING.md)
- [MANAGED-PROTOCOL.md](../MANAGED-PROTOCOL.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
