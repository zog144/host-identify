# Identity verification and acceptance

## Fixture evidence and limits

The preserved host-install foundation validation exercises reuse, independent-process locking, fsync failures, unsafe-file refusal, no-overwrite key publication, matching authorization/consumption, and companion host-discover observation parsing. It is deliberately a local/synthetic coverage report, not confirmation of a booted host.

## Live acceptance requires more

Host-install or host-deploy must separately prove fixed UID/GID, real mounted STATE, recovery holds, identity persistence across process restart and reboot, station fingerprint approval, and authenticated heartbeat delivery. Power-loss, clone/restore detection and remote-control behavior are not implied by temporary-directory tests.

## Failure protocol

If identity evidence is absent, unreadable or inconsistent, retain original files and fail closed. Do not reset the host UUID, generate a replacement key under the same identity, or reissue an expired managed session with a guessed checkpoint. Preserve original tested companion pins when reporting results.

## Detailed contracts and original evidence

- [VALIDATION-HOST-INSTALL.md](../VALIDATION-HOST-INSTALL.md)
- [HOST-INSTALL.md](../HOST-INSTALL.md)
- [MANAGED-PROTOCOL.md](../MANAGED-PROTOCOL.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
