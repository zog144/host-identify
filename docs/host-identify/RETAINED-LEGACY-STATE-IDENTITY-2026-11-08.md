# Retained legacy Ed25519 identity under canonical STATE — consumer contract

**2026-11-08 · source-only · host-identify 0.3.5 candidate descendant · host-discover #7 / host-install PR #36**

This interface is deliberately **distinct** from fresh `initialization.prepare`/`load_existing_fd` and historical `storage.load_key`/`load_existing_key`. Existing keys are never generated, reissued, staged, moved, re-enrolled or given a synthetic fresh-initialization receipt. This module reads only. No network dependency or network call is involved.

## Exact API and authority

```python
from zog.host_identify.retained_legacy import load_retained_legacy_fd
key, binding = load_retained_legacy_fd(
    identity_dirfd, completed_migration_fd,
    expected_host_uuid=previous_host_uuid,
    expected_fingerprint=previous_public_fingerprint,
    expected_registry_origin=previous_control_registry_https_origin,
    identity_directory="/state/host-discover/identity",
)
```

Caller retains ownership of **both file descriptors**. The native host-install owner must independently identify the canonical `/state` directory, open the retained identity without symlink traversal, verify transaction postconditions and pass a protected root-owned completion FD. A descriptor supplied by an ordinary JSON value, a user-controlled path, or a remote request is **not** authoritative. Source CI cannot authenticate the native FD-supplying process. The native owner needs explicit per-operation authorized publication and recoverable completion before enabling the daemon.

The protected completion file is a regular file **UID 0, mode 0600, link count 1**, opened **O_RDONLY**, and delivered as an already-open FD to the unprivileged host-discover process. The identity directory is owned by the running host-discover account, its primary group matches the caller, and its mode is 0700. Its canonical path must be exactly `/state/host-discover/identity`; the loader performs a symlink-safe directory walk and checks that the selected directory and retained FD reference the same `(st_dev,st_ino)` pair. The three required regular files are `identity.pem`, `binding.json`, and `key.lock`; only `registry-ca.pem` may also exist. Each retained file is owner/current-GID, mode 0600, link count 1, no symlink, bounded. All fresh-managed and staging markers are forbidden.

## Exact completion document

The root-owned, bounded UTF-8 JSON document has **exactly** these fields:

```json
{
  "schema": "zog-retained-legacy-state-identity-completion-v1",
  "status": "complete",
  "migration_id": "canonical-uuid-of-local-migration",
  "identity_directory": "/state/host-discover/identity",
  "host_uuid": "unchanged-canonical-host-uuid",
  "fingerprint": "unchanged-lowercase-64-hex-ed25519-public-fingerprint",
  "registry_origin": "https://the-unchanged-registry-origin",
  "uid": 970,
  "gid": 970,
  "identity_inode": [1, 101],
  "key_inode": [1, 102],
  "binding_inode": [1, 103],
  "lock_inode": [1, 104],
  "plan_sha256": "64-lowercase-hex-digest",
  "journal_sha256": "64-lowercase-hex-digest"
}
```

The inode pairs above are **illustrative**, not approved values. The actual issuer must bind real observed `st_dev/st_ino` from the original pre-move entries to final post-move entries, prove same-filesystem rename preserving them, and bind the selected host-install migration plan and durably completed journal bytes to their SHA-256. Never manufacture this file from caller-provided IDs or an unverified `status` string. The root-owned completion is separate from the fresh `receipt.json`; it must reside outside the identity directory and never overwrite an initialization receipt. The native issuer must also validate that the durable transaction has no pending stage/rollback and that the previous Host UUID, public fingerprint, control registry and enrollment binding are preserved.

On every load, the consumer checks receipt identity/UID/GID/inodes, exact directory entries, prior public fingerprint, Ed25519 key and matching `binding.json` `{host_id,fingerprint}`. It retains a shared lock on the original `key.lock` while inspecting the key and binding. No missing state is initialized, and no failure authorizes a network enrollment. Source code does not accept merely `verified=true`, an arbitrary supplied JSON dict, or a fabricated fresh receipt.

**Native HOLD:** host-install PR #36 currently provides a source preflight and simulated journal only, with native executor disabled. It does **not** yet publish this root-owned completion, the protected native FD handoff, or a separately verified postcondition probe. Those responsibilities must land and be accepted separately before the existing host-registry Host is touched. No new registrar, external signer, Command Center enrollment or credentials are required for this local operation.
