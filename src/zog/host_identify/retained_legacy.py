"""Read-only consumption of an already enrolled legacy Ed25519 key after STATE move.

This is NOT fresh host-install initialization and does not validate a journal by
itself. The privileged host-install migration owner must publish a completed,
root-owned receipt based on native postcondition checks and pass an already
verified identity directory descriptor. No path is opened to *find* the key.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import uuid

from .initialization import IdentityStateError, decode_key, directory_fd as safe_directory_fd
from .signatures import fingerprint

SCHEMA = "zog-retained-legacy-state-identity-completion-v1"
DIRECTORY = "/state/host-discover/identity"
FILES = frozenset({"identity.pem", "binding.json", "key.lock"})
OPTIONAL = frozenset({"registry-ca.pem"})
# Known legacy operational state, not Host identity or admission evidence.
# mirror-role.json is atomically replaced after role-state changes.
RETAINED_SIDECARS = frozenset({
    "mirror-role.json", "mirror-role.lock", "primary-origin.json",
})
ALLOWED = FILES | OPTIONAL | RETAINED_SIDECARS
MARKERS = frozenset({"initialization.json", "receipt.json", "prepared-key.pem",
                     "publish-key.tmp", "migration.json"})


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def _read_exact(fd, limit):
    os.lseek(fd, 0, os.SEEK_SET)
    data = os.read(fd, limit + 1)
    if len(data) > limit:
        raise IdentityStateError("Oversize protected evidence")
    return data


def _owned_file(fd, name, uid, mode=0o600):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    info = os.fstat(handle)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != mode
            or info.st_nlink != 1 or info.st_size > 32768):
        os.close(handle)
        raise PermissionError("Unsafe retained identity entry")
    return handle, info


def _inode(info):
    return [info.st_dev, info.st_ino]


def load_retained_legacy_fd(directory_fd, completion_fd, *,
                            expected_host_uuid, expected_fingerprint,
                            expected_registry_origin, identity_directory=DIRECTORY):
    """Load ONLY a committed migration, via retained directory and root-owned FD.

    The privileged native owner must independently authenticate descriptor
    origin and completion publication; this function rechecks their physical
    identity and contents. Neither descriptor is closed or newly created.
    """
    if identity_directory != DIRECTORY:
        raise IdentityStateError("Unexpected canonical migrated identity location")
    if not _uuid(expected_host_uuid):
        raise IdentityStateError("Expected enrolled Host UUID required")
    if (type(expected_fingerprint) is not str or len(expected_fingerprint) != 64
            or any(c not in "0123456789abcdef" for c in expected_fingerprint)):
        raise IdentityStateError("Expected previously enrolled fingerprint required")
    if not isinstance(expected_registry_origin, str) or not expected_registry_origin.startswith("https://"):
        raise IdentityStateError("Expected retained control registry required")
    # Refuse an unlinked/moved original inode or a replaced/symlinked path.
    with safe_directory_fd(identity_directory) as selected_fd:
        selected = os.fstat(selected_fd)
        held = os.fstat(directory_fd)
        if _inode(selected) != _inode(held):
            raise IdentityStateError("Migrated identity directory substituted")
    directory = os.fstat(directory_fd)
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
            or directory.st_gid != os.getegid() or stat.S_IMODE(directory.st_mode) != 0o700):
        raise PermissionError("Unsafe retained identity directory")
    # A read-only, root-owned, single-link receipt cannot be forged by the
    # unprivileged host-discover account. Native installer MUST supply its FD.
    receipt_info = os.fstat(completion_fd)
    if (not stat.S_ISREG(receipt_info.st_mode) or receipt_info.st_uid != 0
            or stat.S_IMODE(receipt_info.st_mode) != 0o600
            or receipt_info.st_nlink != 1 or not 0 < receipt_info.st_size <= 8192
            or fcntl.fcntl(completion_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
        raise PermissionError("Untrusted or writable migration completion")
    try:
        receipt = json.loads(_read_exact(completion_fd, 8192))
    except (ValueError, UnicodeError) as error:
        raise IdentityStateError("Malformed migration completion") from error
    expected_fields = {"schema", "status", "migration_id", "identity_directory",
                       "host_uuid", "fingerprint", "registry_origin", "uid", "gid",
                       "identity_inode", "key_inode", "binding_inode", "lock_inode",
                       "plan_sha256", "journal_sha256", "ca_inode", "ca_sha256"}
    if (type(receipt) is not dict or set(receipt) != expected_fields
            or receipt["schema"] != SCHEMA or receipt["status"] != "complete"
            or not _uuid(receipt["migration_id"])
            or receipt["identity_directory"] != identity_directory
            or receipt["host_uuid"] != expected_host_uuid
            or receipt["fingerprint"] != expected_fingerprint
            or receipt["registry_origin"] != expected_registry_origin
            or type(receipt["uid"]) is not int or receipt["uid"] != os.geteuid()
            or type(receipt["gid"]) is not int or receipt["gid"] != os.getegid()
            or any(type(receipt[x]) is not str or len(receipt[x]) != 64
                   or any(c not in "0123456789abcdef" for c in receipt[x])
                   for x in ("plan_sha256", "journal_sha256"))
            or _inode(directory) != receipt["identity_inode"]):
        raise IdentityStateError("Incomplete or foreign retained identity migration")
    entries = set(os.listdir(directory_fd))
    if not FILES <= entries or entries - ALLOWED:
        raise IdentityStateError("Unexpected migrated identity directory contents")
    lock, lock_info = _owned_file(directory_fd, "key.lock", os.geteuid())
    try:
        if _inode(lock_info) != receipt["lock_inode"]:
            raise IdentityStateError("Retained identity lock substituted")
        fcntl.flock(lock, fcntl.LOCK_SH)
        # Recheck under the same never-replaced key.lock inode.
        entries = set(os.listdir(directory_fd))
        if not FILES <= entries or entries - ALLOWED:
            raise IdentityStateError("Conflicting identity transaction")
        # Validate only security metadata. Legacy role/origin records are
        # retained in place and are not reinterpreted by the key loader.
        # A role writer may atomically replace mirror-role.json AFTER restart;
        # its inode must therefore not become permanent completion metadata.
        sidecar_inodes = {}
        for sidecar in sorted(entries & RETAINED_SIDECARS):
            sidecar_fd, sidecar_info = _owned_file(
                directory_fd, sidecar, os.geteuid())
            try:
                if sidecar_info.st_dev != directory.st_dev:
                    raise PermissionError("Retained sidecar crosses filesystem")
                sidecar_inodes[sidecar] = _inode(sidecar_info)
            finally:
                os.close(sidecar_fd)
        if "registry-ca.pem" in entries:
            ca, ca_info = _owned_file(directory_fd, "registry-ca.pem", os.geteuid())
            try:
                if (_inode(ca_info) != receipt["ca_inode"]
                        or hashlib.sha256(_read_exact(ca, 32768)).hexdigest()
                        != receipt["ca_sha256"]):
                    raise IdentityStateError("Migrated registry CA changed")
            finally:
                os.close(ca)
        elif receipt["ca_inode"] is not None or receipt["ca_sha256"] is not None:
            raise IdentityStateError("Retained CA missing from migrated identity")
        for name, field in (("identity.pem", "key_inode"),
                            ("binding.json", "binding_inode")):
            handle, info = _owned_file(directory_fd, name, os.geteuid())
            try:
                if _inode(info) != receipt[field]:
                    raise IdentityStateError("Retained identity inode substituted")
                data = _read_exact(handle, 32768)
                if name == "identity.pem":
                    key = decode_key(data)
                else:
                    try:
                        binding = json.loads(data)
                    except (ValueError, UnicodeError) as error:
                        raise IdentityStateError("Invalid retained binding") from error
            finally:
                os.close(handle)
        if (type(binding) is not dict or set(binding) != {"host_id", "fingerprint"}
                or binding["host_id"] != expected_host_uuid
                or binding["fingerprint"] != expected_fingerprint
                or fingerprint(key.public_key()) != expected_fingerprint):
            raise IdentityStateError("Retained key and enrolled binding disagree")
        # Recheck paths and retained lock inode immediately before admitting
        # identity, including a concurrent replacement after the first read.
        for name,field in (("key.lock","lock_inode"),
                           ("identity.pem","key_inode"),
                           ("binding.json","binding_inode")):
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or _inode(info) != receipt[field]):
                raise IdentityStateError("Retained entry replaced during inspection")
        for name, originally_seen in sidecar_inodes.items():
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_gid != os.getegid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or info.st_dev != directory.st_dev
                    or _inode(info) != originally_seen):
                raise IdentityStateError("Retained sidecar replaced during load")
        if set(os.listdir(directory_fd)) != entries:
            raise IdentityStateError("Retained identity inventory changed")
        with safe_directory_fd(identity_directory) as selected_fd:
            if _inode(os.fstat(selected_fd)) != receipt["identity_inode"]:
                raise IdentityStateError("Migrated identity path replaced")
        return key, dict(binding)
    finally:
        os.close(lock)
