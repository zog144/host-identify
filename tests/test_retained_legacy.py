"""Read-only legacy migration loader: synthetic filesystem, no host migration."""
import json
import os
import stat
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_identify import retained_legacy as migration
from zog.host_identify.signatures import fingerprint


@pytest.fixture
def installed(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("privileged source fixture requires root-owned receipt; no live Host")
    root = tmp_path / "state" / "host-discover" / "identity"
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    monkeypatch.setattr(migration, "DIRECTORY", str(root))
    key = Ed25519PrivateKey.generate()
    key_file = root / "identity.pem"
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    host = str(uuid.uuid4())
    finger = fingerprint(key.public_key())
    (root / "binding.json").write_text(json.dumps({"host_id":host, "fingerprint":finger}))
    (root / "key.lock").write_bytes(b"")
    for file in root.iterdir():
        file.chmod(0o600)
    receipt_path = tmp_path / "completion.json"
    def evidence(status="complete"):
        def ino(path):
            s = path.stat()
            return [s.st_dev, s.st_ino]
        return {"schema":migration.SCHEMA, "status":status,
                "migration_id":str(uuid.uuid4()),
                "identity_directory":str(root), "host_uuid":host,
                "fingerprint":finger,
                "registry_origin":"https://registry.example.invalid",
                "uid":os.geteuid(), "gid":os.getegid(),
                "identity_inode":ino(root), "key_inode":ino(key_file),
                "binding_inode":ino(root/"binding.json"),
                "lock_inode":ino(root/"key.lock"),
                "ca_inode":None, "ca_sha256":None,
                "plan_sha256":"a"*64, "journal_sha256":"b"*64}
    receipt = evidence()
    receipt_path.write_text(json.dumps(receipt))
    receipt_path.chmod(0o600)
    return root, key, host, finger, receipt_path, receipt, evidence


def load(row, receipt=None):
    root, key, host, finger, path, original, _ = row
    folder = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        completion = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return migration.load_retained_legacy_fd(folder, completion,
                expected_host_uuid=host, expected_fingerprint=finger,
                expected_registry_origin="https://registry.example.invalid",
                identity_directory=str(root))
        finally:
            os.close(completion)
    finally:
        os.close(folder)

def test_original_key_binding_and_repeated_restart(installed):
    root, key, host, finger, path, receipt, _ = installed
    first, binding = load(installed)
    assert fingerprint(first.public_key()) == finger
    assert binding == {"host_id":host, "fingerprint":finger}
    before = sorted((p.name, p.stat().st_ino, p.read_bytes()) for p in root.iterdir())
    second, _ = load(installed)
    assert fingerprint(second.public_key()) == finger
    assert sorted((p.name, p.stat().st_ino, p.read_bytes()) for p in root.iterdir()) == before


@pytest.mark.parametrize("attack", [
    "missing-binding", "wrong-binding", "wrong-host", "wrong-fingerprint",
    "wrong-receipt", "pending", "extra-file", "managed-receipt",
    "key-symlink", "key-hardlink", "lock-hardlink", "binding-symlink",
    "key-mode", "binding-mode", "foreign-receipt", "directory-replaced",
    "receipt-mode", "receipt-hardlink", "wrong-key", "unexpected-ca",
    "foreign-key-owner", "foreign-binding-owner", "foreign-directory-owner",
    "wrong-directory-mode", "wrong-key-group", "missing-key",
    "missing-ca-after-receipt", "wrong-ca-bytes",
])
def test_fail_closed(installed, attack, tmp_path):
    root, key, host, finger, path, receipt, evidence = installed
    if attack == "missing-binding": (root/"binding.json").unlink()
    elif attack == "wrong-binding": (root/"binding.json").write_text("{}")
    elif attack == "wrong-host": receipt["host_uuid"] = str(uuid.uuid4())
    elif attack == "wrong-fingerprint": receipt["fingerprint"] = "0"*64
    elif attack == "wrong-receipt": receipt["schema"] = "fake"
    elif attack == "pending": receipt["status"] = "applying"
    elif attack == "extra-file": (root/"foreign").write_text("x")
    elif attack == "managed-receipt": (root/"receipt.json").write_text("{}")
    elif attack == "key-symlink":
        (root/"identity.pem").unlink()
        (root/"identity.pem").symlink_to(tmp_path/"missing")
    elif attack == "key-hardlink": os.link(root/"identity.pem", tmp_path/"linked")
    elif attack == "lock-hardlink": os.link(root/"key.lock", tmp_path/"linked")
    elif attack == "binding-symlink":
        (root/"binding.json").unlink()
        (root/"binding.json").symlink_to(tmp_path/"missing")
    elif attack == "key-mode": (root/"identity.pem").chmod(0o644)
    elif attack == "binding-mode": (root/"binding.json").chmod(0o644)
    elif attack == "foreign-receipt": receipt["uid"] = os.geteuid()+1
    elif attack == "directory-replaced":
        moved = root.with_name("moved")
        root.rename(moved)
        root.mkdir(mode=0o700)
    elif attack == "receipt-mode": path.chmod(0o640)
    elif attack == "receipt-hardlink": os.link(path, tmp_path/"linked")
    elif attack == "wrong-key":
        replacement = Ed25519PrivateKey.generate()
        (root/"identity.pem").write_bytes(replacement.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    elif attack == "unexpected-ca":
        (root/"registry-ca.pem").symlink_to(tmp_path/"missing")
    elif attack == "foreign-key-owner": os.chown(root/"identity.pem", 10001, -1)
    elif attack == "foreign-binding-owner": os.chown(root/"binding.json", 10001, -1)
    elif attack == "foreign-directory-owner": os.chown(root, 10001, -1)
    elif attack == "wrong-directory-mode": root.chmod(0o750)
    elif attack == "wrong-key-group": os.chown(root/"identity.pem", -1, 10001)
    elif attack == "missing-key": (root/"identity.pem").unlink()
    elif attack in ("missing-ca-after-receipt", "wrong-ca-bytes"):
        import hashlib
        ca = root/"registry-ca.pem"
        ca.write_bytes(b"retained-original-ca")
        ca.chmod(0o600)
        s = ca.stat()
        receipt["ca_inode"] = [s.st_dev, s.st_ino]
        receipt["ca_sha256"] = hashlib.sha256(ca.read_bytes()).hexdigest()
        if attack == "missing-ca-after-receipt":
            ca.unlink()
        else:
            ca.write_bytes(b"substituted-ca")
    path.write_text(json.dumps(receipt))
    with pytest.raises((ValueError, PermissionError, OSError)):
        load(installed)


def test_no_initialization_or_legacy_fallback(installed):
    from zog.host_identify import storage, initialization
    root, key, host, finger, path, receipt, _ = installed
    with pytest.raises(PermissionError):
        storage.load_existing_key("/state/host-discover/identity")
    with pytest.raises((ValueError, PermissionError, OSError)):
        initialization.load_existing(root, receipt)


@pytest.mark.parametrize("attack", (
    "valid", "mutable-role", "wrong-mode", "wrong-owner",
    "symlink", "hardlink", "unlisted-extra", "missing-lock",
))
def test_known_legacy_role_and_primary_origin_sidecars(installed,attack,tmp_path):
    """Retained files are operational state, not new identity or enrollment."""
    root,key,host,finger,receipt_path,receipt,_=installed
    originals={
        "mirror-role.json":b'{"status":{"state":"stopped"}}',
        "mirror-role.lock":b"",
        "primary-origin.json":b'{"origin":"https://registry.example.invalid"}',
    }
    for name,body in originals.items():
        file=root/name
        file.write_bytes(body)
        file.chmod(0o600)
    original_inodes={name:(root/name).stat().st_ino for name in originals}
    if attack=="wrong-mode":
        (root/"mirror-role.json").chmod(0o644)
    elif attack=="wrong-owner":
        os.chown(root/"primary-origin.json",10001,-1)
    elif attack=="symlink":
        (root/"primary-origin.json").unlink()
        (root/"primary-origin.json").symlink_to(tmp_path/"foreign")
    elif attack=="hardlink":
        os.link(root/"mirror-role.lock",tmp_path/"linked")
    elif attack=="unlisted-extra":
        (root/"arbitrary.json").write_bytes(b"{}")
    elif attack=="missing-lock":
        (root/"mirror-role.lock").unlink()
        # The source inventory must decide what was present. The retained
        # key loader itself accepts known optional operational state; the
        # original-witness comparison prevents a disappeared original lock.
        key_loaded,_=load(installed)
        assert fingerprint(key_loaded.public_key())==finger
        return
    if attack in ("wrong-mode","wrong-owner","symlink","hardlink",
                  "unlisted-extra"):
        with pytest.raises((ValueError,PermissionError,OSError)):
            load(installed)
        return
    loaded,binding=load(installed)
    assert fingerprint(loaded.public_key())==finger
    assert binding=={"host_id":host,"fingerprint":finger}
    assert all((root/name).read_bytes()==body for name,body in originals.items())
    if attack=="mutable-role":
        # Existing roles.Controller.save uses an atomic replacement.
        # Restart must not reject the role record simply because the
        # normal writer gave mirror-role.json a fresh inode.
        replacement=root/".role-next"
        replacement.write_bytes(b'{"status":{"state":"ready"}}')
        replacement.chmod(0o600)
        os.replace(replacement,root/"mirror-role.json")
        assert (root/"mirror-role.json").stat().st_ino != (
            original_inodes["mirror-role.json"])
        reloaded,_=load(installed)
        assert fingerprint(reloaded.public_key())==finger
        assert (root/"mirror-role.lock").stat().st_ino==(
            original_inodes["mirror-role.lock"])
