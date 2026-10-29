import json
import time
import uuid

import pytest

from zog.host_identify import archive_credentials, mirror_access, storage
from test_archive_storage import (
    AUDIENCE, ISSUER, MIRROR, grant, paths, save,
)


def test_archive_inventory_has_no_enabled_cross_host_secret_purpose():
    value=archive_credentials.inventory()
    assert value["schema"]=="zog-archive-credential-inventory-v1"
    assert archive_credentials.enabled_https_purposes()==()
    assert value["classes"]["consumer-access-token"]["transport"]=="authenticated-host-response"
    assert value["classes"]["token-issuer-signing-key"]["transport"]=="never-distribute-to-mirror"
    assert value["classes"]["verification-keyring"]["secret"] is False
    assert value["classes"]["upstream-collection-credential"]["transport"]=="unsupported"
    assert value["classes"]["provider-service-credential"]["transport"]=="unsupported"
    for kind in value["classes"]:
        with pytest.raises(archive_credentials.ArchiveCredentialPolicyError):
            archive_credentials.https_delivery_profile(kind)


def _roles(host_id, *, selected=True, ready=True, revision=7):
    return {
        "desired":{
            "version":1,
            "revision":revision,
            "selected":selected,
            "endpoint":MIRROR if selected else "",
            "retain_archives":True,
            "lease_expires_at":int(time.time())+900,
        },
        "candidates":[{
            "host_id":str(uuid.uuid4()),
            "endpoint":MIRROR,
            "revision":revision,
            "ready":ready,
            "state":"ready" if ready else "stopped",
        }] if selected else [],
    }


def test_role_withdrawal_removes_access_without_creating_shared_password(tmp_path,grant):
    _,shared=paths(tmp_path)
    key,host,data=grant
    save(shared,host,data)
    mirror_access.save_candidates(shared,host,_roles(host))
    result=mirror_access.read_access(
        shared,{"one":key.public_key()},ISSUER,AUDIENCE,"download","sources",MIRROR)
    assert result["token"]==data["token"]
    withdrawn=_roles(host,selected=False,ready=False,revision=8)
    mirror_access.save_candidates(shared,host,withdrawn)
    with pytest.raises(PermissionError):
        mirror_access.read_access(
            shared,{"one":key.public_key()},ISSUER,AUDIENCE,"download","sources",MIRROR)
    # The short-lived credential file may still exist until heartbeat withdrawal/
    # expiry cleanup, but role withdrawal independently blocks provider selection.
    assert (shared/"archive.json").exists()
    assert not any("password" in p.name.lower() for p in shared.iterdir())


def test_expired_access_grant_fails_each_read(tmp_path,grant):
    _,shared=paths(tmp_path)
    key,host,data=grant
    save(shared,host,data)
    mirror_access.save_candidates(shared,host,_roles(host))
    expired=dict(data,expires_at=int(time.time())-1)
    storage.atomic(shared/"archive.json",json.dumps(expired).encode(),0o640,shared.stat().st_gid)
    with pytest.raises(PermissionError):
        mirror_access.read_access(
            shared,{"one":key.public_key()},ISSUER,AUDIENCE,"download","sources",MIRROR)


def test_incorrect_collection_does_not_expand_access(tmp_path,grant):
    _,shared=paths(tmp_path)
    key,host,data=grant
    save(shared,host,data)
    mirror_access.save_candidates(shared,host,_roles(host))
    with pytest.raises(PermissionError):
        mirror_access.read_access(
            shared,{"one":key.public_key()},ISSUER,AUDIENCE,
            "download","root-filesystems",MIRROR)


def test_host_identity_change_invalidates_candidate_binding(tmp_path,grant):
    _,shared=paths(tmp_path)
    key,host,data=grant
    save(shared,host,data)
    other=str(uuid.uuid4())
    mirror_access.save_candidates(shared,other,_roles(other))
    with pytest.raises(PermissionError,match="identity mismatch"):
        mirror_access.read_access(
            shared,{"one":key.public_key()},ISSUER,AUDIENCE,"download","sources",MIRROR)
