import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_identify import (
    archive_credentials, credential_delivery, mirror_access, signatures, storage,
)
from test_archive_storage import (
    AUDIENCE, ISSUER, MIRROR, grant, paths, save,
)


def provider_scope(**changes):
    host_key=changes.pop("host_key",Ed25519PrivateKey.generate())
    value={
        "schema":archive_credentials.PROVIDER_SCOPE_SCHEMA,
        "host_id":str(uuid.uuid4()),
        "host_fingerprint":signatures.fingerprint(host_key.public_key()),
        "installation_id":str(uuid.uuid4()),
        "state_volume_id":str(uuid.uuid4()),
        "registry_id":"hosts",
        "provider_id":"canonical-upstream",
        "provider_origin":"https://provider.example.test",
        "provider_role":archive_credentials.PROVIDER_ROLE,
        "role_revision":7,
        "collections":["sources"],
        "operations":["fetch"],
        "provider_credential_id":"source-read",
        "credential_revision":3,
    }
    value.update(changes)
    return host_key,value


def authorization(scope,key,now=1_800_000_000,**changes):
    selected=archive_credentials.provider_scope(scope)
    value={
        "schema":credential_delivery.AUTHORIZATION_SCHEMA,
        "issuer":"https://authority.example.test",
        **archive_credentials.provider_binding(scope),
        "credential_revision":selected["credential_revision"],
        "authorization_id":str(uuid.uuid4()),
        "revision":4,
        "status":"approved",
        "approved_at":now-60,
        "revoked_at":None,
        "expires_at":now+3600,
    }
    value.update(changes)
    return credential_delivery.sign_authorization(value,key),value


def test_archive_inventory_enables_only_provider_https_purpose():
    value=archive_credentials.inventory()
    assert value["schema"]=="zog-archive-credential-inventory-v1"
    assert archive_credentials.enabled_https_purposes()==(
        archive_credentials.PROVIDER_PURPOSE,
    )
    assert value["classes"]["consumer-access-token"]["transport"]=="authenticated-host-response"
    assert value["classes"]["consumer-access-token"]["https_delivery_purpose"] is None
    assert value["classes"]["token-issuer-signing-key"]["transport"]=="never-distribute-to-mirror"
    assert value["classes"]["verification-keyring"]["secret"] is False
    for kind in ("upstream-collection-credential","provider-service-credential"):
        profile=archive_credentials.https_delivery_profile(kind)
        assert profile["purpose"]==archive_credentials.PROVIDER_PURPOSE
        assert profile["consumer"]=="archive-mirror"
        assert profile["provider_role"]=="upstream-source-provider"
        assert profile["operations"]==["fetch"]
    for kind in ("consumer-access-token","token-issuer-signing-key",
                 "verification-keyring","tls-private-key"):
        with pytest.raises(archive_credentials.ArchiveCredentialPolicyError):
            archive_credentials.https_delivery_profile(kind)


def test_provider_scope_is_exact_and_binds_collection_role_revision_and_origin():
    _,base=provider_scope()
    selected=archive_credentials.provider_scope(base)
    assert selected["purpose"]==archive_credentials.PROVIDER_PURPOSE
    assert selected["consumer"]=="archive-mirror"
    assert len(selected["scope_id"])==64
    assert selected["credential_id"].startswith("archive-provider-")
    for changed in (
        {"collections":["root-filesystems"]},
        {"provider_origin":"https://other.example.test"},
        {"role_revision":8},
        {"provider_credential_id":"other-read"},
    ):
        candidate={**base,**changed}
        assert (
            archive_credentials.provider_scope(candidate)["credential_id"]
            != selected["credential_id"]
        )
    with pytest.raises(archive_credentials.ArchiveCredentialPolicyError):
        archive_credentials.provider_scope({**base,"operations":["download"]})
    with pytest.raises(archive_credentials.ArchiveCredentialPolicyError):
        archive_credentials.provider_scope(
            {**base,"provider_role":"mirror-consumer"}
        )


def test_common_authorization_is_exactly_bound_to_provider_scope():
    _,scope=provider_scope()
    authority=Ed25519PrivateKey.generate()
    envelope,raw=authorization(scope,authority)
    accepted=archive_credentials.verify_provider_authorization(
        envelope,authority.public_key(),
        expected_issuer="https://authority.example.test",scope=scope,
        now=1_800_000_000,
    )
    assert accepted==raw
    _,other=provider_scope(collections=["root-filesystems"])
    with pytest.raises(credential_delivery.CredentialProtocolError):
        archive_credentials.verify_provider_authorization(
            envelope,authority.public_key(),
            expected_issuer="https://authority.example.test",scope=other,
            now=1_800_000_000,
        )
    with pytest.raises(archive_credentials.ArchiveCredentialPolicyError):
        archive_credentials.verify_provider_authorization(
            envelope,authority.public_key(),
            expected_issuer="https://authority.example.test",
            scope={**scope,"credential_revision":4},
            now=1_800_000_000,
        )


def test_provider_request_uses_common_protocol_without_archive_access_token_fields():
    _,scope=provider_scope()
    authority=Ed25519PrivateKey.generate()
    _,auth=authorization(scope,authority)
    request=archive_credentials.request(
        scope,auth,request_id=str(uuid.uuid4()),action="deliver",
        previous_delivery_id=None,created_at=1_800_000_000,
        expires_at=1_800_000_060,
    )
    assert request["consumer"]=="archive-mirror"
    assert request["purpose"]==archive_credentials.PROVIDER_PURPOSE
    assert set(request).isdisjoint({"issuer","audience","collection","operations","token"})


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
