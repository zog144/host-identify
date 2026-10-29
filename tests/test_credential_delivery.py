import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures


ISSUER = "https://credentials.example.test"


@pytest.fixture
def fixture():
    host_key = Ed25519PrivateKey.generate()
    authority_key = Ed25519PrivateKey.generate()
    now = int(time.time())
    binding = {
        "host_id": str(uuid.uuid4()),
        "host_fingerprint": signatures.fingerprint(host_key.public_key()),
        "installation_id": str(uuid.uuid4()),
        "state_volume_id": str(uuid.uuid4()),
        "registry_id": "primary",
        "consumer": "station-access",
        "purpose": "admin-password",
        "credential_id": "station-admin",
    }
    authorization = {
        "schema": cd.AUTHORIZATION_SCHEMA,
        "issuer": ISSUER,
        **binding,
        "credential_revision": 1,
        "authorization_id": str(uuid.uuid4()),
        "revision": 1,
        "status": "approved",
        "approved_at": now - 1,
        "revoked_at": None,
        "expires_at": now + 3600,
    }
    return host_key, authority_key, binding, authorization, now


def request(authorization, now, **changes):
    value = {
        "schema": cd.REQUEST_SCHEMA,
        **{key: authorization[key] for key in (
            "host_id", "host_fingerprint", "installation_id",
            "state_volume_id", "registry_id", "consumer", "purpose",
            "credential_id", "credential_revision",
        )},
        "authorization_id": authorization["authorization_id"],
        "authorization_revision": authorization["revision"],
        "request_id": str(uuid.uuid4()),
        "action": "deliver",
        "previous_delivery_id": None,
        "created_at": now,
        "expires_at": now + 60,
    }
    value.update(changes)
    return value


def delivery(req, authorization, now, secret=b"very-secret-value", **changes):
    value = {
        "schema": cd.DELIVERY_SCHEMA,
        "request_id": req["request_id"],
        "delivery_id": str(uuid.uuid4()),
        "authorization_id": authorization["authorization_id"],
        "authorization_revision": authorization["revision"],
        "credential_id": authorization["credential_id"],
        "credential_revision": authorization["credential_revision"],
        "consumer": authorization["consumer"],
        "purpose": authorization["purpose"],
        "issued_at": now,
        "expires_at": now + 60,
        "secret_format": "base64",
        "secret": base64.b64encode(secret).decode(),
    }
    value.update(changes)
    return value


def receipt(req, delivered, now, **changes):
    value = {
        "schema": cd.RECEIPT_SCHEMA,
        **{key: req[key] for key in (
            "host_id", "host_fingerprint", "installation_id",
            "state_volume_id", "registry_id", "consumer", "purpose",
            "credential_id", "credential_revision", "authorization_id",
            "authorization_revision", "request_id",
        )},
        "delivery_id": delivered["delivery_id"],
        "receipt_id": str(uuid.uuid4()),
        "outcome": "installed",
        "installed_at": now,
    }
    value.update(changes)
    return value


def cancel(req, now, **changes):
    value = {
        "schema": cd.CANCEL_SCHEMA,
        **{key: req[key] for key in (
            "host_id", "host_fingerprint", "installation_id",
            "state_volume_id", "registry_id", "consumer", "purpose",
            "credential_id", "credential_revision", "authorization_id",
            "authorization_revision", "request_id",
        )},
        "cancel_id": str(uuid.uuid4()),
        "reason": "operator-request",
        "created_at": now,
        "expires_at": now + 60,
    }
    value.update(changes)
    return value


def test_authorization_is_independently_signed_and_purpose_scoped(fixture):
    _, authority_key, binding, value, now = fixture
    envelope = cd.sign_authorization(value, authority_key)
    assert cd.verify_authorization(
        envelope, authority_key.public_key(),
        expected_issuer=ISSUER, expected_binding=binding, now=now,
    ) == value

    with pytest.raises(cd.CredentialProtocolError):
        cd.verify_authorization(
            envelope, Ed25519PrivateKey.generate().public_key(),
            expected_issuer=ISSUER, expected_binding=binding, now=now,
        )
    with pytest.raises(cd.CredentialProtocolError, match="binding"):
        cd.verify_authorization(
            envelope, authority_key.public_key(),
            expected_issuer=ISSUER,
            expected_binding=dict(binding, purpose="archive-mirror"),
            now=now,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_id", lambda: str(uuid.uuid4())),
        ("host_fingerprint", lambda: "f" * 64),
        ("installation_id", lambda: str(uuid.uuid4())),
        ("state_volume_id", lambda: str(uuid.uuid4())),
        ("registry_id", lambda: "secondary"),
        ("consumer", lambda: "archive-mirror"),
        ("purpose", lambda: "cloudflare-token"),
        ("credential_id", lambda: "other"),
        ("credential_revision", lambda: 2),
        ("authorization_id", lambda: str(uuid.uuid4())),
        ("authorization_revision", lambda: 2),
    ],
)
def test_request_rejects_cross_scope_replay(fixture, field, value):
    _, _, _, authorization, now = fixture
    with pytest.raises(cd.CredentialProtocolError):
        cd.validate_request(
            request(authorization, now, **{field: value()}),
            authorization,
            now=now,
        )


def test_revoked_and_expired_authorizations_cannot_deliver(fixture):
    _, authority_key, binding, authorization, now = fixture
    revoked = dict(
        authorization, revision=2, status="revoked", revoked_at=now
    )
    verified = cd.verify_authorization(
        cd.sign_authorization(revoked, authority_key),
        authority_key.public_key(),
        expected_issuer=ISSUER, expected_binding=binding, now=now,
    )
    with pytest.raises(cd.CredentialProtocolError, match="revoked"):
        cd.validate_request(request(verified, now), verified, now=now)

    expired = dict(
        authorization, approved_at=now - 1000, expires_at=now - 10
    )
    with pytest.raises(cd.CredentialProtocolError, match="lifetime"):
        cd.verify_authorization(
            cd.sign_authorization(expired, authority_key),
            authority_key.public_key(),
            expected_issuer=ISSUER, expected_binding=binding, now=now,
        )


def test_host_identity_http_authentication_is_separate_from_authority(fixture):
    host_key, _, _, authorization, now = fixture
    req = request(authorization, now)
    prepared = cd.prepare_request(
        ISSUER + "/api/credentials/deliver/",
        req, authorization, host_key, nonce="A" * 24,
    )
    decoded, nonce, _ = cd.verify_request_http(
        prepared.url, "POST", dict(prepared.headers), prepared.body,
        host_key.public_key(), authorization, now=now,
    )
    assert decoded == req
    assert nonce == "A" * 24

    with pytest.raises((ValueError, cd.CredentialProtocolError)):
        cd.verify_request_http(
            prepared.url, "POST", dict(prepared.headers), prepared.body,
            Ed25519PrivateKey.generate().public_key(), authorization, now=now,
        )


def test_delivery_is_authority_signed_and_secret_is_not_in_ledger(fixture):
    _, authority_key, _, authorization, now = fixture
    req = request(authorization, now)
    value = delivery(req, authorization, now)
    verified = cd.verify_delivery(
        cd.sign_delivery(value, authority_key),
        authority_key.public_key(), req, authorization, now=now,
    )
    assert cd.secret_bytes(verified) == b"very-secret-value"

    state = cd.record_delivery(
        cd.admit_request(cd.new_ledger(authorization), req), verified
    )
    encoded = json.dumps(state)
    assert "very-secret-value" not in encoded
    assert value["secret"] not in encoded


def test_tampered_or_oversize_secret_is_rejected(fixture):
    _, authority_key, _, authorization, now = fixture
    req = request(authorization, now)
    value = delivery(req, authorization, now)
    envelope = cd.sign_delivery(value, authority_key)
    tampered = json.loads(json.dumps(envelope))
    tampered["delivery"]["secret"] = base64.b64encode(b"attacker").decode()
    with pytest.raises(cd.CredentialProtocolError, match="signature"):
        cd.verify_delivery(
            tampered, authority_key.public_key(), req, authorization, now=now
        )

    oversize = delivery(
        req, authorization, now, secret=b"x" * (cd.MAX_SECRET + 1)
    )
    with pytest.raises(cd.CredentialProtocolError, match="secret"):
        cd.verify_delivery(
            cd.sign_delivery(oversize, authority_key),
            authority_key.public_key(), req, authorization, now=now,
        )


def test_delivery_is_not_installation_and_uncertainty_blocks_redelivery(fixture):
    _, authority_key, _, authorization, now = fixture
    state = cd.new_ledger(authorization)
    req = request(authorization, now)
    state = cd.admit_request(state, req)
    delivered = delivery(req, authorization, now)
    state = cd.record_delivery(state, delivered)
    assert state["requests"][-1]["status"] == "delivered"
    assert state["requests"][-1]["receipt_id"] is None

    with pytest.raises(cd.CredentialProtocolError, match="in-progress"):
        cd.admit_request(state, request(authorization, now))

    installed = receipt(req, delivered, now)
    cd.validate_receipt(installed, req, delivered, now=now)
    state = cd.record_installation(state, installed)
    assert state["requests"][-1]["status"] == "installed"


def test_receipt_is_secret_free_and_host_identity_signed(fixture):
    host_key, _, _, authorization, now = fixture
    req = request(authorization, now)
    delivered = delivery(req, authorization, now)
    installed = receipt(req, delivered, now)
    prepared = cd.prepare_receipt(
        ISSUER + "/api/credentials/receipt/",
        installed, req, delivered, host_key, nonce="B" * 24,
    )
    verified, nonce, _ = cd.verify_receipt_http(
        prepared.url, "POST", dict(prepared.headers), prepared.body,
        host_key.public_key(), req, delivered, now=now,
    )
    assert verified == installed
    assert nonce == "B" * 24
    encoded = json.dumps(installed).lower()
    assert "secret" not in encoded
    assert "sha256" not in encoded


def test_receipt_after_delivery_expiry_is_rejected(fixture):
    _, _, _, authorization, now = fixture
    req = request(authorization, now)
    delivered = delivery(req, authorization, now, expires_at=now + 1)
    with pytest.raises(cd.CredentialProtocolError, match="installed-at"):
        cd.validate_receipt(
            receipt(req, delivered, now + 10),
            req, delivered, now=now + 10,
        )


def test_cancel_before_delivery_is_safe_and_signed(fixture):
    host_key, _, _, authorization, now = fixture
    state = cd.new_ledger(authorization)
    req = request(authorization, now)
    state = cd.admit_request(state, req)
    value = cancel(req, now)
    prepared = cd.prepare_cancel(
        ISSUER + "/api/credentials/cancel/",
        value, req, host_key, nonce="C" * 24,
    )
    verified, nonce, _ = cd.verify_cancel_http(
        prepared.url, "POST", dict(prepared.headers), prepared.body,
        host_key.public_key(), req, now=now,
    )
    assert nonce == "C" * 24
    state = cd.record_cancel(state, verified)
    assert state["requests"][-1]["status"] == "cancelled"
    assert state["rotation_required"] is False


def test_cancel_after_delivery_forces_rotation(fixture):
    _, _, _, authorization, now = fixture
    req = request(authorization, now)
    state = cd.admit_request(cd.new_ledger(authorization), req)
    state = cd.record_delivery(state, delivery(req, authorization, now))
    state = cd.record_cancel(state, cancel(req, now))
    assert state["requests"][-1]["status"] == "cancelled-after-delivery"
    assert state["rotation_required"] is True
    with pytest.raises(cd.CredentialProtocolError, match="renewal"):
        cd.admit_request(state, request(authorization, now))


def test_renewal_requires_new_revision_and_exact_previous_delivery(fixture):
    _, _, _, authorization, now = fixture
    first = request(authorization, now)
    delivered = delivery(first, authorization, now)
    state = cd.admit_request(cd.new_ledger(authorization), first)
    state = cd.record_delivery(state, delivered)
    state = cd.record_installation(state, receipt(first, delivered, now))

    auth2 = dict(
        authorization, revision=2, credential_revision=2,
        expires_at=now + 7200,
    )
    state = cd.advance_authorization(state, auth2)
    renew = request(
        auth2, now, action="renew",
        previous_delivery_id=delivered["delivery_id"],
    )
    state = cd.admit_request(state, renew)
    assert state["requests"][-1]["action"] == "renew"

    # Cancel the pending renewal before testing another request identity.
    state = cd.record_cancel(state, cancel(renew, now))
    wrong = request(
        auth2, now, action="renew",
        previous_delivery_id=str(uuid.uuid4()),
    )
    with pytest.raises(cd.CredentialProtocolError, match="previous"):
        cd.admit_request(state, wrong)


def test_revocation_after_delivery_blocks_installation(fixture):
    _, _, _, authorization, now = fixture
    req = request(authorization, now)
    delivered = delivery(req, authorization, now)
    state = cd.record_delivery(
        cd.admit_request(cd.new_ledger(authorization), req), delivered
    )
    revoked = dict(
        authorization, revision=2, status="revoked", revoked_at=now
    )
    state = cd.advance_authorization(state, revoked)
    with pytest.raises(cd.CredentialProtocolError, match="revoked"):
        cd.record_installation(state, receipt(req, delivered, now))


def test_authorization_rollback_conflict_and_revocation_reversal_block(fixture):
    _, _, _, authorization, now = fixture
    state = cd.new_ledger(authorization)
    revoked = dict(
        authorization, revision=2, credential_revision=2,
        status="revoked", revoked_at=now,
    )
    state = cd.advance_authorization(state, revoked)
    with pytest.raises(cd.CredentialProtocolError, match="rollback"):
        cd.advance_authorization(state, authorization)

    conflict = dict(revoked, status="approved", revoked_at=None)
    with pytest.raises(cd.CredentialProtocolError):
        cd.advance_authorization(state, conflict)

    later_approval = dict(
        authorization, revision=3, credential_revision=3,
        status="approved", revoked_at=None,
    )
    with pytest.raises(cd.CredentialProtocolError, match="reversal"):
        cd.advance_authorization(state, later_approval)


def test_same_request_retry_is_idempotent_but_changed_identity_conflicts(fixture):
    _, _, _, authorization, now = fixture
    req = request(authorization, now)
    state = cd.admit_request(cd.new_ledger(authorization), req)
    assert cd.admit_request(state, req) == state
    conflict = dict(
        req,
        action="renew",
        previous_delivery_id=str(uuid.uuid4()),
    )
    with pytest.raises(cd.CredentialProtocolError, match="conflict"):
        cd.admit_request(state, conflict)


def test_cancel_is_fresh_and_secret_free(fixture):
    _, _, _, authorization, now = fixture
    req = request(authorization, now)
    value = cancel(req, now, reason="interruption-recovery")
    assert cd.validate_cancel(value, req, now=now) == value
    assert "secret" not in json.dumps(value).lower()
    expired = dict(value, created_at=now - 500, expires_at=now - 400)
    with pytest.raises(cd.CredentialProtocolError, match="lifetime"):
        cd.validate_cancel(expired, req, now=now)
