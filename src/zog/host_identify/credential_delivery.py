"""Unified HTTPS credential delivery protocol v1.

Pure protocol and state-transition primitives only. This module opens no
network sockets, stores no secret bytes, and does not decide local installation
policy. Callers must durably persist HTTP-signature nonces and the returned
secret-free ledger before taking the corresponding external action.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import time
import uuid

from cryptography.exceptions import InvalidSignature

from . import signatures


AUTHORIZATION_SCHEMA = "zog-credential-authorization-v1"
AUTHORIZATION_ENVELOPE_SCHEMA = "zog-credential-authorization-envelope-v1"
REQUEST_SCHEMA = "zog-credential-request-v1"
DELIVERY_SCHEMA = "zog-credential-delivery-v1"
DELIVERY_ENVELOPE_SCHEMA = "zog-credential-delivery-envelope-v1"
RECEIPT_SCHEMA = "zog-credential-installation-receipt-v1"
CANCEL_SCHEMA = "zog-credential-cancel-v1"
LEDGER_SCHEMA = "zog-credential-delivery-ledger-v1"

REQUEST_LIFETIME = 120
DELIVERY_LIFETIME = 120
AUTHORIZATION_LIFETIME = 7 * 24 * 60 * 60
CLOCK_SKEW = 5
MAX_BODY = 65536
MAX_SECRET = 16384
MAX_REQUESTS = 128

_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


class CredentialProtocolError(ValueError):
    """Credential delivery contract violation."""


def canonical(value: object) -> bytes:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(raw) > MAX_BODY:
        raise CredentialProtocolError("message-too-large")
    return raw


def digest(value: object) -> str:
    """Digest non-secret protocol objects; never use for a delivery envelope."""
    return hashlib.sha256(canonical(value)).hexdigest()


def _uuid(value: object, code: str) -> str:
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CredentialProtocolError(code) from exc
    if parsed != value:
        raise CredentialProtocolError(code)
    return parsed


def _token(value: object, code: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise CredentialProtocolError(code)
    return value


def _fingerprint(value: object, code: str) -> str:
    if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
        raise CredentialProtocolError(code)
    return value


def _integer(value: object, code: str, *, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= 2**53 - 1:
        raise CredentialProtocolError(code)
    return value


def _window(created, expires, maximum, *, now=None, code):
    created = _integer(created, code)
    expires = _integer(expires, code)
    if not created < expires or expires - created > maximum:
        raise CredentialProtocolError(code)
    moment = time.time() if now is None else float(now)
    if created > moment + CLOCK_SKEW or expires <= moment - CLOCK_SKEW:
        raise CredentialProtocolError(code)
    return created, expires


_BINDING_FIELDS = (
    "host_id",
    "host_fingerprint",
    "installation_id",
    "state_volume_id",
    "registry_id",
    "consumer",
    "purpose",
    "credential_id",
)


def binding(value: dict) -> dict:
    """Return the exact reusable destination/credential binding."""
    if not isinstance(value, dict) or not set(_BINDING_FIELDS) <= set(value):
        raise CredentialProtocolError("invalid-binding")
    return {
        "host_id": _uuid(value["host_id"], "invalid-host-id"),
        "host_fingerprint": _fingerprint(
            value["host_fingerprint"], "invalid-host-fingerprint"
        ),
        "installation_id": _uuid(
            value["installation_id"], "invalid-installation-id"
        ),
        "state_volume_id": _uuid(
            value["state_volume_id"], "invalid-state-volume-id"
        ),
        "registry_id": _token(value["registry_id"], "invalid-registry-id"),
        "consumer": _token(value["consumer"], "invalid-consumer"),
        "purpose": _token(value["purpose"], "invalid-purpose"),
        "credential_id": _token(value["credential_id"], "invalid-credential-id"),
    }


def _matches_binding(left: dict, right: dict, code: str) -> None:
    if binding(left) != binding(right):
        raise CredentialProtocolError(code)


def _sign_bytes(kind: str, value: dict) -> bytes:
    return kind.encode("ascii") + b"\0" + canonical(value)


def _signed_envelope(schema: str, field: str, kind: str, value: dict, key):
    signature = key.sign(_sign_bytes(kind, value))
    return {
        "schema": schema,
        "key_id": signatures.fingerprint(key.public_key()),
        field: value,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def _verify_envelope(envelope, *, schema, field, kind, key):
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema", "key_id", field, "signature"}
        or envelope["schema"] != schema
        or envelope["key_id"] != signatures.fingerprint(key)
    ):
        raise CredentialProtocolError("invalid-signed-envelope")
    value = envelope[field]
    try:
        raw = base64.b64decode(envelope["signature"], validate=True)
    except (TypeError, ValueError) as exc:
        raise CredentialProtocolError("invalid-signature") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != envelope["signature"]:
        raise CredentialProtocolError("invalid-signature")
    try:
        key.verify(raw, _sign_bytes(kind, value))
    except InvalidSignature as exc:
        raise CredentialProtocolError("invalid-signature") from exc
    return value


def validate_authorization(
    value, *, expected_issuer: str, expected_binding: dict, now=None
):
    required = {
        "schema", "issuer", *_BINDING_FIELDS, "credential_revision",
        "authorization_id", "revision", "status", "approved_at",
        "revoked_at", "expires_at",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise CredentialProtocolError("invalid-authorization-schema")
    if value["schema"] != AUTHORIZATION_SCHEMA:
        raise CredentialProtocolError("unsupported-authorization-schema")
    if signatures.origin(value["issuer"]) != signatures.origin(expected_issuer):
        raise CredentialProtocolError("authorization-issuer-mismatch")
    _matches_binding(expected_binding, value, "authorization-binding-mismatch")
    _integer(value["credential_revision"], "invalid-credential-revision")
    _uuid(value["authorization_id"], "invalid-authorization-id")
    _integer(value["revision"], "invalid-authorization-revision")
    if value["status"] not in {"approved", "revoked"}:
        raise CredentialProtocolError("invalid-authorization-status")
    approved, expires = _window(
        value["approved_at"], value["expires_at"], AUTHORIZATION_LIFETIME,
        now=now, code="invalid-authorization-lifetime",
    )
    revoked = value["revoked_at"]
    if value["status"] == "approved":
        if revoked is not None:
            raise CredentialProtocolError("invalid-authorization-revocation")
    else:
        revoked = _integer(
            revoked, "invalid-authorization-revocation", minimum=approved
        )
        moment = time.time() if now is None else float(now)
        if revoked > moment + CLOCK_SKEW or revoked >= expires:
            raise CredentialProtocolError("invalid-authorization-revocation")
    return value


def sign_authorization(value: dict, key) -> dict:
    return _signed_envelope(
        AUTHORIZATION_ENVELOPE_SCHEMA, "authorization",
        AUTHORIZATION_SCHEMA, value, key,
    )


def verify_authorization(
    envelope, key, *, expected_issuer: str, expected_binding: dict, now=None
):
    value = _verify_envelope(
        envelope,
        schema=AUTHORIZATION_ENVELOPE_SCHEMA,
        field="authorization",
        kind=AUTHORIZATION_SCHEMA,
        key=key,
    )
    return validate_authorization(
        value,
        expected_issuer=expected_issuer,
        expected_binding=expected_binding,
        now=now,
    )


def validate_request(value, authorization: dict, *, now=None):
    required = {
        "schema", *_BINDING_FIELDS, "credential_revision",
        "authorization_id", "authorization_revision", "request_id",
        "action", "previous_delivery_id", "created_at", "expires_at",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise CredentialProtocolError("invalid-request-schema")
    if value["schema"] != REQUEST_SCHEMA:
        raise CredentialProtocolError("unsupported-request-schema")
    _matches_binding(authorization, value, "request-binding-mismatch")
    moment = time.time() if now is None else float(now)
    if authorization["status"] != "approved":
        raise CredentialProtocolError("authorization-revoked")
    if authorization["expires_at"] <= moment:
        raise CredentialProtocolError("authorization-expired")
    if value["credential_revision"] != authorization["credential_revision"]:
        raise CredentialProtocolError("credential-revision-mismatch")
    if value["authorization_id"] != authorization["authorization_id"]:
        raise CredentialProtocolError("authorization-id-mismatch")
    if value["authorization_revision"] != authorization["revision"]:
        raise CredentialProtocolError("authorization-revision-mismatch")
    _uuid(value["request_id"], "invalid-request-id")
    if value["action"] not in {"deliver", "renew"}:
        raise CredentialProtocolError("invalid-request-action")
    previous = value["previous_delivery_id"]
    if value["action"] == "deliver":
        if previous is not None:
            raise CredentialProtocolError("unexpected-previous-delivery")
    else:
        _uuid(previous, "invalid-previous-delivery-id")
    _window(
        value["created_at"], value["expires_at"], REQUEST_LIFETIME,
        now=now, code="invalid-request-lifetime",
    )
    return value


def prepare_request(url, value, authorization, key, *, now=None, nonce=None):
    validate_request(value, authorization, now=now)
    if signatures.fingerprint(key.public_key()) != value["host_fingerprint"]:
        raise CredentialProtocolError("request-key-mismatch")
    return signatures.sign(
        url, canonical(value), key, value["host_id"], now=now, nonce=nonce
    )


def verify_request_http(
    url, method, headers, body, host_key, authorization, *, now=None
):
    if len(body) > MAX_BODY:
        raise CredentialProtocolError("message-too-large")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise CredentialProtocolError("invalid-request-json") from exc
    validate_request(value, authorization, now=now)
    if signatures.fingerprint(host_key) != value["host_fingerprint"]:
        raise CredentialProtocolError("request-key-mismatch")
    nonce, nonce_expiry = signatures.verify(
        url, method, headers, body, host_key, value["host_id"]
    )
    return value, nonce, nonce_expiry


def validate_delivery(value, request: dict, authorization: dict, *, now=None):
    required = {
        "schema", "request_id", "delivery_id", "authorization_id",
        "authorization_revision", "credential_id", "credential_revision",
        "consumer", "purpose", "issued_at", "expires_at",
        "secret_format", "secret",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise CredentialProtocolError("invalid-delivery-schema")
    if value["schema"] != DELIVERY_SCHEMA:
        raise CredentialProtocolError("unsupported-delivery-schema")
    if request["request_id"] != value["request_id"]:
        raise CredentialProtocolError("delivery-request-mismatch")
    _uuid(value["request_id"], "invalid-request-id")
    _uuid(value["delivery_id"], "invalid-delivery-id")
    for field in (
        "authorization_id", "authorization_revision", "credential_id",
        "credential_revision", "consumer", "purpose",
    ):
        expected = authorization["revision"] if field == "authorization_revision" else authorization[field]
        if value[field] != expected:
            raise CredentialProtocolError("delivery-authorization-mismatch")
    _window(
        value["issued_at"], value["expires_at"], DELIVERY_LIFETIME,
        now=now, code="invalid-delivery-lifetime",
    )
    if value["secret_format"] != "base64":
        raise CredentialProtocolError("unsupported-secret-format")
    try:
        secret = base64.b64decode(value["secret"], validate=True)
    except (TypeError, ValueError) as exc:
        raise CredentialProtocolError("invalid-secret") from exc
    if (
        not 1 <= len(secret) <= MAX_SECRET
        or base64.b64encode(secret).decode("ascii") != value["secret"]
    ):
        raise CredentialProtocolError("invalid-secret")
    return value


def sign_delivery(value: dict, key) -> dict:
    return _signed_envelope(
        DELIVERY_ENVELOPE_SCHEMA, "delivery", DELIVERY_SCHEMA, value, key
    )


def verify_delivery(
    envelope, key, request: dict, authorization: dict, *, now=None
):
    value = _verify_envelope(
        envelope,
        schema=DELIVERY_ENVELOPE_SCHEMA,
        field="delivery",
        kind=DELIVERY_SCHEMA,
        key=key,
    )
    return validate_delivery(value, request, authorization, now=now)


def secret_bytes(delivery: dict) -> bytes:
    """Decode an already verified delivery; callers must not persist/log it."""
    return base64.b64decode(delivery["secret"], validate=True)


def validate_receipt(value, request: dict, delivery: dict, *, now=None):
    required = {
        "schema", *_BINDING_FIELDS, "credential_revision",
        "authorization_id", "authorization_revision", "request_id",
        "delivery_id", "receipt_id", "outcome", "installed_at",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise CredentialProtocolError("invalid-receipt-schema")
    if value["schema"] != RECEIPT_SCHEMA:
        raise CredentialProtocolError("unsupported-receipt-schema")
    _matches_binding(request, value, "receipt-binding-mismatch")
    for field in (
        "credential_revision", "authorization_id",
        "authorization_revision", "request_id",
    ):
        if value[field] != request[field]:
            raise CredentialProtocolError("receipt-request-mismatch")
    if value["delivery_id"] != delivery["delivery_id"]:
        raise CredentialProtocolError("receipt-delivery-mismatch")
    _uuid(value["receipt_id"], "invalid-receipt-id")
    if value["outcome"] != "installed":
        raise CredentialProtocolError("invalid-installation-outcome")
    installed = _integer(value["installed_at"], "invalid-installed-at")
    moment = time.time() if now is None else float(now)
    if (
        installed > moment + CLOCK_SKEW
        or installed < delivery["issued_at"]
        or installed > delivery["expires_at"] + CLOCK_SKEW
    ):
        raise CredentialProtocolError("invalid-installed-at")
    return value


def validate_cancel(value, request: dict, *, now=None):
    required = {
        "schema", *_BINDING_FIELDS, "credential_revision",
        "authorization_id", "authorization_revision", "request_id",
        "cancel_id", "reason", "created_at", "expires_at",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise CredentialProtocolError("invalid-cancel-schema")
    if value["schema"] != CANCEL_SCHEMA:
        raise CredentialProtocolError("unsupported-cancel-schema")
    _matches_binding(request, value, "cancel-binding-mismatch")
    for field in (
        "credential_revision", "authorization_id",
        "authorization_revision", "request_id",
    ):
        if value[field] != request[field]:
            raise CredentialProtocolError("cancel-request-mismatch")
    _uuid(value["cancel_id"], "invalid-cancel-id")
    if value["reason"] not in {
        "operator-request", "installation-failed",
        "interruption-recovery", "superseded",
    }:
        raise CredentialProtocolError("invalid-cancel-reason")
    _window(
        value["created_at"], value["expires_at"], REQUEST_LIFETIME,
        now=now, code="invalid-cancel-lifetime",
    )
    return value


def _prepare_host_message(url, value, validator, key, *, now=None, nonce=None):
    validator(value)
    if signatures.fingerprint(key.public_key()) != value["host_fingerprint"]:
        raise CredentialProtocolError("request-key-mismatch")
    return signatures.sign(
        url, canonical(value), key, value["host_id"], now=now, nonce=nonce
    )


def _verify_host_message(url, method, headers, body, host_key, validator):
    if len(body) > MAX_BODY:
        raise CredentialProtocolError("message-too-large")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise CredentialProtocolError("invalid-host-message-json") from exc
    validator(value)
    if signatures.fingerprint(host_key) != value["host_fingerprint"]:
        raise CredentialProtocolError("request-key-mismatch")
    nonce, nonce_expiry = signatures.verify(
        url, method, headers, body, host_key, value["host_id"]
    )
    return value, nonce, nonce_expiry


def prepare_receipt(
    url, value, request, delivery, key, *, now=None, nonce=None
):
    return _prepare_host_message(
        url, value,
        lambda item: validate_receipt(item, request, delivery, now=now),
        key, now=now, nonce=nonce,
    )


def verify_receipt_http(
    url, method, headers, body, host_key, request, delivery, *, now=None
):
    return _verify_host_message(
        url, method, headers, body, host_key,
        lambda item: validate_receipt(item, request, delivery, now=now),
    )


def prepare_cancel(url, value, request, key, *, now=None, nonce=None):
    return _prepare_host_message(
        url, value,
        lambda item: validate_cancel(item, request, now=now),
        key, now=now, nonce=nonce,
    )


def verify_cancel_http(
    url, method, headers, body, host_key, request, *, now=None
):
    return _verify_host_message(
        url, method, headers, body, host_key,
        lambda item: validate_cancel(item, request, now=now),
    )


def new_ledger(authorization: dict) -> dict:
    if authorization["status"] not in {"approved", "revoked"}:
        raise CredentialProtocolError("invalid-authorization-status")
    return {
        "schema": LEDGER_SCHEMA,
        **binding(authorization),
        "authorization_id": authorization["authorization_id"],
        "authorization_revision": authorization["revision"],
        "authorization_status": authorization["status"],
        "credential_revision": authorization["credential_revision"],
        "rotation_required": False,
        "requests": [],
    }


def validate_ledger(value):
    required = {
        "schema", *_BINDING_FIELDS, "authorization_id",
        "authorization_revision", "authorization_status",
        "credential_revision", "rotation_required", "requests",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise CredentialProtocolError("invalid-ledger-schema")
    if value["schema"] != LEDGER_SCHEMA:
        raise CredentialProtocolError("unsupported-ledger-schema")
    binding(value)
    _uuid(value["authorization_id"], "invalid-authorization-id")
    _integer(value["authorization_revision"], "invalid-authorization-revision")
    _integer(value["credential_revision"], "invalid-credential-revision")
    if value["authorization_status"] not in {"approved", "revoked"}:
        raise CredentialProtocolError("invalid-authorization-status")
    if type(value["rotation_required"]) is not bool:
        raise CredentialProtocolError("invalid-rotation-state")
    rows = value["requests"]
    if not isinstance(rows, list) or len(rows) > MAX_REQUESTS:
        raise CredentialProtocolError("invalid-request-history")
    seen_requests, seen_deliveries, seen_receipts, seen_cancels = set(), set(), set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "request_id", "action", "credential_revision",
            "authorization_revision", "status", "previous_delivery_id",
            "delivery_id", "receipt_id", "cancel_id",
        }:
            raise CredentialProtocolError("invalid-request-history")
        request_id = _uuid(row["request_id"], "invalid-request-history")
        if request_id in seen_requests:
            raise CredentialProtocolError("duplicate-request-id")
        seen_requests.add(request_id)
        if row["action"] not in {"deliver", "renew"}:
            raise CredentialProtocolError("invalid-request-history")
        _integer(row["credential_revision"], "invalid-request-history")
        _integer(row["authorization_revision"], "invalid-request-history")
        if row["status"] not in {
            "pending", "delivered", "installed",
            "cancelled", "cancelled-after-delivery",
        }:
            raise CredentialProtocolError("invalid-request-history")
        for field, seen in (
            ("delivery_id", seen_deliveries),
            ("receipt_id", seen_receipts),
            ("cancel_id", seen_cancels),
        ):
            item = row[field]
            if item is not None:
                _uuid(item, "invalid-request-history")
                if item in seen:
                    raise CredentialProtocolError("duplicate-operation-id")
                seen.add(item)
        previous = row["previous_delivery_id"]
        if previous is not None:
            _uuid(previous, "invalid-request-history")
    return value


def advance_authorization(state: dict, authorization: dict) -> dict:
    validate_ledger(state)
    _matches_binding(state, authorization, "authorization-binding-mismatch")
    if authorization["authorization_id"] != state["authorization_id"]:
        raise CredentialProtocolError("authorization-id-changed")
    revision = authorization["revision"]
    if revision < state["authorization_revision"]:
        raise CredentialProtocolError("authorization-rollback")
    if revision == state["authorization_revision"]:
        if (
            authorization["status"] != state["authorization_status"]
            or authorization["credential_revision"] != state["credential_revision"]
        ):
            raise CredentialProtocolError("authorization-revision-conflict")
        return copy.deepcopy(state)
    if state["authorization_status"] == "revoked" and authorization["status"] != "revoked":
        raise CredentialProtocolError("revocation-reversal")
    if authorization["credential_revision"] < state["credential_revision"]:
        raise CredentialProtocolError("credential-revision-rollback")
    result = copy.deepcopy(state)
    result["authorization_revision"] = revision
    result["authorization_status"] = authorization["status"]
    result["credential_revision"] = authorization["credential_revision"]
    if authorization["credential_revision"] > state["credential_revision"]:
        result["rotation_required"] = False
    return result


def _latest_installed(state):
    for row in reversed(state["requests"]):
        if row["status"] == "installed":
            return row
    return None


def admit_request(state: dict, request: dict) -> dict:
    validate_ledger(state)
    if state["authorization_status"] != "approved":
        raise CredentialProtocolError("authorization-revoked")
    _matches_binding(state, request, "request-binding-mismatch")
    if request["authorization_id"] != state["authorization_id"]:
        raise CredentialProtocolError("authorization-id-mismatch")
    if request["authorization_revision"] != state["authorization_revision"]:
        raise CredentialProtocolError("authorization-revision-mismatch")
    if request["credential_revision"] != state["credential_revision"]:
        raise CredentialProtocolError("credential-revision-mismatch")
    for row in state["requests"]:
        if row["request_id"] == request["request_id"]:
            expected = {
                "request_id": request["request_id"],
                "action": request["action"],
                "credential_revision": request["credential_revision"],
                "authorization_revision": request["authorization_revision"],
                "previous_delivery_id": request["previous_delivery_id"],
            }
            if any(row[key] != expected[key] for key in expected):
                raise CredentialProtocolError("request-id-conflict")
            return copy.deepcopy(state)
    if any(row["status"] in {"pending", "delivered"} for row in state["requests"]):
        raise CredentialProtocolError("request-in-progress")
    if len(state["requests"]) >= MAX_REQUESTS:
        raise CredentialProtocolError("request-history-full")
    latest = _latest_installed(state)
    if request["action"] == "deliver":
        if latest is not None or state["rotation_required"]:
            raise CredentialProtocolError("renewal-required")
    else:
        if latest is None or request["previous_delivery_id"] != latest["delivery_id"]:
            raise CredentialProtocolError("previous-delivery-mismatch")
        if request["credential_revision"] <= latest["credential_revision"]:
            raise CredentialProtocolError("rotation-revision-required")
    result = copy.deepcopy(state)
    result["requests"].append({
        "request_id": request["request_id"],
        "action": request["action"],
        "credential_revision": request["credential_revision"],
        "authorization_revision": request["authorization_revision"],
        "status": "pending",
        "previous_delivery_id": request["previous_delivery_id"],
        "delivery_id": None,
        "receipt_id": None,
        "cancel_id": None,
    })
    return result


def record_delivery(state: dict, delivery: dict) -> dict:
    validate_ledger(state)
    result = copy.deepcopy(state)
    for row in result["requests"]:
        if row["request_id"] != delivery["request_id"]:
            continue
        if row["status"] == "delivered" and row["delivery_id"] == delivery["delivery_id"]:
            return result
        if row["status"] != "pending":
            raise CredentialProtocolError("delivery-after-terminal-request")
        if (
            delivery["credential_revision"] != row["credential_revision"]
            or delivery["authorization_revision"] != row["authorization_revision"]
        ):
            raise CredentialProtocolError("delivery-revision-mismatch")
        _uuid(delivery["delivery_id"], "invalid-delivery-id")
        if any(
            other["delivery_id"] == delivery["delivery_id"]
            for other in result["requests"] if other is not row
        ):
            raise CredentialProtocolError("delivery-id-replayed")
        row["status"] = "delivered"
        row["delivery_id"] = delivery["delivery_id"]
        return result
    raise CredentialProtocolError("unknown-request-id")


def record_installation(state: dict, receipt: dict) -> dict:
    validate_ledger(state)
    if state["authorization_status"] != "approved":
        raise CredentialProtocolError("authorization-revoked")
    result = copy.deepcopy(state)
    for row in result["requests"]:
        if row["request_id"] != receipt["request_id"]:
            continue
        if row["status"] == "installed" and row["receipt_id"] == receipt["receipt_id"]:
            return result
        if row["authorization_revision"] != result["authorization_revision"]:
            raise CredentialProtocolError("authorization-superseded")
        if row["status"] != "delivered" or row["delivery_id"] != receipt["delivery_id"]:
            raise CredentialProtocolError("installation-before-delivery")
        _uuid(receipt["receipt_id"], "invalid-receipt-id")
        if any(
            other["receipt_id"] == receipt["receipt_id"]
            for other in result["requests"] if other is not row
        ):
            raise CredentialProtocolError("receipt-id-replayed")
        row["status"] = "installed"
        row["receipt_id"] = receipt["receipt_id"]
        result["rotation_required"] = False
        return result
    raise CredentialProtocolError("unknown-request-id")


def record_cancel(state: dict, cancel: dict) -> dict:
    validate_ledger(state)
    result = copy.deepcopy(state)
    for row in result["requests"]:
        if row["request_id"] != cancel["request_id"]:
            continue
        if row["cancel_id"] == cancel["cancel_id"] and row["status"] in {
            "cancelled", "cancelled-after-delivery",
        }:
            return result
        _uuid(cancel["cancel_id"], "invalid-cancel-id")
        if any(
            other["cancel_id"] == cancel["cancel_id"]
            for other in result["requests"] if other is not row
        ):
            raise CredentialProtocolError("cancel-id-replayed")
        if row["status"] == "pending":
            row["status"] = "cancelled"
        elif row["status"] == "delivered":
            row["status"] = "cancelled-after-delivery"
            result["rotation_required"] = True
        else:
            raise CredentialProtocolError("cancel-after-terminal-request")
        row["cancel_id"] = cancel["cancel_id"]
        return result
    raise CredentialProtocolError("unknown-request-id")
