"""Archive-specific adapter for Zog HTTPS credential delivery v1.

Short-lived archive access JWTs remain on the existing host-response path.
Only durable upstream-provider credentials use the common HTTPS delivery
protocol, and their common credential identity is derived from an exact
nonsecret archive scope.
"""
from copy import deepcopy
import hashlib
import re
from urllib.parse import urlsplit

from . import credential_delivery

SCHEMA = "zog-archive-credential-inventory-v1"
PROVIDER_SCOPE_SCHEMA = "zog-archive-provider-credential-scope-v1"
PROVIDER_CONSUMER = "archive-mirror"
PROVIDER_PURPOSE = "archive-mirror-provider"
PROVIDER_ROLE = "upstream-source-provider"
PROVIDER_OPERATION = "fetch"

_COLLECTION = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")

_CLASSES = {
    "consumer-access-token": {
        "secret": True,
        "owner": "host-identify/archive-authority",
        "lifetime": "short-lived",
        "transport": "authenticated-host-response",
        "https_delivery_purpose": None,
        "install": "ephemeral-consumer-cache",
        "notes": "Existing scoped JWT; issuer/audience/operation/collection/expiry remain authoritative.",
    },
    "token-issuer-signing-key": {
        "secret": True,
        "owner": "archive-token-authority",
        "lifetime": "durable",
        "transport": "never-distribute-to-mirror",
        "https_delivery_purpose": None,
        "install": "authority-private-only",
        "notes": "A mirror receives only public verification keys.",
    },
    "verification-keyring": {
        "secret": False,
        "owner": "archive-mirror-operator",
        "lifetime": "rotatable-public-data",
        "transport": "reviewed-public-configuration",
        "https_delivery_purpose": None,
        "install": "application-owned-public-file",
        "notes": "Ed25519 public keys only.",
    },
    "upstream-collection-credential": {
        "secret": True,
        "owner": "archive-credential-authority",
        "lifetime": "durable",
        "transport": "zog-https-credential-delivery-v1",
        "https_delivery_purpose": PROVIDER_PURPOSE,
        "install": "archive-mirror-private-provider-store",
        "notes": "Purpose-scoped provider credential; never an archive consumer access grant.",
    },
    "provider-service-credential": {
        "secret": True,
        "owner": "archive-credential-authority",
        "lifetime": "durable",
        "transport": "zog-https-credential-delivery-v1",
        "https_delivery_purpose": PROVIDER_PURPOSE,
        "install": "archive-mirror-private-provider-store",
        "notes": "Same reviewed upstream-provider profile; provider secret is opaque to the common protocol.",
    },
    "tls-private-key": {
        "secret": True,
        "owner": "certificate-termination-owner",
        "lifetime": "certificate-lifecycle",
        "transport": "outside-archive-mirror",
        "https_delivery_purpose": None,
        "install": "certify-manage/nginx-owned",
        "notes": "TLS termination credentials are not archive-mirror credentials.",
    },
}

class ArchiveCredentialPolicyError(ValueError):
    pass


def _deny(code):
    raise ArchiveCredentialPolicyError(code) from None


def _positive(value, code):
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        _deny(code)
    return value


def _token(value, code):
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        _deny(code)
    return value


def _origin(value):
    if not isinstance(value, str):
        _deny("invalid-provider-origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        _deny("invalid-provider-origin")
    host = parsed.hostname.lower()
    port = "" if parsed.port in (None, 443) else f":{parsed.port}"
    return f"https://{host}{port}"


def _collections(values):
    if (
        not isinstance(values, list) or not 1 <= len(values) <= 32
        or values != sorted(set(values))
        or any(not isinstance(value, str) or not _COLLECTION.fullmatch(value)
               for value in values)
    ):
        _deny("invalid-provider-collections")
    return list(values)


def _operations(values):
    if values != [PROVIDER_OPERATION]:
        _deny("invalid-provider-operations")
    return list(values)


_PROVIDER_FIELDS = frozenset({
    "schema", "host_id", "host_fingerprint", "installation_id",
    "state_volume_id", "registry_id", "provider_id", "provider_origin",
    "provider_role", "role_revision", "collections", "operations",
    "provider_credential_id", "credential_revision",
})


def provider_scope(value):
    """Validate and normalize one nonsecret upstream-provider credential scope."""
    if not isinstance(value, dict) or set(value) != _PROVIDER_FIELDS:
        _deny("invalid-provider-scope")
    if value["schema"] != PROVIDER_SCOPE_SCHEMA:
        _deny("unsupported-provider-scope")
    # Reuse the canonical binding validators for Host/installation/STATE/registry.
    base = credential_delivery.binding({
        "host_id": value["host_id"],
        "host_fingerprint": value["host_fingerprint"],
        "installation_id": value["installation_id"],
        "state_volume_id": value["state_volume_id"],
        "registry_id": value["registry_id"],
        "consumer": PROVIDER_CONSUMER,
        "purpose": PROVIDER_PURPOSE,
        "credential_id": "placeholder",
    })
    provider_id = _token(value["provider_id"], "invalid-provider-id")
    credential = _token(
        value["provider_credential_id"], "invalid-provider-credential-id"
    )
    if value["provider_role"] != PROVIDER_ROLE:
        _deny("invalid-provider-role")
    role_revision = _positive(value["role_revision"], "invalid-role-revision")
    revision = _positive(
        value["credential_revision"], "invalid-credential-revision"
    )
    normalized = {
        "schema": PROVIDER_SCOPE_SCHEMA,
        "host_id": base["host_id"],
        "host_fingerprint": base["host_fingerprint"],
        "installation_id": base["installation_id"],
        "state_volume_id": base["state_volume_id"],
        "registry_id": base["registry_id"],
        "provider_id": provider_id,
        "provider_origin": _origin(value["provider_origin"]),
        "provider_role": PROVIDER_ROLE,
        "role_revision": role_revision,
        "collections": _collections(value["collections"]),
        "operations": _operations(value["operations"]),
        "provider_credential_id": credential,
        "credential_revision": revision,
    }
    scope = {
        key: normalized[key] for key in (
            "provider_id", "provider_origin", "provider_role", "role_revision",
            "collections", "operations", "provider_credential_id",
        )
    }
    scope_id = hashlib.sha256(
        credential_delivery.canonical(scope)
    ).hexdigest()
    return {
        **normalized,
        "scope_id": scope_id,
        "consumer": PROVIDER_CONSUMER,
        "purpose": PROVIDER_PURPOSE,
        # 128 bits of the scope digest keeps the token bounded while binding
        # provider/origin/role/collections/operation/underlying credential ID.
        "credential_id": "archive-provider-" + scope_id[:32],
    }


def provider_binding(value):
    scope = provider_scope(value)
    return credential_delivery.binding(scope)


def verify_provider_authorization(
    envelope, authority_key, *, expected_issuer, scope, now=None
):
    selected = provider_scope(scope)
    authorization = credential_delivery.verify_authorization(
        envelope, authority_key,
        expected_issuer=expected_issuer,
        expected_binding=provider_binding(scope),
        now=now,
    )
    if authorization["credential_revision"] != selected["credential_revision"]:
        _deny("provider-credential-revision-mismatch")
    return authorization


def request(
    scope, authorization, *, request_id, action,
    previous_delivery_id, created_at, expires_at,
):
    """Build one exact common-protocol request for the selected provider scope."""
    selected = provider_scope(scope)
    binding = provider_binding(scope)
    if credential_delivery.binding(authorization) != binding:
        _deny("provider-authorization-binding-mismatch")
    if authorization["credential_revision"] != selected["credential_revision"]:
        _deny("provider-credential-revision-mismatch")
    value = {
        "schema": credential_delivery.REQUEST_SCHEMA,
        **binding,
        "credential_revision": selected["credential_revision"],
        "authorization_id": authorization["authorization_id"],
        "authorization_revision": authorization["revision"],
        "request_id": request_id,
        "action": action,
        "previous_delivery_id": previous_delivery_id,
        "created_at": created_at,
        "expires_at": expires_at,
    }
    return credential_delivery.validate_request(value, authorization, now=created_at)


def validate_delivery(scope, authorization, request_value, delivery, *, now=None):
    selected = provider_scope(scope)
    if credential_delivery.binding(authorization) != provider_binding(scope):
        _deny("provider-authorization-binding-mismatch")
    if authorization["credential_revision"] != selected["credential_revision"]:
        _deny("provider-credential-revision-mismatch")
    return credential_delivery.validate_delivery(
        delivery, request_value, authorization, now=now
    )


def inventory():
    """Return bounded policy metadata; never secret values."""
    return {"schema": SCHEMA, "classes": deepcopy(_CLASSES)}


def https_delivery_profile(kind):
    entry = _CLASSES.get(kind)
    if entry is None:
        raise ArchiveCredentialPolicyError("unknown archive credential class")
    purpose = entry["https_delivery_purpose"]
    if purpose is None:
        raise ArchiveCredentialPolicyError(
            "archive credential class has no approved HTTPS delivery purpose"
        )
    return {
        "purpose": purpose,
        "consumer": PROVIDER_CONSUMER,
        "scope_schema": PROVIDER_SCOPE_SCHEMA,
        "provider_role": PROVIDER_ROLE,
        "operations": [PROVIDER_OPERATION],
    }


def enabled_https_purposes():
    return tuple(sorted({
        entry["https_delivery_purpose"]
        for entry in _CLASSES.values()
        if entry["https_delivery_purpose"] is not None
    }))
