"""Archive credential classes and delivery-policy boundary.

The common Zog HTTPS credential-delivery framework is the only permitted
cross-host durable-secret transport. Archive v1 currently has no durable
archive-owned secret that needs that transport, so no HTTPS purpose is enabled.
"""
from copy import deepcopy

SCHEMA = "zog-archive-credential-inventory-v1"

# Machine-readable, secret-free policy metadata. Never put credential bytes here.
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
        "owner": "not-configured",
        "lifetime": "not-applicable",
        "transport": "unsupported",
        "https_delivery_purpose": None,
        "install": "unsupported",
        "notes": "Current Git and reviewed-source acquisition require credential-free HTTPS URLs.",
    },
    "provider-service-credential": {
        "secret": True,
        "owner": "not-configured",
        "lifetime": "not-applicable",
        "transport": "unsupported",
        "https_delivery_purpose": None,
        "install": "unsupported",
        "notes": "Archive serving has no shared service password.",
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


def inventory():
    """Return bounded policy metadata; never secret values."""
    return {"schema": SCHEMA, "classes": deepcopy(_CLASSES)}


def https_delivery_profile(kind):
    """Return a future common-HTTPS profile only when explicitly reviewed.

    No archive purpose is enabled in v1. Callers must not reinterpret another
    component's purpose (for example issuer-cloudflare-dns01) for archive use.
    """
    entry = _CLASSES.get(kind)
    if entry is None:
        raise ArchiveCredentialPolicyError("unknown archive credential class")
    purpose = entry["https_delivery_purpose"]
    if purpose is None:
        raise ArchiveCredentialPolicyError(
            "archive credential class has no approved HTTPS delivery purpose"
        )
    return {"purpose": purpose, "consumer": "archive-mirror"}


def enabled_https_purposes():
    return tuple(sorted(
        entry["https_delivery_purpose"]
        for entry in _CLASSES.values()
        if entry["https_delivery_purpose"] is not None
    ))
