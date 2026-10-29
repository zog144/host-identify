# Unified HTTPS credential delivery v1

**Status:** source contract only; no network listener, secret transfer, or production activation.  
**Transport direction:** approved Option B — authenticated HTTPS on port 443.  
**Shared protocol owner:** host-identify.  
**Credential Authority / authorization owner:** station-access or another explicitly reviewed authority.  
**Protected receiving/install owner:** host-install/root-controlled component.  
**Host-discover:** identity/enrollment integration only; ordinary beacon/service accounts do not receive root-owned secrets.

This protocol is separate from the managed-session `inspect` profile. A signed
beacon, enrollment, current managed session, or successful inspection proves
none of the authorization required for secret delivery.

## Three independent proofs

Credential delivery has three distinct decisions:

1. **Caller authentication.** The receiving Host uses its existing Ed25519
   HostIdentity to sign the HTTPS request with the existing RFC 9421 helper.
   The authority must durably reject replayed HTTP signature nonces.
2. **Secret authorization.** A separately trusted Credential Authority signs a
   versioned authorization binding the exact Host, HostIdentity fingerprint,
   installation, STATE volume, registry, approved consumer, purpose,
   credential ID/revision, authorization ID/revision, approval, expiry and
   revocation state.
3. **Installation success.** Delivery of secret bytes is not success. The
   receiving root owner must install into the approved protected destination,
   then return a HostIdentity-signed, secret-free installation receipt.

The Credential Authority key is independently pinned. It must not be inferred
from a signed beacon, a browser session, DNS, a credential response itself, or
an inspect-only managed session.

## Binding

All authorization and request state binds:

```text
host_id
host_fingerprint
installation_id
state_volume_id
registry_id
consumer
purpose
credential_id
credential_revision
authorization_id
authorization_revision
fresh request_id
```

A purpose is narrow, such as `issuer-cloudflare-dns01` or a reviewed
administrator-bootstrap purpose. One purpose cannot be reused for another
consumer or credential class.

## HTTPS messages

The common module is `zog.host_identify.credential_delivery`.

### Authorization

`zog-credential-authorization-v1` is signed in a
`zog-credential-authorization-envelope-v1`.

It includes the exact binding, Credential Authority HTTPS origin, positive
credential revision, immutable authorization UUID, monotonic authorization
revision, `approved|revoked`, approval/revocation time and bounded expiry.

Authorization lifetime is at most seven days in v1. Higher revisions may
rotate a credential revision or revoke authority. Lower revisions,
same-revision conflicts, credential-revision rollback and revocation reversal
are rejected by the durable ledger.

### Request

`zog-credential-request-v1` is a HostIdentity-signed HTTPS POST body. It is
valid for at most 120 seconds. Actions are:

- `deliver`: first approved delivery; no previous delivery ID.
- `renew`: requires a newer credential revision and the exact previously
  installed delivery ID.

The authority must validate the authorization first, verify the exact host
signature/fingerprint and persist both the HTTP nonce and request admission
before producing secret bytes.

### Delivery

`zog-credential-delivery-v1` is returned in a Credential-Authority-signed
`zog-credential-delivery-envelope-v1`. It is correlated to one request,
authorization revision, purpose, consumer and credential revision. Secret bytes
are base64 only for JSON transport and are bounded to 16 KiB. Delivery lifetime
is at most 120 seconds.

The common durable ledger **never stores secret bytes or a reusable secret
digest**. The receiver must avoid logs, diagnostics, exception text, crash
dumps and application-readable temporary files containing the secret.

### Installation receipt

`zog-credential-installation-receipt-v1` is HostIdentity-signed and
secret-free. It binds the request and delivery IDs and reports only
`outcome=installed` after the root-owned installer has durably committed the
credential to its approved destination and enforced ownership/mode.

A delivery without this receipt remains uncertain and cannot authorize a new
delivery.

### Cancellation

`zog-credential-cancel-v1` is HostIdentity-signed, fresh and secret-free.
Cancellation before delivery safely terminates the request. Cancellation after
delivery marks the secret as exposed but not installed and sets
`rotation_required=true`; the same credential revision must not be delivered
again.

Interruption recovery must inspect the durable request/delivery ledger first.
It must never guess whether an uncertain delivery occurred.

## Durable anti-replay state

`zog-credential-delivery-ledger-v1` contains only non-secret identifiers,
revisions and states. It retains up to 128 request operations and rejects:

- duplicate request IDs with changed action/scope/revision;
- duplicate delivery, receipt or cancellation IDs;
- a second request while one is pending or delivered-but-unresolved;
- stale authorization or credential revisions;
- renewals not bound to the exact last installed delivery;
- installation after authorization revocation/supersession;
- redelivery after an uncertain delivered secret until rotation.

HTTP signature nonce replay protection is a separate durable authority ledger
and remains mandatory.

## Expiry and revocation

Expiry is checked independently at authorization, request and delivery stages.
A credential delivered before authorization revocation must not be installed
after a higher-revision revocation has been accepted.

Revocation does not erase audit history. The protected receiving owner decides
how to disable/delete an already installed secret, revoke dependent sessions
and request a later approved rotation.

## Ownership boundaries

### host-identify

Owns canonical schemas, signature helpers, validation and the pure secret-free
state machine. It does not open sockets or persist delivered secrets.

### station-access / Credential Authority

Owns operator approval, exact purpose/account selection, Credential Authority
private key, authorization/revocation history, HTTP nonce replay ledger,
credential source/vault and server-side request/delivery state. Browser
administrator authentication is separate from machine credential authority.

### host-install / protected receiver

Owns the root-only HTTPS client or delegated root helper, independent authority
pin, destination admission, protected temporary handling, durable installation,
rotation/removal and secret-free installation/cancellation receipts.

### host-discover

May provide enrolled HostIdentity/binding evidence and source-level integration,
but its ordinary UID-970 daemon and managed `inspect` session are **not**
credential receivers. Secrets must never be placed in beacon bodies, heartbeat
responses, managed journals, certificate-assignment files or ordinary
host-discover application state.

### archive-mirror

Current archive credentials remain as documented in
[ARCHIVE-CREDENTIALS.md](ARCHIVE-CREDENTIALS.md). No durable archive HTTPS
purpose is enabled by this protocol.

## Negative-test contract

`tests/test_credential_delivery.py` covers:

- wrong authority key/purpose/destination binding;
- HostIdentity mismatch and HTTP signature verification;
- revoked/expired authorization;
- secret tampering and size bounds;
- delivery without installation receipt;
- duplicate/changed request identity;
- unresolved delivery blocking redelivery;
- signed secret-free receipt/cancellation;
- cancellation after delivery forcing rotation;
- exact previous-delivery renewal binding;
- revocation between delivery and installation;
- authorization rollback/conflict/revocation reversal.

## Handoff

**station-access Regular:** implement only the authority/server side after a
purpose profile is explicitly approved. Persist authorization, request,
HTTP-nonce and delivery state before returning bytes. Do not infer authorization
from enrollment or browser login.

**host-install Regular:** define the root-owned authority pin, protected HTTPS
receiver, destination policy, durable secret installation and restart/recovery
ledger. No ordinary host-discover UID should gain read access.

**host-discover Regular:** keep credential delivery outside heartbeat and
inspect-only managed sessions; expose only non-secret exact Host/installation/
STATE/registry binding evidence needed by the protected receiver.

Live HTTPS activation, real credential bytes and provider/service changes are
out of scope for this source pass.
