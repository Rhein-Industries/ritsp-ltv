# Validation profiles and compatibility

## Upgrading from 0.5 to 0.6

Update the dependency to `ritsp-ltv = "0.6"` and refresh the consumer lockfile.
Applications that also depend on riptering must select its 0.7 release line:
ritsp-ltv re-exports riptering types, and types from the older release line are
distinct. The MSRV remains Rust 1.88 and provider features keep their names.

Review timestamp inputs for the required ESS certificate binding and supported
TSA certificate/name profile. For delegated OCSP responses, migrate issuer-only
validation to the path-aware APIs described below and provide the complete
issuer path and trust store. Strict nonce echo checking is optional; the default
remains opportunistic. Unsupported profiles and malformed extensions now fail
closed, so successful validation under the previous release does not guarantee
acceptance after upgrading. No option bypasses the timestamp certificate binding.

## Supported validation profiles

Timestamp verification requires a signed ESS `SigningCertificate` (SHA-1
certificate identification) or `SigningCertificateV2` (SHA-256 by default,
or supported SHA-2/SHA-3 algorithm). Both attributes are independently
validated when present. The complete DER certificate hash and optional
issuer directoryName/serial must identify the certificate selected by CMS
SignerIdentifier. Multiple instances or values, unsigned ESS attributes,
unsupported algorithms/parameters, and a missing binding are rejected.

This verifier supports one certificate identifier per ESS attribute. Additional
identifiers impose certification-path restrictions; ESS policies impose a
profile that this library does not fully implement. Those forms are rejected
instead of silently ignoring their requirements. Applications using these
profiles need a verifier with complete ESS path/policy support. No compatibility
escape hatch disables certificate binding.

The TSA must have an exclusive critical `id-kp-timeStamping` EKU. If KeyUsage
is present, it must also permit `digitalSignature` or `nonRepudiation`,
regardless of that extension's critical flag. This applies to TSP-only builds
and purpose-aware chain validation. CA KeyUsage remains optional; a present
CA KeyUsage must permit certificate signing. Critical CA EKUs are unsupported
ancestor purpose restrictions and fail closed, including on trust anchors.
The verifier does not claim full PKIX policy or ancestor EKU processing.

An optional authenticated `TSTInfo.tsa` must match the signer's subject
directoryName or a subjectAltName of the same type. DNS names compare without
ASCII case sensitivity. Other supported GeneralName values compare exactly as
typed DER values; there is no wildcard expansion, hostname interpretation,
or broad directory-string normalization. Unsupported `x400Address` and
malformed names fail verification. Parsing-only `extract_tst_info` remains
unauthenticated and can structurally inspect unsupported names.

Canonical UTC GeneralizedTime accepts arbitrary fractional-second precision,
preserves the original bytes, and rejects fractional trailing zeros/comma/time
zones. PKIX certificates have second-resolution bounds; a positive fraction
at `notAfter` is outside the validity interval. Default timestamp chain
validation enforces this boundary for the signer, intermediates, and anchor.
An explicit caller-supplied validation time retains its existing semantics.

Delegated OCSP signer validation needs the complete issuer path so constraints
from every CA and the anchor apply to the responder. Issuer-only OCSP helpers
and the default async orchestrator now reject delegated responses, including
responders with `id-pkix-ocsp-nocheck`. That extension removes only the separate
responder revocation check, never the path, purpose, or name-constraint checks.
Direct-issuer responses retain the existing subject-and-SPKI binding. When an
embedded same-key reissue verifies, validation uses the exact caller-supplied
issuer certificate's validity and profile, rather than embedded metadata.

For offline OCSP, use `check_revocation_detailed_with_issuer_path` with
`issuer_chain[0]` equal to the exact CertID issuer and a trust store. A returned
`delegated_responder` still requires its own revocation check. For online
validation use `check_certificate_revocation_with_ocsp_context`; it completes
that check with the existing recursion, freshness, timeout and strictness
policies. The optional `OcspValidationContext.issuer_path` supplies the path
and trust store without changing existing `RevocationConfig` struct literals.

Default OCSP nonce handling remains opportunistic: an echoed nonce must match,
but a responder may omit it, subject to response freshness. Set
`OcspValidationContext.require_nonce = true` for online strict echo checking;
`RevocationConfig.use_ocsp_nonce` must also be true. Offline helpers expose the
same `require_nonce` option. Strict mode rejects missing request/response
nonces and mismatches. Pre-produced/non-nonce responders may stop working with
that option; see RFC 5019 section 2.2 and RFC 6960 section 4.4.1.

OCSP response and single-response extensions require complete DER parsing.
Duplicate OIDs, malformed extensions, and unsupported critical extensions
reject. Unknown noncritical extensions remain ignored. Nonces are supported
only in response extensions; a nonce in single-response extensions rejects.
The existing raw/DER-wrapped nonce compatibility is retained, with complete
consumption required before treating a value as wrapped.

External same-key trust-anchor reissues are evaluated as separate candidates
against the supplied ordered chain. A candidate's profile, time, path-length
or name-constraint failure does not prevent another configured external anchor
from succeeding. This is not exhaustive certification-path construction or
alternate intermediate-chain search. `prefer_ocsp` controls
equal-priority merge ties only; either source's revocation result still wins.

These changes preserve existing function signatures and configuration literals,
but intentionally narrow acceptance of incomplete or unsupported security
profiles. They do not establish full PKIX policy processing, TSA key-compromise
archival policy, FIPS deployment compliance, or hardware validation.

Normative references: [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html),
[RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html),
[RFC 5035](https://www.rfc-editor.org/rfc/rfc5035.html),
[RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html),
[RFC 5019](https://www.rfc-editor.org/rfc/rfc5019.html), and
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html).
