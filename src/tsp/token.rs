//! TimeStampReq/Resp ASN.1 parsing and validation per RFC 3161.
//!
//! This module handles:
//! - Building `TimeStampReq` messages
//! - Parsing `TimeStampResp` responses
//! - Extracting and validating `TSTInfo` from the embedded `TimeStampToken`
//! - Nonce generation and verification

use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::crypto::algorithm::DigestAlgorithm;
use crate::der_utils;
use crate::error::{TrustError, TspError};
use crate::trust::TrustStore;

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------

/// id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// id-signedData (1.2.840.113549.1.7.2)
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// id-contentType signed attribute (1.2.840.113549.1.9.3)
const ID_CONTENT_TYPE_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// id-messageDigest signed attribute (1.2.840.113549.1.9.4)
const ID_MESSAGE_DIGEST_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

const ID_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// Extended Key Usage extension (2.5.29.37)
const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// Basic Constraints extension (2.5.29.19)
const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// id-kp-timeStamping extended key usage (1.3.6.1.5.5.7.3.8).
///
/// RFC 3161 §2.3 requires the TSA signing certificate to carry this EKU,
/// and that the extension be marked **critical**.
const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// rsaEncryption (1.2.840.113549.1.1.1) — bare RSA key algorithm.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// id-ecPublicKey (1.2.840.10045.2.1) — bare EC key algorithm.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// id-RSASSA-PSS (1.2.840.113549.1.1.10).
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

// ---------------------------------------------------------------------------
// PKI status codes per RFC 3161 §2.4.2
// ---------------------------------------------------------------------------

/// PKIStatus values per RFC 3161.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiStatus {
    /// 0 — granted
    Granted,
    /// 1 — grantedWithMods
    GrantedWithMods,
    /// 2 — rejection
    Rejection,
    /// 3 — waiting
    Waiting,
    /// 4 — revocationWarning
    RevocationWarning,
    /// 5 — revocationNotification
    RevocationNotification,
    /// Unknown status value
    Unknown(u64),
}

impl PkiStatus {
    fn from_u64(v: u64) -> Self {
        match v {
            0 => Self::Granted,
            1 => Self::GrantedWithMods,
            2 => Self::Rejection,
            3 => Self::Waiting,
            4 => Self::RevocationWarning,
            5 => Self::RevocationNotification,
            _ => Self::Unknown(v),
        }
    }

    /// Returns true if the status indicates success (token was issued).
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Granted | Self::GrantedWithMods)
    }
}

impl std::fmt::Display for PkiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted => write!(f, "granted (0)"),
            Self::GrantedWithMods => write!(f, "grantedWithMods (1)"),
            Self::Rejection => write!(f, "rejection (2)"),
            Self::Waiting => write!(f, "waiting (3)"),
            Self::RevocationWarning => write!(f, "revocationWarning (4)"),
            Self::RevocationNotification => write!(f, "revocationNotification (5)"),
            Self::Unknown(v) => write!(f, "unknown ({v})"),
        }
    }
}

// ---------------------------------------------------------------------------
// TimeStampReq builder
// ---------------------------------------------------------------------------

/// Build a DER-encoded RFC 3161 `TimeStampReq`.
///
/// ```text
/// TimeStampReq ::= SEQUENCE  {
///    version               INTEGER  { v1(1) },
///    messageImprint        MessageImprint,
///    reqPolicy             TSAPolicyId              OPTIONAL,
///    nonce                 INTEGER                  OPTIONAL,
///    certReq               BOOLEAN                  DEFAULT FALSE,
///    extensions        [0] IMPLICIT Extensions      OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE  {
///    hashAlgorithm         AlgorithmIdentifier,
///    hashedMessage         OCTET STRING
/// }
/// ```
pub fn build_timestamp_request(
    digest_algorithm: DigestAlgorithm,
    message_hash: &[u8],
    policy_oid: Option<&ObjectIdentifier>,
    nonce: Option<u64>,
    cert_req: bool,
) -> Result<Vec<u8>, TspError> {
    let mut parts: Vec<Vec<u8>> = Vec::new();

    // version INTEGER { v1(1) }
    parts.push(der_utils::encode_integer_u64(1));

    // messageImprint
    let hash_alg = digest_algorithm_identifier(digest_algorithm);
    let hash_alg_der = hash_alg
        .to_der()
        .map_err(|e| TspError::InvalidResponse(format!("failed to encode hash algorithm: {e}")))?;
    let hashed_message = OctetString::new(message_hash.to_vec()).map_err(|e| {
        TspError::InvalidResponse(format!("failed to create hash octet string: {e}"))
    })?;
    let hashed_message_der = hashed_message
        .to_der()
        .map_err(|e| TspError::InvalidResponse(format!("failed to encode hash: {e}")))?;
    let msg_imprint = der_utils::encode_sequence_from_parts(&[&hash_alg_der, &hashed_message_der]);
    parts.push(msg_imprint);

    // reqPolicy OPTIONAL
    if let Some(oid) = policy_oid {
        let oid_der = oid
            .to_der()
            .map_err(|e| TspError::InvalidResponse(format!("failed to encode policy OID: {e}")))?;
        parts.push(oid_der);
    }

    // nonce OPTIONAL
    if let Some(n) = nonce {
        parts.push(der_utils::encode_integer_u64(n));
    }

    // certReq BOOLEAN DEFAULT FALSE — only encode when TRUE
    if cert_req {
        parts.push(der_utils::encode_boolean(true));
    }

    // Assemble SEQUENCE
    let body: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    Ok(der_utils::encode_sequence_raw(&body))
}

// ---------------------------------------------------------------------------
// TimeStampResp parsing
// ---------------------------------------------------------------------------

/// Parsed RFC 3161 TimeStampResp.
///
/// ```text
/// TimeStampResp ::= SEQUENCE  {
///    status                PKIStatusInfo,
///    timeStampToken        TimeStampToken     OPTIONAL
/// }
/// ```
#[derive(Debug)]
pub struct TimeStampResp {
    /// The PKI status information.
    pub status: PkiStatus,
    /// Free text status string (if any).
    pub status_string: Option<String>,
    /// Failure info bitstring (if any).
    pub failure_info: Option<Vec<u8>>,
    /// The raw DER-encoded TimeStampToken (a CMS ContentInfo).
    /// Present only when status is Granted or GrantedWithMods.
    pub token_der: Option<Vec<u8>>,
}

/// Parse a DER-encoded RFC 3161 `TimeStampResp`.
pub fn parse_timestamp_response(der_bytes: &[u8]) -> Result<TimeStampResp, TspError> {
    // TimeStampResp is a SEQUENCE
    let (response, trailing) = parse_tst_field(der_bytes, 0x30, "TimeStampResp")?;
    if !trailing.is_empty() {
        return Err(TspError::InvalidResponse(
            "trailing data after TimeStampResp".into(),
        ));
    }

    // First element: PKIStatusInfo SEQUENCE
    let (status_info, rest) = parse_tst_field(response.value(), 0x30, "PKIStatusInfo")?;

    // PKIStatusInfo: first element is PKIStatus INTEGER
    let (status_field, status_rest) = parse_tst_field(status_info.value(), 0x02, "PKIStatus")?;
    let status_val = status_field
        .decode_as::<u64>()
        .map_err(|e| TspError::InvalidResponse(format!("PKIStatus: {e}")))?;
    let status = PkiStatus::from_u64(status_val);

    // Parse optional statusString and failureInfo from status_rest
    let mut status_string = None;
    let mut failure_info = None;
    let mut remaining = status_rest;

    // Each remaining element of PKIStatusInfo is a well-formed TLV. A structural
    // parse failure here means the response is malformed, so fail hard rather
    // than silently truncating the optional statusString/failureInfo (L-6).
    while !remaining.is_empty() {
        let stag = remaining[0];
        let (field, srest) = parse_tst_field(remaining, stag, "PKIStatusInfo field")?;
        let sbody = field.value();
        match stag {
            // statusString PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
            0x30 => {
                if status_string.is_some() || failure_info.is_some() {
                    return Err(TspError::InvalidResponse(
                        "PKIStatusInfo: duplicate or out-of-order statusString".into(),
                    ));
                }
                // PKIFreeText is SIZE (1..MAX): a present-but-empty SEQUENCE
                // violates the constraint, so reject it rather than silently
                // accepting it and leaving `status_string` as None (L-6).
                if sbody.is_empty() {
                    return Err(TspError::InvalidResponse(
                        "statusString PKIFreeText SEQUENCE is empty (violates SIZE (1..MAX))"
                            .into(),
                    ));
                }
                // EVERY element MUST be a UTF8String (tag 0x0C) carrying valid
                // UTF-8 — not only the first. Reject any other ASN.1 type and
                // reject invalid UTF-8 rather than lossily normalizing it (L-6).
                // The first element is surfaced as `status_string`.
                let mut elems = sbody;
                while !elems.is_empty() {
                    if elems[0] != 0x0C {
                        return Err(TspError::InvalidResponse(format!(
                            "statusString element is not a UTF8String (tag 0x0c), got 0x{:02x}",
                            elems[0]
                        )));
                    }
                    let (text_field, inner_rest) = parse_tst_field(elems, 0x0C, "statusString")?;
                    let text = std::str::from_utf8(text_field.value()).map_err(|e| {
                        TspError::InvalidResponse(format!("statusString is not valid UTF-8: {e}"))
                    })?;
                    if status_string.is_none() {
                        status_string = Some(text.to_string());
                    }
                    elems = inner_rest;
                }
            }
            // BIT STRING (failureInfo)
            0x03 => {
                if failure_info.is_some() {
                    return Err(TspError::InvalidResponse(
                        "PKIStatusInfo: duplicate failureInfo".into(),
                    ));
                }
                let bits = field
                    .decode_as::<der::asn1::BitStringRef<'_>>()
                    .map_err(|e| {
                        TspError::InvalidResponse(format!("PKIStatusInfo failureInfo: {e}"))
                    })?;
                let unused = bits.unused_bits();
                if bits
                    .raw_bytes()
                    .last()
                    .is_some_and(|byte| byte & ((1u8 << unused) - 1) != 0)
                {
                    return Err(TspError::InvalidResponse(
                        "PKIStatusInfo failureInfo: nonzero unused bits".into(),
                    ));
                }
                // Keep the public field's existing raw BIT STRING body format.
                failure_info = Some(sbody.to_vec());
            }
            _ => {
                return Err(TspError::InvalidResponse(format!(
                    "PKIStatusInfo: unexpected field 0x{stag:02x}"
                )))
            }
        }
        remaining = srest;
    }

    // Second element: TimeStampToken OPTIONAL
    let token_der = if !rest.is_empty() {
        // The token is a ContentInfo (SEQUENCE). It must be a structurally valid
        // SEQUENCE that consumes ALL remaining bytes of the TimeStampResp — any
        // trailing bytes after it are malformed and rejected rather than being
        // folded into token_der or ignored (L-6).
        let (_, after) = parse_tst_field(rest, 0x30, "TimeStampToken SEQUENCE")?;
        if !after.is_empty() {
            return Err(TspError::InvalidResponse(
                "trailing data after TimeStampToken in TimeStampResp".into(),
            ));
        }
        // `rest` is now exactly the token TLV (tag + length + value).
        Some(rest.to_vec())
    } else {
        None
    };

    Ok(TimeStampResp {
        status,
        status_string,
        failure_info,
        token_der,
    })
}

/// Validate a TimeStampResp: check status, **cryptographically verify the
/// token signature**, and confirm the message imprint / nonce match the request.
///
/// This performs the full RFC 3161 / RFC 5652 verification of the embedded
/// `TimeStampToken`:
/// - the CMS `SignerInfo` signature is verified over the signed attributes;
/// - the `content-type` and `message-digest` signed attributes are checked to
///   bind the signature to the `TSTInfo` content;
/// - a signed ESS certificate identifier binds the exact signer certificate,
///   and an optional `TSTInfo.tsa` matches a subject/SAN name;
/// - the signing certificate is required to carry a critical
///   `id-kp-timeStamping` extended key usage.
///
/// It does **not** chain the TSA certificate to a trust anchor — at request
/// time the caller has no trust store. Use [`verify_timestamp_token`] with a
/// [`TrustStore`] to perform full path validation at verification time.
///
/// `extra_certs` lets the caller supply the TSA signing certificate out-of-band
/// for tokens that omit the (optional) CMS `certificates` field — e.g. when the
/// request used `certReq=false`. Pass `&[]` when the request used `certReq=true`
/// (the default), since the certificate is then embedded.
///
/// Returns the raw DER-encoded TimeStampToken (CMS ContentInfo containing SignedData).
pub fn validate_timestamp_response(
    resp: &TimeStampResp,
    expected_hash: &[u8],
    expected_nonce: Option<u64>,
    digest_algorithm: DigestAlgorithm,
    extra_certs: &[Certificate],
) -> Result<Vec<u8>, TspError> {
    validate_timestamp_response_for_policy(
        resp,
        expected_hash,
        expected_nonce,
        digest_algorithm,
        extra_certs,
        None,
    )
}

pub(crate) fn validate_timestamp_response_for_policy(
    resp: &TimeStampResp,
    expected_hash: &[u8],
    expected_nonce: Option<u64>,
    digest_algorithm: DigestAlgorithm,
    extra_certs: &[Certificate],
    expected_policy: Option<&ObjectIdentifier>,
) -> Result<Vec<u8>, TspError> {
    // Check status
    if !resp.status.is_success() {
        let msg = match &resp.status_string {
            Some(s) => format!("status={}, message={s}", resp.status),
            None => format!("status={}", resp.status),
        };
        return Err(TspError::TsaError(msg));
    }

    let token_der = resp.token_der.as_ref().ok_or_else(|| {
        TspError::InvalidResponse("no token in response despite success status".into())
    })?;

    // Cryptographically verify the CMS signature and bind it to the TSTInfo.
    let (_verified, tst_info) = verify_token_cms(token_der, extra_certs)?;

    // Validate message imprint hash / algorithm / nonce against the request.
    check_tst_info_matches(&tst_info, expected_hash, expected_nonce, digest_algorithm)?;
    check_tst_policy(tst_info.policy_oid.as_deref(), expected_policy)?;

    Ok(token_der.clone())
}

pub(crate) fn check_tst_policy(
    actual: Option<&str>,
    expected: Option<&ObjectIdentifier>,
) -> Result<(), TspError> {
    if let Some(expected) = expected {
        if actual != Some(expected.to_string().as_str()) {
            return Err(TspError::VerificationFailed(
                "timestamp policy does not match requested policy".into(),
            ));
        }
    }
    Ok(())
}

/// Fully verify an RFC 3161 timestamp token, including chaining the TSA
/// signing certificate to a configured trust anchor.
///
/// This is the entry point a *verifier* (as opposed to the requester) should
/// use — e.g. when validating an AdES B-T signature's embedded timestamp.
///
/// Verification steps:
/// 1. Parse the CMS `ContentInfo`/`SignedData` and locate the signing certificate.
/// 2. Verify the `SignerInfo` signature over the DER-encoded signed attributes.
/// 3. Check the `content-type` and `message-digest` signed attributes bind the
///    signature to the encapsulated `TSTInfo`.
/// 4. Require a critical `id-kp-timeStamping` EKU on the signing certificate.
/// 5. Check mandatory signed ESS certificate bindings and optional TSA name.
/// 6. Confirm the message imprint hash/algorithm (and nonce, if supplied) match.
/// 7. If `trust_store` is provided: build the certificate chain from the
///    available certificates and verify it terminates at a trust anchor.
///
/// The CMS `certificates` field is optional (RFC 5652) and some TSAs omit it
/// (e.g. when `certReq` was false). `extra_certs` lets the caller supply the
/// TSA signing certificate (and any intermediates) out-of-band so such tokens
/// can still be verified; pass `&[]` when the token embeds its own certificates.
///
/// `validation_time` is the time at which certificate validity is assessed
/// (typically the timestamp's `genTime` for archival validation, or "now").
/// When `None` and a trust store is supplied, it defaults to the token's
/// authenticated `genTime`.
///
/// Returns the verified [`TstInfo`] on success.
pub fn verify_timestamp_token(
    token_der: &[u8],
    expected_hash: &[u8],
    digest_algorithm: DigestAlgorithm,
    expected_nonce: Option<u64>,
    trust_store: Option<&TrustStore>,
    validation_time: Option<der::DateTime>,
    extra_certs: &[Certificate],
) -> Result<TstInfo, TspError> {
    let (verified, tst_info) = verify_token_cms(token_der, extra_certs)?;

    check_tst_info_matches(&tst_info, expected_hash, expected_nonce, digest_algorithm)?;

    if let Some(store) = trust_store {
        // Build the chain [signer, intermediate, ...] from embedded certs and
        // verify it reaches a trust anchor. verify_chain performs the actual
        // signature checks on every link, so the ordering is safe. Order using
        // the store's signature policy so that, when legacy algorithms are
        // allowed, a weak-but-valid link is still preferred over a bare
        // same-subject name match (which would otherwise pick the wrong
        // re-issued intermediate and make verify_chain fail).
        let chain = order_chain(
            &verified.signer,
            &verified.embedded,
            store.signature_policy(),
        );

        // Default the chain validation time to the token's authenticated
        // genTime. verify_chain skips intermediate/anchor time-validity checks
        // when validation_time is None, so falling back to genTime ensures the
        // chain is assessed as of the moment the timestamp was created (the
        // correct instant for archival validation) rather than not at all.
        let effective_time = match validation_time {
            Some(t) => Some(t),
            None => Some(gen_time_datetime(&tst_info)?),
        };

        // Bind the leaf to the TimestampSigner role at the chain layer as well
        // (H-4). Without `ltv` the role machinery is not compiled, but the
        // always-compiled CMS path already enforces the same TSA profile
        // (critical timeStamping EKU via `require_timestamping_eku`, not-a-CA via
        // `require_not_ca`), so both build configurations reject the same certs.
        let positive_fraction = validation_time.is_none() && gen_time_parts(&tst_info)?.1;
        let chain_result = store.verify_timestamp_chain(
            &chain,
            effective_time.expect("timestamp validation time is always supplied"),
            positive_fraction,
        );
        // The error covers both chain-building/anchor failures and, under `ltv`,
        // leaf purpose/profile violations (missing timeStamping EKU, non-critical
        // EKU, CA:TRUE), so keep the message general and defer to the inner error
        // for the specific cause.
        chain_result.map_err(|e| {
            TspError::VerificationFailed(format!("TSA certificate chain validation failed: {e}"))
        })?;
    }

    Ok(tst_info)
}

/// A timestamp token whose CMS signature has been cryptographically verified.
struct VerifiedToken {
    /// The certificate whose key signed the token.
    signer: Certificate,
    /// All certificates embedded in the SignedData (signer + any intermediates).
    embedded: Vec<Certificate>,
}

/// Parse and cryptographically verify the CMS SignedData of a timestamp token.
///
/// Returns the verified signer/embedded certificates together with the parsed
/// `TSTInfo` taken from the (now-authenticated) encapsulated content.
fn verify_token_cms(
    token_der: &[u8],
    extra_certs: &[Certificate],
) -> Result<(VerifiedToken, TstInfo), TspError> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    // ContentInfo { contentType, content [0] EXPLICIT }
    let ci = ContentInfo::from_der(token_der)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse ContentInfo: {e}")))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(TspError::InvalidResponse(format!(
            "ContentInfo contentType is not id-signedData (got {})",
            ci.content_type
        )));
    }

    let signed_data: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SignedData: {e}")))?;

    // encapContentInfo must wrap a TSTInfo.
    let eci = &signed_data.encap_content_info;
    if eci.econtent_type != ID_CT_TST_INFO {
        return Err(TspError::InvalidResponse(format!(
            "encapContentInfo eContentType is not id-ct-TSTInfo (got {})",
            eci.econtent_type
        )));
    }
    let econtent = eci.econtent.as_ref().ok_or_else(|| {
        TspError::InvalidResponse("SignedData has no encapsulated content".into())
    })?;
    // The eContent is an OCTET STRING; its value is the DER of TSTInfo.
    let tst_info_der = econtent.value().to_vec();

    // Exactly one SignerInfo is expected for an RFC 3161 token. More than one
    // makes verification ambiguous (which signer is authoritative?), so reject.
    let signer_infos = &signed_data.signer_infos.0;
    if signer_infos.len() != 1 {
        return Err(TspError::InvalidResponse(format!(
            "expected exactly one SignerInfo, found {}",
            signer_infos.len()
        )));
    }
    let signer_info = signer_infos.iter().next().expect("checked len == 1");

    // Signed attributes are mandatory: the signature is computed over them, and
    // they carry the message-digest binding to the eContent.
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TspError::VerificationFailed("SignerInfo has no signedAttrs".into()))?;

    // Collect candidate certificates: those embedded in the token (CMS
    // `certificates` is optional and may be absent) plus any supplied
    // out-of-band by the caller via `extra_certs`.
    let mut embedded: Vec<Certificate> = Vec::new();
    if let Some(cert_set) = &signed_data.certificates {
        for choice in cert_set.0.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                embedded.push(cert.clone());
            }
        }
    }
    for cert in extra_certs {
        if !embedded.iter().any(|c| c == cert) {
            embedded.push(cert.clone());
        }
    }

    // No certificates to verify against at all: the token omitted the (optional)
    // CMS `certificates` field and the caller supplied no `extra_certs`. This is
    // not a cryptographic failure — we simply lack the signer's public key — so
    // report it distinctly and point the caller at the two ways to provide it.
    if embedded.is_empty() {
        return Err(TspError::InvalidResponse(
            "timestamp token contains no certificates and no extra_certs were supplied; \
             request the token with certReq=true, or pass the TSA certificate via extra_certs"
                .into(),
        ));
    }

    // RFC 3161 §2.4.2 / RFC 5816: ESS binds the actual certificate, not only
    // its public key or the unsigned SignerIdentifier. Both versions, when
    // present, must bind the same certificate (RFC 5035 §2).
    let bindings = signing_certificate_bindings(signed_attrs)?;
    if let Some(unsigned) = &signer_info.unsigned_attrs {
        if unsigned
            .iter()
            .any(|a| a.oid == ID_SIGNING_CERTIFICATE || a.oid == ID_SIGNING_CERTIFICATE_V2)
        {
            return Err(TspError::VerificationFailed(
                "ESS signing-certificate attribute must be signed".into(),
            ));
        }
    }
    let mut signer = None;
    for cert in &embedded {
        if !signer_identifier_matches(&signer_info.sid, cert) {
            continue;
        }
        let mut matches = true;
        for binding in &bindings {
            if !binding.matches(cert)? {
                matches = false;
                break;
            }
        }
        if matches {
            signer = Some(cert.clone());
            break;
        }
    }
    let signer = signer.ok_or_else(|| {
        TspError::VerificationFailed(
            "no signing certificate matches SignerInfo and ESS certificate bindings".into(),
        )
    })?;

    // The digest algorithm used for the message-digest attribute and signature.
    let digest_alg = DigestAlgorithm::from_oid(&signer_info.digest_alg.oid).ok_or_else(|| {
        TspError::VerificationFailed(format!(
            "unsupported SignerInfo digestAlgorithm OID: {}",
            signer_info.digest_alg.oid
        ))
    })?;

    // --- content-type signed attribute must equal id-ct-TSTInfo ---
    let content_type_attr =
        find_attribute(signed_attrs, &ID_CONTENT_TYPE_ATTR)?.ok_or_else(|| {
            TspError::VerificationFailed("signedAttrs missing content-type attribute".into())
        })?;
    let signed_content_type: ObjectIdentifier = content_type_attr.decode_as().map_err(|e| {
        TspError::VerificationFailed(format!("invalid content-type attribute: {e}"))
    })?;
    if signed_content_type != ID_CT_TST_INFO {
        return Err(TspError::VerificationFailed(format!(
            "signed content-type is not id-ct-TSTInfo (got {signed_content_type})"
        )));
    }

    // --- message-digest signed attribute must equal digest(eContent) ---
    let message_digest_attr =
        find_attribute(signed_attrs, &ID_MESSAGE_DIGEST_ATTR)?.ok_or_else(|| {
            TspError::VerificationFailed("signedAttrs missing message-digest attribute".into())
        })?;
    // RFC 5652: the message-digest attribute value is an OCTET STRING. Decode it
    // as such rather than reading raw Any bytes, so a different ASN.1 type whose
    // content happens to match cannot be accepted.
    let signed_digest = message_digest_attr
        .decode_as::<OctetString>()
        .map_err(|e| {
            TspError::VerificationFailed(format!(
                "message-digest attribute is not an OCTET STRING: {e}"
            ))
        })?;
    let computed_digest = digest_alg.digest(&tst_info_der)?;
    if signed_digest.as_bytes() != computed_digest.as_slice() {
        return Err(TspError::VerificationFailed(
            "message-digest signed attribute does not match the TSTInfo content".into(),
        ));
    }

    // --- verify the SignerInfo signature over the DER-encoded signedAttrs ---
    // CMS signs the SET OF SignedAttributes (tag 0x31), not the [0] IMPLICIT form.
    let signed_attrs_der = signed_attrs.to_der().map_err(|e| {
        TspError::VerificationFailed(format!("failed to re-encode signedAttrs: {e}"))
    })?;
    let spki_der = signer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| TspError::VerificationFailed(format!("failed to encode signer SPKI: {e}")))?;
    verify_cms_signature(
        &signed_attrs_der,
        signer_info.signature.as_bytes(),
        &spki_der,
        &signer_info.signature_algorithm,
        digest_alg,
    )
    .map_err(|e| TspError::VerificationFailed(format!("TSA signature verification failed: {e}")))?;

    // --- require a critical id-kp-timeStamping EKU on the signer ---
    require_timestamping_eku(&signer)?;

    // --- the TSA signer must not be a CA (RFC 3161 §2.3 profile) ---
    // Enforced here, in the always-compiled CMS path, so the same TSA profile
    // holds in both `tsp`-only and `ltv` builds. The `ltv` chain path also runs
    // this via `CertRole::TimestampSigner`; keeping it here closes the gap where
    // a `tsp`-only build (which calls plain `verify_chain`) would otherwise
    // accept a CA certificate carrying a critical timeStamping EKU.
    require_not_ca(&signer)?;
    require_timestamp_signing_key_usage(&signer)?;

    // The TSTInfo is now authenticated; parse its fields.
    let tst_info = parse_tst_info_body(&tst_info_der)?;
    check_tsa_identity(&tst_info_der, &signer)?;

    // RFC 3161: genTime must fall within the signing certificate's validity.
    // This holds independently of any trust store, so enforce it on every
    // verification path (both the requester and the verifier entry points).
    check_gen_time_within_validity(&signer, &tst_info)?;

    Ok((VerifiedToken { signer, embedded }, tst_info))
}

/// A single ESS certificate identity. Restrictive multi-certificate/policy
/// profiles are rejected rather than silently ignoring path restrictions.
struct EssBinding {
    digest: riptering::HashAlgorithm,
    hash: Vec<u8>,
    issuer_serial: Option<(
        x509_cert::name::Name,
        x509_cert::serial_number::SerialNumber,
    )>,
}

impl EssBinding {
    fn matches(&self, cert: &Certificate) -> Result<bool, TspError> {
        use subtle::ConstantTimeEq;
        if self.issuer_serial.as_ref().is_some_and(|(issuer, serial)| {
            issuer != &cert.tbs_certificate.issuer || serial != &cert.tbs_certificate.serial_number
        }) {
            return Ok(false);
        }
        let der = cert
            .to_der()
            .map_err(|e| TspError::VerificationFailed(format!("ESS certificate encoding: {e}")))?;
        let hash = riptering::digest::digest(self.digest, &der)?;
        Ok(bool::from(hash.ct_eq(&self.hash)))
    }
}

fn signing_certificate_bindings(
    attrs: &x509_cert::attr::Attributes,
) -> Result<Vec<EssBinding>, TspError> {
    let mut bindings = Vec::new();
    for (oid, v2) in [
        (ID_SIGNING_CERTIFICATE, false),
        (ID_SIGNING_CERTIFICATE_V2, true),
    ] {
        if let Some(value) = find_attribute(attrs, &oid)? {
            bindings.push(parse_ess_binding(value, v2)?);
        }
    }
    if bindings.is_empty() {
        return Err(TspError::VerificationFailed(
            "timestamp signedAttrs lacks ESS SigningCertificate/SigningCertificateV2".into(),
        ));
    }
    Ok(bindings)
}

fn parse_ess_binding(value: &der::Any, v2: bool) -> Result<EssBinding, TspError> {
    use x509_cert::ext::pkix::name::GeneralName;
    let encoded = value
        .to_der()
        .map_err(|e| TspError::InvalidResponse(format!("ESS: {e}")))?;
    let (attribute, trailing) = parse_tst_field(&encoded, 0x30, "ESS signing certificate")?;
    if !trailing.is_empty() {
        return Err(TspError::InvalidResponse("ESS trailing data".into()));
    }
    let (certs, policies) = parse_tst_field(attribute.value(), 0x30, "ESS certs")?;
    // Additional identifiers restrict path certificates (RFC 5035 §3/§5).
    // This verifier does not implement certificate policy-tree processing.
    if !policies.is_empty() {
        return Err(TspError::VerificationFailed(
            "ESS certificate policy restrictions are unsupported".into(),
        ));
    }
    let (id, more) = parse_tst_field(certs.value(), 0x30, "ESS certificate ID")?;
    if !more.is_empty() {
        return Err(TspError::VerificationFailed(
            "ESS multiple certificate restrictions are unsupported".into(),
        ));
    }
    let mut pos = id.value();
    let mut digest = if v2 {
        riptering::HashAlgorithm::Sha256
    } else {
        riptering::HashAlgorithm::Sha1
    };
    if v2 && pos.first() == Some(&0x30) {
        let (alg, rest) = parse_tst_field(pos, 0x30, "ESS hashAlgorithm")?;
        let alg = alg
            .decode_as::<spki::AlgorithmIdentifierRef<'_>>()
            .map_err(|e| TspError::InvalidResponse(format!("ESS hashAlgorithm: {e}")))?;
        if alg.parameters.is_some_and(|p| !p.is_null()) {
            return Err(TspError::InvalidResponse(
                "ESS hash parameters must be absent or NULL".into(),
            ));
        }
        digest = if alg.oid == ObjectIdentifier::new_unwrap("1.3.14.3.2.26") {
            riptering::HashAlgorithm::Sha1
        } else {
            oid_to_digest_algorithm(&alg.oid)?.into()
        };
        pos = rest;
    }
    let (hash, rest) = parse_tst_field(pos, 0x04, "ESS certHash")?;
    let expected_len = match digest {
        riptering::HashAlgorithm::Sha1 => 20,
        riptering::HashAlgorithm::Sha256 | riptering::HashAlgorithm::Sha3_256 => 32,
        riptering::HashAlgorithm::Sha384 | riptering::HashAlgorithm::Sha3_384 => 48,
        riptering::HashAlgorithm::Sha512 | riptering::HashAlgorithm::Sha3_512 => 64,
        _ => return Err(TspError::InvalidResponse("unsupported ESS digest".into())),
    };
    if hash.value().len() != expected_len {
        return Err(TspError::InvalidResponse(
            "ESS certHash has incorrect length".into(),
        ));
    }
    let issuer_serial = if rest.is_empty() {
        None
    } else {
        let (issuer_serial, trailing) = parse_tst_field(rest, 0x30, "ESS issuerSerial")?;
        if !trailing.is_empty() {
            return Err(TspError::InvalidResponse(
                "ESS certificate ID trailing fields".into(),
            ));
        }
        let (names, rest) = parse_tst_field(issuer_serial.value(), 0x30, "ESS issuer names")?;
        let names = names
            .decode_as::<x509_cert::ext::pkix::name::GeneralNames>()
            .map_err(|e| TspError::InvalidResponse(format!("ESS issuer names: {e}")))?;
        let issuer = match names.as_slice() {
            [GeneralName::DirectoryName(name)] => name.clone(),
            _ => {
                return Err(TspError::InvalidResponse(
                    "ESS issuer must be exactly one directoryName".into(),
                ))
            }
        };
        let (serial, trailing) = parse_tst_field(rest, 0x02, "ESS serialNumber")?;
        if !trailing.is_empty() {
            return Err(TspError::InvalidResponse(
                "ESS issuerSerial trailing fields".into(),
            ));
        }
        let serial = serial
            .decode_as::<x509_cert::serial_number::SerialNumber>()
            .map_err(|e| TspError::InvalidResponse(format!("ESS serialNumber: {e}")))?;
        Some((issuer, serial))
    };
    Ok(EssBinding {
        digest,
        hash: hash.value().to_vec(),
        issuer_serial,
    })
}

/// RFC 3161 §2.4.2: an optional tsa must be one of the signer's names. Exact
/// typed names are used, with case-insensitive DNS names; wildcard matching
/// and general directory-string normalization are deliberately not inferred.
fn check_tsa_identity(tst_der: &[u8], signer: &Certificate) -> Result<(), TspError> {
    use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
    let (sequence, _) = parse_tst_field(tst_der, 0x30, "TSTInfo")?;
    let mut pos = sequence.value();
    while !pos.is_empty() {
        let is_tsa = pos[0] == 0xA0;
        let (field, rest) = parse_tst_field(pos, pos[0], "TSTInfo identity")?;
        pos = rest;
        if !is_tsa {
            continue;
        }
        let name = GeneralName::from_der(field.value()).map_err(|e| {
            TspError::VerificationFailed(format!(
                "TSTInfo tsa name is malformed or unsupported: {e}"
            ))
        })?;
        if matches!(&name, GeneralName::DirectoryName(n) if n == &signer.tbs_certificate.subject) {
            return Ok(());
        }
        let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
        let mut sans = signer
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .filter(|e| e.extn_id == san_oid);
        let san = sans.next();
        if sans.next().is_some() {
            return Err(TspError::VerificationFailed(
                "TSA certificate has duplicate subjectAltName".into(),
            ));
        }
        if let Some(san) = san {
            let san = SubjectAltName::from_der(san.extn_value.as_bytes())
                .map_err(|e| TspError::VerificationFailed(format!("TSA subjectAltName: {e}")))?;
            if san.0.iter().any(|candidate| match (&name, candidate) {
                (GeneralName::DnsName(a), GeneralName::DnsName(b)) => {
                    a.as_str().eq_ignore_ascii_case(b.as_str())
                }
                _ => &name == candidate,
            }) {
                return Ok(());
            }
        }
        return Err(TspError::VerificationFailed(
            "TSTInfo tsa does not match signer subject or subjectAltName".into(),
        ));
    }
    Ok(())
}

/// Validate that a parsed [`TstInfo`] matches the request's expected hash,
/// algorithm, and (optionally) nonce.
fn check_tst_info_matches(
    tst_info: &TstInfo,
    expected_hash: &[u8],
    expected_nonce: Option<u64>,
    digest_algorithm: DigestAlgorithm,
) -> Result<(), TspError> {
    use subtle::ConstantTimeEq;

    // Compare the messageImprint hash in constant time (L-7). These are public,
    // locally-derived values so the risk is low, but a constant-time compare is
    // cheap defense-in-depth and avoids leaking a match-prefix length.
    let hash_matches = tst_info.message_hash.len() == expected_hash.len()
        && bool::from(tst_info.message_hash.ct_eq(expected_hash));
    if !hash_matches {
        return Err(TspError::InvalidResponse(
            "TSTInfo messageImprint hash does not match request".into(),
        ));
    }

    if tst_info.hash_algorithm != digest_algorithm {
        return Err(TspError::InvalidResponse(format!(
            "TSTInfo hash algorithm mismatch: expected {:?}, got {:?}",
            digest_algorithm, tst_info.hash_algorithm,
        )));
    }

    if let Some(expected) = expected_nonce {
        match tst_info.nonce {
            // Constant-time nonce comparison (L-7).
            Some(actual) if bool::from(actual.ct_eq(&expected)) => {}
            Some(actual) => {
                return Err(TspError::InvalidResponse(format!(
                    "nonce mismatch: expected {expected}, got {actual}"
                )));
            }
            None => {
                return Err(TspError::InvalidResponse(
                    "expected nonce in TSTInfo but none present".into(),
                ));
            }
        }
    }

    Ok(())
}

/// Check whether a certificate matches the CMS `SignerIdentifier`.
fn signer_identifier_matches(sid: &cms::signed_data::SignerIdentifier, cert: &Certificate) -> bool {
    use cms::signed_data::SignerIdentifier;
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(iasn) => {
            cert.tbs_certificate.issuer == iasn.issuer
                && cert.tbs_certificate.serial_number == iasn.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(skid) => {
            let want = skid.0.as_bytes();
            cert_ski(cert).as_deref() == Some(want)
        }
    }
}

/// Extract the SubjectKeyIdentifier (2.5.29.14) octet contents from a cert.
fn cert_ski(cert: &Certificate) -> Option<Vec<u8>> {
    let ski_oid = ObjectIdentifier::new_unwrap("2.5.29.14");
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let ext = exts.iter().find(|e| e.extn_id == ski_oid)?;
    // extnValue is an OCTET STRING wrapping the SKI OCTET STRING.
    let (tag, body) = der_utils::parse_tlv(ext.extn_value.as_bytes()).ok()?;
    if tag != 0x04 {
        return None;
    }
    Some(body)
}

/// Find a single-valued signed attribute by OID.
///
/// Returns `Ok(None)` if the attribute is absent. CMS signed attributes such as
/// `content-type` and `message-digest` must appear exactly once and carry a
/// single value (RFC 5652 §11); duplicate attributes or multi-valued attributes
/// are rejected with `Err` to avoid ambiguity.
fn find_attribute<'a>(
    attrs: &'a x509_cert::attr::Attributes,
    oid: &ObjectIdentifier,
) -> Result<Option<&'a der::Any>, TspError> {
    let mut matching = attrs.iter().filter(|attr| attr.oid == *oid);
    let attr = match matching.next() {
        Some(a) => a,
        None => return Ok(None),
    };
    if matching.next().is_some() {
        return Err(TspError::VerificationFailed(format!(
            "duplicate signed attribute {oid}"
        )));
    }
    if attr.values.len() != 1 {
        return Err(TspError::VerificationFailed(format!(
            "signed attribute {oid} must have exactly one value (has {})",
            attr.values.len()
        )));
    }
    Ok(attr.values.iter().next())
}

/// Verify the CMS `SignerInfo` signature over `signed_attrs_der`.
///
/// The CMS `SignerInfo.signatureAlgorithm` is frequently a *bare* key algorithm
/// (`rsaEncryption`, `id-ecPublicKey`, `rsassaPss`) rather than a combined
/// sig+hash OID. The authoritative hash is `SignerInfo.digestAlgorithm`
/// (`digest_alg`), so we bind verification to it:
/// - RSASSA-PSS is verified strictly according to its `RSASSA-PSS-params`
///   (hashAlgorithm, MGF1 hash, saltLength, trailerField), and those
///   parameters must agree with `digestAlgorithm`. See [`verify_pss_signature`].
/// - Bare `rsaEncryption` / `id-ecPublicKey` are mapped to the combined OID for
///   `digest_alg`.
/// - A combined OID (sha256WithRSAEncryption, ecdsa-with-SHA256, ...) is passed
///   through, but only after checking that the hash it encodes matches
///   `digestAlgorithm`; a mismatch is rejected rather than silently accepted.
fn verify_cms_signature(
    signed_attrs_der: &[u8],
    signature: &[u8],
    spki_der: &[u8],
    signature_algorithm: &AlgorithmIdentifierOwned,
    digest_alg: DigestAlgorithm,
) -> Result<(), TrustError> {
    use crate::crypto::verify::verify_signature_by_oid;
    use const_oid::db;

    let sig_alg_oid = &signature_algorithm.oid;

    if *sig_alg_oid == OID_RSASSA_PSS {
        return verify_pss_signature(
            signed_attrs_der,
            signature,
            spki_der,
            signature_algorithm,
            digest_alg,
        );
    }

    let resolved = if *sig_alg_oid == OID_RSA_ENCRYPTION {
        match digest_alg {
            DigestAlgorithm::Sha256 => db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            DigestAlgorithm::Sha384 => db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION,
            DigestAlgorithm::Sha512 => db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION,
            _ => *sig_alg_oid,
        }
    } else if *sig_alg_oid == OID_EC_PUBLIC_KEY {
        match digest_alg {
            DigestAlgorithm::Sha256 => db::rfc5912::ECDSA_WITH_SHA_256,
            DigestAlgorithm::Sha384 => db::rfc5912::ECDSA_WITH_SHA_384,
            DigestAlgorithm::Sha512 => db::rfc5912::ECDSA_WITH_SHA_512,
            _ => *sig_alg_oid,
        }
    } else {
        // Already a combined OID (sha256WithRSAEncryption, ecdsa-with-SHA256,
        // Ed25519, ...). For the RSA/ECDSA combined forms the hash is encoded in
        // the OID itself; reject any token whose signatureAlgorithm hash
        // disagrees with the SignerInfo.digestAlgorithm used for the
        // message-digest attribute, instead of trusting two inconsistent hashes.
        if let Some(embedded) = combined_oid_digest(sig_alg_oid) {
            if embedded != digest_alg {
                return Err(TrustError::SignatureVerification(format!(
                    "signatureAlgorithm hash ({}) disagrees with SignerInfo.digestAlgorithm ({})",
                    embedded.name(),
                    digest_alg.name(),
                )));
            }
        }
        *sig_alg_oid
    };

    verify_signature_by_oid(signed_attrs_der, signature, spki_der, &resolved)
}

/// Verify an RSASSA-PSS `SignerInfo` signature strictly per its
/// `RSASSA-PSS-params` (RFC 4055), then bind the PSS hash to
/// `SignerInfo.digestAlgorithm`.
///
/// The parameter handling (hashAlgorithm, MGF1 hash, saltLength, trailerField)
/// lives in [`crate::crypto::verify::verify_rsa_pss_signature_strict`], shared
/// with certificate/CRL/OCSP verification. On top of that, CMS requires the
/// PSS `hashAlgorithm` to equal the `digestAlgorithm` used for the
/// message-digest attribute, so a token that pairs a mismatched hash with PSS
/// is rejected here even though the signature itself is well-formed.
fn verify_pss_signature(
    signed_attrs_der: &[u8],
    signature: &[u8],
    spki_der: &[u8],
    signature_algorithm: &AlgorithmIdentifierOwned,
    digest_alg: DigestAlgorithm,
) -> Result<(), TrustError> {
    use crate::crypto::verify::verify_rsa_pss_signature_strict;

    let pss_hash = verify_rsa_pss_signature_strict(
        signed_attrs_der,
        signature,
        spki_der,
        signature_algorithm.parameters.as_ref(),
    )?;

    if pss_hash != digest_alg {
        return Err(TrustError::SignatureVerification(format!(
            "RSASSA-PSS hashAlgorithm ({}) disagrees with SignerInfo.digestAlgorithm ({})",
            pss_hash.name(),
            digest_alg.name(),
        )));
    }

    Ok(())
}

/// For a *combined* signature-algorithm OID (one that bakes in the hash, e.g.
/// `sha256WithRSAEncryption` or `ecdsa-with-SHA256`), return the digest it
/// encodes. Returns `None` for OIDs that carry no separate hash we model here
/// (Ed25519, or legacy SHA-1/MD5/SHA-224 forms outside our digest set).
fn combined_oid_digest(oid: &ObjectIdentifier) -> Option<DigestAlgorithm> {
    use const_oid::db;
    if *oid == db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION || *oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        Some(DigestAlgorithm::Sha256)
    } else if *oid == db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION
        || *oid == db::rfc5912::ECDSA_WITH_SHA_384
    {
        Some(DigestAlgorithm::Sha384)
    } else if *oid == db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION
        || *oid == db::rfc5912::ECDSA_WITH_SHA_512
    {
        Some(DigestAlgorithm::Sha512)
    } else {
        None
    }
}

/// Require that `cert` carries the `id-kp-timeStamping` EKU, marked critical,
/// per RFC 3161 §2.3.
fn require_timestamping_eku(cert: &Certificate) -> Result<(), TspError> {
    let exts = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
        TspError::VerificationFailed("TSA certificate has no extensions (no EKU)".into())
    })?;
    let mut eku_extensions = exts.iter().filter(|e| e.extn_id == ID_CE_EXT_KEY_USAGE);
    let eku_ext = eku_extensions.next().ok_or_else(|| {
        TspError::VerificationFailed("TSA certificate lacks an extendedKeyUsage extension".into())
    })?;
    if eku_extensions.next().is_some() {
        return Err(TspError::VerificationFailed(
            "TSA certificate has duplicate extendedKeyUsage extensions".into(),
        ));
    }

    if !eku_ext.critical {
        return Err(TspError::VerificationFailed(
            "TSA certificate extendedKeyUsage is not marked critical (RFC 3161 §2.3)".into(),
        ));
    }

    let eku = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
        .map_err(|e| TspError::VerificationFailed(format!("TSA extendedKeyUsage: {e}")))?;
    if eku.0.as_slice() != [ID_KP_TIME_STAMPING] {
        return Err(TspError::VerificationFailed(
            "TSA certificate extendedKeyUsage must contain only id-kp-timeStamping (RFC 3161 §2.3)"
                .into(),
        ));
    }

    Ok(())
}

/// A present keyUsage must permit the timeStamping EKU's signing purpose in
/// every build. Absence imposes no additional key-usage restriction.
pub(crate) fn require_timestamp_signing_key_usage(cert: &Certificate) -> Result<(), TspError> {
    let oid = ObjectIdentifier::new_unwrap("2.5.29.15");
    let mut extensions = cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|ext| ext.extn_id == oid);
    let Some(extension) = extensions.next() else {
        return Ok(());
    };
    if extensions.next().is_some() {
        return Err(TspError::VerificationFailed(
            "TSA certificate has duplicate keyUsage".into(),
        ));
    }
    let bits = der::asn1::BitStringRef::from_der(extension.extn_value.as_bytes())
        .map_err(|e| TspError::VerificationFailed(format!("TSA keyUsage: {e}")))?;
    let raw = bits.raw_bytes();
    if raw.is_empty()
        || raw
            .last()
            .is_some_and(|last| last & ((1u8 << bits.unused_bits()) - 1) != 0)
    {
        return Err(TspError::VerificationFailed(
            "TSA keyUsage has invalid padding/content".into(),
        ));
    }
    // RFC 5280 §4.2.1.12: KU and EKU apply together, even when KU is
    // non-critical. timeStamping permits digitalSignature/nonRepudiation.
    if raw[0] & 0xC0 == 0 {
        return Err(TspError::VerificationFailed(
            "TSA keyUsage does not permit signing".into(),
        ));
    }
    Ok(())
}

/// A TSA certificate must not assert cA:TRUE. An absent basicConstraints
/// defaults to false; malformed or duplicate extensions fail closed.
fn require_not_ca(cert: &Certificate) -> Result<(), TspError> {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(()); // no extensions => no basicConstraints => not a CA
    };
    let mut bc_extensions = exts.iter().filter(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS);
    let Some(bc_ext) = bc_extensions.next() else {
        return Ok(()); // absent basicConstraints => cA defaults to FALSE
    };
    if bc_extensions.next().is_some() {
        return Err(TspError::VerificationFailed(
            "TSA certificate has duplicate basicConstraints extensions".into(),
        ));
    }
    let (is_ca, _) = der_utils::parse_basic_constraints(bc_ext.extn_value.as_bytes())
        .map_err(|e| TspError::VerificationFailed(format!("TSA basicConstraints: {e}")))?;
    if is_ca {
        return Err(TspError::VerificationFailed(
            "TSA certificate asserts basicConstraints CA:TRUE (RFC 3161 §2.3)".into(),
        ));
    }
    Ok(())
}

/// Order embedded certificates into a chain `[signer, issuer, ...]`.
///
/// For each step, candidates are matched by subject==issuer name and then the
/// one whose public key actually verifies the current certificate's signature
/// is preferred. This avoids picking the wrong certificate when several
/// embedded certs share a subject name (e.g. re-issued intermediates), which
/// would otherwise make a valid chain fail in [`TrustStore::verify_chain`]. If
/// no candidate verifies, the first name match is used so verify_chain still
/// produces a meaningful error.
fn order_chain(
    signer: &Certificate,
    embedded: &[Certificate],
    policy: crate::crypto::verify::SignaturePolicy,
) -> Vec<Certificate> {
    let mut chain = vec![signer.clone()];
    // Bounded to avoid loops on adversarial inputs.
    for _ in 0..16 {
        let current = chain.last().unwrap().clone();
        if current.tbs_certificate.issuer == current.tbs_certificate.subject {
            break; // reached a self-signed cert
        }
        let candidates: Vec<&Certificate> = embedded
            .iter()
            .filter(|c| {
                c.tbs_certificate.subject == current.tbs_certificate.issuer
                    && !chain
                        .iter()
                        .any(|existing| existing.tbs_certificate == c.tbs_certificate)
            })
            .collect();

        // Prefer a candidate whose key actually signed `current`. Use the same
        // policy verify_chain will use, so a legacy-but-valid link is preferred
        // (under allow_legacy) instead of being skipped and falling back to a
        // possibly-wrong same-subject name match.
        let chosen = candidates
            .iter()
            .find(|c| {
                crate::crypto::verify::verify_certificate_signature_with_policy(
                    &current, c, &policy,
                )
                .is_ok()
            })
            .or_else(|| candidates.first());

        match chosen {
            Some(c) => chain.push((*c).clone()),
            None => break,
        }
    }
    chain
}

/// Decode the timestamp's `genTime` (GeneralizedTime) to a `der::DateTime`.
fn gen_time_datetime(tst_info: &TstInfo) -> Result<der::DateTime, TspError> {
    Ok(gen_time_parts(tst_info)?.0)
}

/// DER GeneralizedTime uses UTC seconds with an optional fractional second,
/// no comma and no trailing fractional zero (RFC 3161 §2.4.2 / X.690 §11.7).
/// Certificate times have whole-second resolution. Preserve the exact bytes
/// for callers, and carry whether the fraction is positive for end boundaries.
fn gen_time_parts(tst_info: &TstInfo) -> Result<(der::DateTime, bool), TspError> {
    let bytes = &tst_info.gen_time_der;
    let fractional = if bytes.len() == 15 && bytes[14] == b'Z' {
        false
    } else if bytes.len() >= 17
        && bytes[14] == b'.'
        && bytes.last() == Some(&b'Z')
        && bytes[15..bytes.len() - 1].iter().all(u8::is_ascii_digit)
        && bytes[bytes.len() - 2] != b'0'
    {
        true
    } else {
        return Err(TspError::VerificationFailed(
            "invalid DER genTime fractional/UTC encoding".into(),
        ));
    };
    let mut seconds = bytes[..14].to_vec();
    seconds.push(b'Z');
    let gt_tlv = der_utils::encode_tlv(0x18, &seconds);
    Ok(der::asn1::GeneralizedTime::from_der(&gt_tlv)
        .map_err(|e| TspError::VerificationFailed(format!("invalid genTime: {e}")))?
        .to_date_time())
    .map(|time| (time, fractional))
}

/// Confirm the timestamp's `genTime` falls within the signer certificate's
/// validity window (RFC 3161).
fn check_gen_time_within_validity(
    signer: &Certificate,
    tst_info: &TstInfo,
) -> Result<(), TspError> {
    let (gen_time, fractional) = gen_time_parts(tst_info)?;

    let validity = &signer.tbs_certificate.validity;
    let not_before = validity.not_before.to_date_time();
    let not_after = validity.not_after.to_date_time();

    if gen_time < not_before || gen_time > not_after || (fractional && gen_time == not_after) {
        return Err(TspError::VerificationFailed(format!(
            "timestamp genTime {gen_time} is outside the TSA certificate validity \
             ({not_before} .. {not_after})"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TSTInfo extraction
// ---------------------------------------------------------------------------

/// Parsed TSTInfo from a TimeStampToken.
#[derive(Debug)]
pub struct TstInfo {
    /// The hash algorithm used in the message imprint.
    pub hash_algorithm: DigestAlgorithm,
    /// The message hash from the message imprint.
    pub message_hash: Vec<u8>,
    /// The serial number of the timestamp.
    pub serial_number: Vec<u8>,
    /// The generation time (raw DER bytes of GeneralizedTime).
    pub gen_time_der: Vec<u8>,
    /// Nonce from the response (if present).
    pub nonce: Option<u64>,
    /// The TSA policy OID.
    pub policy_oid: Option<String>,
}

/// Extract TSTInfo from a TimeStampToken (CMS ContentInfo).
///
/// The TimeStampToken is a CMS ContentInfo wrapping SignedData,
/// whose encapsulated content is id-ct-TSTInfo.
///
/// # Warning — parsing only, NO verification
///
/// This function performs **zero cryptographic verification**: the CMS
/// signature, the signer certificate, its trust chain, and the timeStamping
/// EKU are all ignored. The returned fields (including `genTime`) are
/// **unauthenticated, attacker-controllable data**. Never make a trust
/// decision from its output — use [`verify_timestamp_token`], which returns
/// the same [`TstInfo`] only after full RFC 3161 verification. This parser is
/// intended for display/debugging of token contents.
pub fn extract_tst_info(token_der: &[u8]) -> Result<TstInfo, TspError> {
    // Parse ContentInfo SEQUENCE
    let (tag, ci_body) = der_utils::parse_tlv(token_der)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse ContentInfo: {e}")))?;
    if tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "ContentInfo: expected SEQUENCE".into(),
        ));
    }

    // contentType OID — should be id-signedData
    let (_oid_tag, _oid_body, ci_rest) = der_utils::parse_tlv_with_rest(&ci_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse contentType: {e}")))?;

    // content [0] EXPLICIT — the SignedData
    let (ctx_tag, sd_inner, _) = der_utils::parse_tlv_with_rest(ci_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse content [0]: {e}")))?;
    if ctx_tag != 0xA0 {
        return Err(TspError::InvalidResponse(format!(
            "expected [0] EXPLICIT tag 0xA0, got 0x{ctx_tag:02x}"
        )));
    }

    // SignedData SEQUENCE
    let (sd_tag, sd_body) = der_utils::parse_tlv(sd_inner)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SignedData: {e}")))?;
    if sd_tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "SignedData: expected SEQUENCE".into(),
        ));
    }

    // SignedData fields: version, digestAlgorithms, encapContentInfo, [0] certs, [1] crls, signerInfos
    let (_ver_tag, _ver_body, sd_rest) = der_utils::parse_tlv_with_rest(&sd_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SD version: {e}")))?;

    // digestAlgorithms SET OF
    let (_da_tag, _da_body, sd_rest2) = der_utils::parse_tlv_with_rest(sd_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse digestAlgorithms: {e}")))?;

    // encapContentInfo SEQUENCE
    let (_eci_tag, eci_body, _sd_rest3) = der_utils::parse_tlv_with_rest(sd_rest2)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse encapContentInfo: {e}")))?;

    // eContentType OID
    let (_ect_tag, _ect_body, eci_rest) = der_utils::parse_tlv_with_rest(eci_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse eContentType: {e}")))?;

    // eContent [0] EXPLICIT
    let (ec_tag, ec_inner, _) = der_utils::parse_tlv_with_rest(eci_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse eContent [0]: {e}")))?;
    if ec_tag != 0xA0 {
        return Err(TspError::InvalidResponse(format!(
            "expected eContent [0] tag 0xA0, got 0x{ec_tag:02x}"
        )));
    }

    // The eContent is an OCTET STRING containing TSTInfo
    let (os_tag, tst_info_der, _) = der_utils::parse_tlv_with_rest(ec_inner).map_err(|e| {
        TspError::InvalidResponse(format!("failed to parse eContent OCTET STRING: {e}"))
    })?;
    if os_tag != 0x04 {
        return Err(TspError::InvalidResponse(format!(
            "expected OCTET STRING 0x04 for eContent, got 0x{os_tag:02x}"
        )));
    }

    // Now parse TSTInfo SEQUENCE
    parse_tst_info_body(tst_info_der)
}

/// Parse the inner TSTInfo SEQUENCE body.
///
/// ```text
/// TSTInfo ::= SEQUENCE  {
///    version                      INTEGER  { v1(1) },
///    policy                       TSAPolicyId,
///    messageImprint               MessageImprint,
///    serialNumber                 INTEGER,
///    genTime                      GeneralizedTime,
///    accuracy                     Accuracy               OPTIONAL,
///    ordering                     BOOLEAN             DEFAULT FALSE,
///    nonce                        INTEGER                OPTIONAL,
///    tsa                     [0]  GeneralName            OPTIONAL,
///    extensions              [1]  IMPLICIT Extensions    OPTIONAL
/// }
/// ```
fn parse_tst_info_body(der_bytes: &[u8]) -> Result<TstInfo, TspError> {
    let (sequence, trailing) = parse_tst_field(der_bytes, 0x30, "TSTInfo")?;
    if !trailing.is_empty() {
        return Err(TspError::InvalidResponse(
            "TSTInfo: trailing data after SEQUENCE".into(),
        ));
    }
    let mut pos = sequence.value();

    // version INTEGER
    let (version, rest) = parse_tst_field(pos, 0x02, "TSTInfo version")?;
    let version = version
        .decode_as::<u64>()
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo version: {e}")))?;
    if version != 1 {
        return Err(TspError::InvalidResponse(format!(
            "TSTInfo: unsupported version {version} (expected 1)"
        )));
    }
    pos = rest;

    // policy TSAPolicyId (OID)
    let (policy, rest) = parse_tst_field(pos, 0x06, "TSTInfo policy")?;
    let policy_oid = Some(
        policy
            .decode_as::<ObjectIdentifier>()
            .map_err(|e| TspError::InvalidResponse(format!("TSTInfo policy: {e}")))?
            .to_string(),
    );
    pos = rest;

    // messageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    let (message_imprint, rest) = parse_tst_field(pos, 0x30, "TSTInfo messageImprint")?;
    pos = rest;
    let (hash_algorithm, message_hash) = parse_message_imprint(message_imprint.value())?;

    // serialNumber INTEGER
    let (serial, rest) = parse_tst_field(pos, 0x02, "TSTInfo serialNumber")?;
    serial
        .decode_as::<der::asn1::IntRef<'_>>()
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo serialNumber: {e}")))?;
    let serial_number = serial.value().to_vec();
    pos = rest;

    // genTime GeneralizedTime
    let (gen_time, rest) = parse_tst_field(pos, 0x18, "TSTInfo genTime")?;
    let gen_time_der = gen_time.value().to_vec();
    pos = rest;

    // Optional fields have a fixed order and each can occur only once. In
    // particular, a second nonce must not replace the value already parsed.
    let mut nonce = None;
    let mut last_optional = 0;
    while !pos.is_empty() {
        let (rank, context) = match pos[0] {
            0x30 => (1, "TSTInfo accuracy"),
            0x01 => (2, "TSTInfo ordering"),
            0x02 => (3, "TSTInfo nonce"),
            0xA0 => (4, "TSTInfo tsa"),
            0xA1 => (5, "TSTInfo extensions"),
            tag => {
                return Err(TspError::InvalidResponse(format!(
                    "TSTInfo: unexpected optional field 0x{tag:02x}"
                )))
            }
        };
        if rank <= last_optional {
            return Err(TspError::InvalidResponse(format!(
                "{context}: duplicate or out-of-order field"
            )));
        }
        let (field, rest) = parse_tst_field(pos, pos[0], context)?;
        match rank {
            1 => validate_tst_accuracy(field.value())?,
            2 => {
                field
                    .decode_as::<bool>()
                    .map_err(|e| TspError::InvalidResponse(format!("{context}: {e}")))?;
            }
            3 => {
                nonce = Some(
                    field
                        .decode_as::<u64>()
                        .map_err(|e| TspError::InvalidResponse(format!("{context}: {e}")))?,
                );
            }
            4 => validate_tst_tsa_name(field.value())?,
            5 => validate_tst_extensions(field.value())?,
            _ => unreachable!("optional field ranks are fixed above"),
        }
        last_optional = rank;
        pos = rest;
    }

    Ok(TstInfo {
        hash_algorithm,
        message_hash,
        serial_number,
        gen_time_der,
        nonce,
        policy_oid,
    })
}

/// Parse one field without copying its body. The DER decoder additionally
/// checks canonical tag/length encoding; callers explicitly consume the rest.
fn parse_tst_field<'a>(
    input: &'a [u8],
    expected_tag: u8,
    context: &str,
) -> Result<(der::asn1::AnyRef<'a>, &'a [u8]), TspError> {
    let (tag, _, rest) = der_utils::parse_tlv_with_rest(input)
        .map_err(|e| TspError::InvalidResponse(format!("{context}: {e}")))?;
    if tag != expected_tag {
        return Err(TspError::InvalidResponse(format!(
            "{context}: expected tag 0x{expected_tag:02x}, got 0x{tag:02x}"
        )));
    }
    let consumed = input.len() - rest.len();
    let value = der::asn1::AnyRef::from_der(&input[..consumed])
        .map_err(|e| TspError::InvalidResponse(format!("{context}: {e}")))?;
    Ok((value, rest))
}

fn validate_tst_accuracy(mut pos: &[u8]) -> Result<(), TspError> {
    let mut last_component = 0;
    while !pos.is_empty() {
        let rank = match pos[0] {
            0x02 => 1, // seconds INTEGER OPTIONAL
            0x80 => 2, // millis [0] INTEGER (1..999) OPTIONAL
            0x81 => 3, // micros [1] INTEGER (1..999) OPTIONAL
            tag => {
                return Err(TspError::InvalidResponse(format!(
                    "TSTInfo accuracy: unexpected field 0x{tag:02x}"
                )))
            }
        };
        if rank <= last_component {
            return Err(TspError::InvalidResponse(
                "TSTInfo accuracy: duplicate or out-of-order component".into(),
            ));
        }
        let (field, rest) = parse_tst_field(pos, pos[0], "TSTInfo accuracy")?;
        // The context-specific components are IMPLICIT INTEGERs.
        let integer = der::asn1::AnyRef::new(der::Tag::Integer, field.value())
            .map_err(|e| TspError::InvalidResponse(format!("TSTInfo accuracy: {e}")))?;
        if rank == 1 {
            integer
                .decode_as::<der::asn1::UintRef<'_>>()
                .map_err(|e| TspError::InvalidResponse(format!("TSTInfo accuracy seconds: {e}")))?;
        } else {
            let fraction = integer.decode_as::<u16>().map_err(|e| {
                TspError::InvalidResponse(format!("TSTInfo accuracy millis/micros: {e}"))
            })?;
            if !(1..=999).contains(&fraction) {
                return Err(TspError::InvalidResponse(
                    "TSTInfo accuracy millis/micros must be in 1..=999".into(),
                ));
            }
        }
        last_component = rank;
        pos = rest;
    }
    Ok(())
}

fn validate_tst_tsa_name(body: &[u8]) -> Result<(), TspError> {
    let tag = *body
        .first()
        .ok_or_else(|| TspError::InvalidResponse("TSTInfo tsa: missing GeneralName".into()))?;
    if !matches!(
        tag,
        0xA0 | 0x81 | 0x82 | 0xA3 | 0xA4 | 0xA5 | 0x86 | 0x87 | 0x88
    ) {
        return Err(TspError::InvalidResponse(format!(
            "TSTInfo tsa: invalid GeneralName tag 0x{tag:02x}"
        )));
    }
    let (_, rest) = parse_tst_field(body, tag, "TSTInfo tsa GeneralName")?;
    if !rest.is_empty() {
        return Err(TspError::InvalidResponse(
            "TSTInfo tsa: trailing data after GeneralName".into(),
        ));
    }
    // Keep every GeneralName choice, including x400Address, which x509-cert's
    // typed decoder does not support. Identity matching is a separate check.
    Ok(())
}

fn validate_tst_extensions(mut pos: &[u8]) -> Result<(), TspError> {
    if pos.is_empty() {
        return Err(TspError::InvalidResponse(
            "TSTInfo extensions: empty Extensions".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    while !pos.is_empty() {
        let (field, rest) = parse_tst_field(pos, 0x30, "TSTInfo extension")?;
        let extension = field
            .decode_as::<x509_cert::ext::Extension>()
            .map_err(|e| TspError::InvalidResponse(format!("TSTInfo extension: {e}")))?;
        if !seen.insert(extension.extn_id) {
            return Err(TspError::InvalidResponse(format!(
                "TSTInfo extension: duplicate OID {}",
                extension.extn_id
            )));
        }
        // No TSTInfo extension is currently interpreted by this verifier.
        if extension.critical {
            return Err(TspError::InvalidResponse(format!(
                "TSTInfo extension: unsupported critical extension {}",
                extension.extn_id
            )));
        }
        pos = rest;
    }
    Ok(())
}

/// Parse a MessageImprint: { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
fn parse_message_imprint(body: &[u8]) -> Result<(DigestAlgorithm, Vec<u8>), TspError> {
    let (algorithm, rest) = parse_tst_field(body, 0x30, "messageImprint hashAlgorithm")?;
    let algorithm = algorithm
        .decode_as::<spki::AlgorithmIdentifierRef<'_>>()
        .map_err(|e| TspError::InvalidResponse(format!("messageImprint hashAlgorithm: {e}")))?;
    let digest_alg = oid_to_digest_algorithm(&algorithm.oid)?;
    // Preserve the absent/NULL convention used by interoperable SHA-2 TSAs.
    if algorithm.parameters.is_some_and(|params| !params.is_null()) {
        return Err(TspError::InvalidResponse(
            "messageImprint hashAlgorithm parameters must be absent or NULL".into(),
        ));
    }
    let (hash, trailing) = parse_tst_field(rest, 0x04, "messageImprint hashedMessage")?;
    if !trailing.is_empty() {
        return Err(TspError::InvalidResponse(
            "messageImprint: trailing data after hashedMessage".into(),
        ));
    }
    if hash.value().len() != digest_alg.output_size() {
        return Err(TspError::InvalidResponse(format!(
            "messageImprint: {} hash must contain {} bytes, got {}",
            digest_alg.name(),
            digest_alg.output_size(),
            hash.value().len()
        )));
    }
    Ok((digest_alg, hash.value().to_vec()))
}

/// Map an OID to our DigestAlgorithm enum.
fn oid_to_digest_algorithm(oid: &ObjectIdentifier) -> Result<DigestAlgorithm, TspError> {
    DigestAlgorithm::from_oid(oid)
        .ok_or_else(|| TspError::InvalidResponse(format!("unsupported hash algorithm OID: {oid}")))
}

/// Build an AlgorithmIdentifier for a digest algorithm.
fn digest_algorithm_identifier(alg: DigestAlgorithm) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: alg.oid(),
        parameters: None,
    }
}

// ---------------------------------------------------------------------------
// Generate a nonce
// ---------------------------------------------------------------------------

/// Generate a cryptographically random 64-bit nonce for timestamp requests.
pub fn generate_nonce() -> riptering::Result<u64> {
    let buf = riptering::random_bytes(8)?;
    Ok(u64::from_ne_bytes(
        buf.try_into()
            .expect("requested exactly eight random bytes"),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_tst_info_fields() -> Vec<Vec<u8>> {
        let algorithm = digest_algorithm_identifier(DigestAlgorithm::Sha256)
            .to_der()
            .unwrap();
        let hash = der_utils::encode_tlv(0x04, &[0xAA; 32]);
        vec![
            der_utils::encode_integer_u64(1),
            ObjectIdentifier::new_unwrap("1.2.3.4").to_der().unwrap(),
            der_utils::encode_sequence_from_parts(&[&algorithm, &hash]),
            der_utils::encode_integer_u64(42),
            der_utils::encode_tlv(0x18, b"20260303120000Z"),
        ]
    }

    fn synthetic_tst_info(fields: &[Vec<u8>]) -> Vec<u8> {
        der_utils::encode_sequence_raw(&fields.concat())
    }

    #[test]
    fn test_tsa_eku_requires_one_exclusive_fully_parsed_timestamp_purpose() {
        let oid = ID_KP_TIME_STAMPING.to_der().unwrap();
        let valid = der_utils::encode_sequence_raw(&oid);
        let extension = x509_cert::ext::Extension {
            extn_id: ID_CE_EXT_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(valid.clone()).unwrap(),
        };
        let mut cert = intermediate_cert();
        cert.tbs_certificate.extensions = Some(vec![extension.clone()]);
        assert!(require_timestamping_eku(&cert).is_ok());
        let other_purpose = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")
            .to_der()
            .unwrap();
        for invalid in [
            der_utils::encode_sequence_from_parts(&[&oid, &other_purpose]),
            der_utils::encode_sequence_from_parts(&[&oid, &oid]),
            der_utils::encode_sequence_raw(&[]),
            der_utils::encode_sequence_from_parts(&[&oid, &[0x06, 0x02, 0x2A]]),
            [valid, vec![0x05, 0x00]].concat(),
        ] {
            cert.tbs_certificate.extensions = Some(vec![x509_cert::ext::Extension {
                extn_value: OctetString::new(invalid).unwrap(),
                ..extension.clone()
            }]);
            assert!(require_timestamping_eku(&cert).is_err());
        }
        cert.tbs_certificate.extensions = Some(vec![extension.clone(), extension]);
        assert!(matches!(
            require_timestamping_eku(&cert),
            Err(TspError::VerificationFailed(message)) if message.contains("duplicate")
        ));
    }

    #[test]
    fn test_tsa_basic_constraints_rejects_duplicate_extensions() {
        let non_ca = x509_cert::ext::Extension {
            extn_id: ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new([0x30, 0x00]).unwrap(),
        };
        let mut cert = intermediate_cert();
        cert.tbs_certificate.extensions = Some(vec![non_ca.clone()]);
        assert!(require_not_ca(&cert).is_ok());
        cert.tbs_certificate.extensions = Some(vec![non_ca.clone(), non_ca]);
        assert!(matches!(
            require_not_ca(&cert),
            Err(TspError::VerificationFailed(message)) if message.contains("duplicate")
        ));
    }

    #[test]
    fn test_tst_info_requires_correct_required_field_tags_and_version() {
        let fields = synthetic_tst_info_fields();
        assert!(parse_tst_info_body(&synthetic_tst_info(&fields)).is_ok());
        for index in 0..fields.len() {
            let mut wrong_tag = fields.clone();
            wrong_tag[index][0] = 0x04;
            assert!(
                parse_tst_info_body(&synthetic_tst_info(&wrong_tag)).is_err(),
                "required field {index} must retain its ASN.1 type"
            );
        }
        for version in [vec![0x02, 0x01, 0x02], vec![0x02, 0x02, 0x00, 0x01]] {
            let mut invalid = fields.clone();
            invalid[0] = version;
            assert!(parse_tst_info_body(&synthetic_tst_info(&invalid)).is_err());
        }
        let mut invalid = fields;
        invalid[1] = vec![0x06, 0x01, 0x80];
        assert!(parse_tst_info_body(&synthetic_tst_info(&invalid)).is_err());
    }

    #[test]
    fn test_tst_info_rejects_trailing_malformed_duplicate_and_unordered_fields() {
        let fields = synthetic_tst_info_fields();
        let mut trailing = synthetic_tst_info(&fields);
        trailing.extend_from_slice(&[0x05, 0x00]);
        assert!(parse_tst_info_body(&trailing).is_err());
        let nonce = der_utils::encode_integer_u64(7);
        let optional_cases = [
            vec![vec![0x02, 0x02, 0x01]], // truncated nonce
            vec![nonce.clone(), nonce.clone()],
            vec![nonce, der_utils::encode_boolean(true)],
            vec![vec![0x05, 0x00]],       // unknown optional field
            vec![vec![0x01, 0x01, 0x01]], // non-DER BOOLEAN
            vec![vec![0xA0, 0x00]],       // empty TSA GeneralName wrapper
            vec![vec![0xA1, 0x00]],       // empty Extensions
        ];
        for optional in optional_cases {
            let mut invalid = fields.clone();
            invalid.extend(optional);
            assert!(parse_tst_info_body(&synthetic_tst_info(&invalid)).is_err());
        }
    }

    #[test]
    fn test_tst_info_accepts_well_formed_optional_fields() {
        let mut fields = synthetic_tst_info_fields();
        let seconds = der_utils::encode_integer_u64(0);
        let millis = der_utils::encode_tlv(0x80, &[1]);
        let micros = der_utils::encode_tlv(0x81, &[0x03, 0xE7]); // 999
        fields.push(der_utils::encode_sequence_from_parts(&[
            &seconds, &millis, &micros,
        ]));
        fields.push(der_utils::encode_boolean(true));
        fields.push(der_utils::encode_integer_u64(u64::MAX));
        fields.push(der_utils::encode_tlv(
            0xA0,
            &der_utils::encode_tlv(0x82, b"tsa.example"),
        ));
        let extension = x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.2.3.5"),
            critical: false,
            extn_value: OctetString::new([0x05, 0x00]).unwrap(),
        };
        fields.push(der_utils::encode_tlv(0xA1, &extension.to_der().unwrap()));
        let info = parse_tst_info_body(&synthetic_tst_info(&fields)).unwrap();
        assert_eq!(info.nonce, Some(u64::MAX));
        assert_eq!(info.policy_oid.as_deref(), Some("1.2.3.4"));
        // Preserve the GeneralName choice omitted by x509-cert's typed decoder.
        fields[8] = der_utils::encode_tlv(0xA0, &[0xA3, 0x02, 0x30, 0x00]);
        assert!(parse_tst_info_body(&synthetic_tst_info(&fields)).is_ok());
    }

    #[test]
    fn test_tst_info_accuracy_requires_valid_order_and_fraction_bounds() {
        for body in [
            vec![0x80, 0x01, 0x00],                   // zero millis
            vec![0x81, 0x02, 0x03, 0xE8],             // 1000 micros
            vec![0x80, 0x01, 0x01, 0x80, 0x01, 0x02], // duplicate millis
            vec![0x81, 0x01, 0x01, 0x80, 0x01, 0x01], // reversed order
            vec![0x02, 0x01, 0xFF],                   // negative seconds
            vec![0x80, 0x02, 0x00],                   // truncated millis
        ] {
            let mut fields = synthetic_tst_info_fields();
            fields.push(der_utils::encode_tlv(0x30, &body));
            assert!(parse_tst_info_body(&synthetic_tst_info(&fields)).is_err());
        }
    }

    #[test]
    fn test_tst_info_extensions_rejects_duplicate_and_unrecognized_critical_oids() {
        let extension = x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.2.3.5"),
            critical: false,
            extn_value: OctetString::new([0x05, 0x00]).unwrap(),
        };
        let encoded = extension.to_der().unwrap();
        assert!(validate_tst_extensions(&encoded).is_ok());
        assert!(matches!(
            validate_tst_extensions(&[encoded.clone(), encoded].concat()),
            Err(TspError::InvalidResponse(message)) if message.contains("duplicate")
        ));
        let critical = x509_cert::ext::Extension {
            critical: true,
            ..extension
        };
        let mut fields = synthetic_tst_info_fields();
        fields.push(der_utils::encode_tlv(0xA1, &critical.to_der().unwrap()));
        assert!(matches!(
            parse_tst_info_body(&synthetic_tst_info(&fields)),
            Err(TspError::InvalidResponse(message)) if message.contains("critical")
        ));
    }

    #[test]
    fn test_message_imprint_validates_types_parameters_hash_size_and_consumption() {
        let algorithm = digest_algorithm_identifier(DigestAlgorithm::Sha256)
            .to_der()
            .unwrap();
        let hash = der_utils::encode_tlv(0x04, &[0xAA; 32]);
        let body = [algorithm.clone(), hash.clone()].concat();
        assert!(parse_message_imprint(&body).is_ok());
        let mut wrong_algorithm_tag = algorithm.clone();
        wrong_algorithm_tag[0] = 0x04;
        let mut wrong_hash_tag = hash.clone();
        wrong_hash_tag[0] = 0x02;
        let mut oid = DigestAlgorithm::Sha256.oid().to_der().unwrap();
        oid[0] = 0x04;
        let wrong_oid_tag = der_utils::encode_sequence_raw(&oid);
        let parameters = AlgorithmIdentifierOwned {
            oid: DigestAlgorithm::Sha256.oid(),
            parameters: Some(der::Any::from_der(&[0x02, 0x01, 0x01]).unwrap()),
        }
        .to_der()
        .unwrap();
        for invalid in [
            [wrong_algorithm_tag, hash.clone()].concat(),
            [algorithm.clone(), wrong_hash_tag].concat(),
            [wrong_oid_tag, hash.clone()].concat(),
            [parameters, hash.clone()].concat(),
            [algorithm.clone(), der_utils::encode_tlv(0x04, &[0xAA; 31])].concat(),
            [body, vec![0x05, 0x00]].concat(),
        ] {
            assert!(parse_message_imprint(&invalid).is_err());
        }
        // Both common AlgorithmIdentifier parameter conventions stay accepted.
        let with_null = AlgorithmIdentifierOwned {
            oid: DigestAlgorithm::Sha256.oid(),
            parameters: Some(der::Any::null()),
        }
        .to_der()
        .unwrap();
        assert!(parse_message_imprint(&[with_null, hash].concat()).is_ok());
    }

    #[test]
    fn test_build_timestamp_request_basic() {
        let hash = vec![0xAA; 32]; // SHA-256 sized
        let req =
            build_timestamp_request(DigestAlgorithm::Sha256, &hash, None, None, true).unwrap();

        // Should be a valid DER SEQUENCE
        assert_eq!(req[0], 0x30, "should start with SEQUENCE tag");

        // Parse it back
        let (tag, _body) = der_utils::parse_tlv(&req).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_build_timestamp_request_with_nonce() {
        let hash = vec![0xBB; 32];
        let nonce = 12345678u64;
        let req = build_timestamp_request(DigestAlgorithm::Sha256, &hash, None, Some(nonce), true)
            .unwrap();

        let (tag, _body) = der_utils::parse_tlv(&req).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_encode_integer_u64() {
        // Encode 1
        let encoded = der_utils::encode_integer_u64(1);
        assert_eq!(encoded, vec![0x02, 0x01, 0x01]);

        // Encode 128 (needs padding because high bit set)
        let encoded = der_utils::encode_integer_u64(128);
        assert_eq!(encoded, vec![0x02, 0x02, 0x00, 0x80]);

        // Encode 0
        let encoded = der_utils::encode_integer_u64(0);
        // Should be 0x02 0x01 0x00
        assert_eq!(encoded, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_pki_status_display() {
        assert_eq!(PkiStatus::Granted.to_string(), "granted (0)");
        assert_eq!(PkiStatus::Rejection.to_string(), "rejection (2)");
        assert!(PkiStatus::Granted.is_success());
        assert!(PkiStatus::GrantedWithMods.is_success());
        assert!(!PkiStatus::Rejection.is_success());
    }

    #[test]
    fn test_der_length_roundtrip() {
        for len in [0, 1, 127, 128, 255, 256, 65535, 65536] {
            let mut buf = Vec::new();
            der_utils::encode_der_length(&mut buf, len);
            let (parsed_len, consumed) = der_utils::parse_der_length(&buf).unwrap();
            assert_eq!(parsed_len, len, "length roundtrip failed for {len}");
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_parse_timestamp_response_error_status() {
        // Build a minimal TimeStampResp with rejection status
        // PKIStatusInfo SEQUENCE { PKIStatus INTEGER 2 }
        let status_info = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(2));
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let resp = parse_timestamp_response(&resp_der).unwrap();
        assert_eq!(resp.status, PkiStatus::Rejection);
        assert!(resp.token_der.is_none());
    }

    #[test]
    fn test_parse_timestamp_response_accepts_status_text_and_failure_info() {
        let text = der_utils::encode_sequence_from_parts(&[
            &der_utils::encode_tlv(0x0C, b"unsupported algorithm"),
            &der_utils::encode_tlv(0x0C, "algorithm not supported: 算法".as_bytes()),
        ]);
        // badAlg is bit 0: seven unused bits in the final octet.
        let failure = der_utils::encode_tlv(0x03, &[7, 0x80]);
        let status = der_utils::encode_sequence_from_parts(&[
            &der_utils::encode_integer_u64(2),
            &text,
            &failure,
        ]);
        let response = der_utils::encode_sequence_raw(&status);
        let parsed = parse_timestamp_response(&response).unwrap();
        assert_eq!(
            parsed.status_string.as_deref(),
            Some("unsupported algorithm")
        );
        assert_eq!(parsed.failure_info.as_deref(), Some(&[7, 0x80][..]));
        // failureInfo is also permitted without the optional statusString.
        let status =
            der_utils::encode_sequence_from_parts(&[&der_utils::encode_integer_u64(2), &failure]);
        assert!(parse_timestamp_response(&der_utils::encode_sequence_raw(&status)).is_ok());
    }

    #[test]
    fn test_parse_timestamp_response_rejects_outer_trailing_and_ambiguous_status_fields() {
        let text = der_utils::encode_sequence_raw(&der_utils::encode_tlv(0x0C, b"rejected"));
        let failure = der_utils::encode_tlv(0x03, &[7, 0x80]);
        for optional in [
            vec![text.clone(), text.clone()],
            vec![failure.clone(), failure.clone()],
            vec![failure, text],
            vec![vec![0x05, 0x00]],
        ] {
            let mut status_fields = vec![der_utils::encode_integer_u64(2)];
            status_fields.extend(optional);
            let status = der_utils::encode_sequence_raw(&status_fields.concat());
            assert!(parse_timestamp_response(&der_utils::encode_sequence_raw(&status)).is_err());
        }
        let status = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(2));
        let mut response = der_utils::encode_sequence_raw(&status);
        response.extend_from_slice(&[0x05, 0x00]);
        assert!(matches!(
            parse_timestamp_response(&response),
            Err(TspError::InvalidResponse(message)) if message.contains("trailing")
        ));
    }

    #[test]
    fn test_parse_timestamp_response_rejects_malformed_failure_info() {
        for failure_body in [
            vec![],
            vec![8],       // unused-bits count exceeds seven
            vec![1],       // unused bits without a data octet
            vec![7, 0x81], // nonzero padding bits
        ] {
            let status = der_utils::encode_sequence_from_parts(&[
                &der_utils::encode_integer_u64(2),
                &der_utils::encode_tlv(0x03, &failure_body),
            ]);
            assert!(parse_timestamp_response(&der_utils::encode_sequence_raw(&status)).is_err());
        }
    }

    #[test]
    fn test_parse_timestamp_response_rejects_malformed_status_field() {
        // L-6: a structurally malformed element inside PKIStatusInfo must be a
        // hard error, not silently dropped. Status INTEGER 0 (granted) followed
        // by a SEQUENCE whose declared length overruns the buffer.
        let mut status_body = der_utils::encode_integer_u64(0);
        status_body.extend_from_slice(&[0x30, 0x05, 0x01]); // truncated SEQUENCE
        let status_info = der_utils::encode_sequence_raw(&status_body);
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("malformed PKIStatusInfo field must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "expected InvalidResponse, got {err:?}"
        );
    }

    /// Build a `TimeStampResp` whose PKIStatusInfo carries a rejection status
    /// and a `statusString` SEQUENCE wrapping a single element with `inner_tag`
    /// / `inner_body`, so tests can supply a non-UTF8String or invalid UTF-8.
    fn resp_with_status_string(inner_tag: u8, inner_body: &[u8]) -> Vec<u8> {
        let status_int = der_utils::encode_integer_u64(2); // rejection
        let free_text =
            der_utils::encode_sequence_raw(&der_utils::encode_tlv(inner_tag, inner_body));
        let mut status_body = status_int;
        status_body.extend_from_slice(&free_text);
        let status_info = der_utils::encode_sequence_raw(&status_body);
        der_utils::encode_sequence_raw(&status_info)
    }

    #[test]
    fn test_parse_timestamp_response_accepts_valid_status_string() {
        // A well-formed UTF8String statusString is decoded.
        let resp_der = resp_with_status_string(0x0C, "rejected: bad request".as_bytes());
        let resp = parse_timestamp_response(&resp_der).unwrap();
        assert_eq!(resp.status, PkiStatus::Rejection);
        assert_eq!(resp.status_string.as_deref(), Some("rejected: bad request"));
    }

    #[test]
    fn test_parse_timestamp_response_rejects_non_utf8string_status() {
        // L-6: PKIFreeText elements are UTF8String; an OCTET STRING (or any other
        // type) inside statusString must be rejected, not accepted blindly.
        let resp_der = resp_with_status_string(0x04, b"not a utf8string"); // OCTET STRING
        let err = parse_timestamp_response(&resp_der)
            .expect_err("non-UTF8String statusString must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("UTF8String")),
            "expected UTF8String tag rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_invalid_utf8_status() {
        // L-6: invalid UTF-8 inside a UTF8String must be rejected, not lossily
        // normalized.
        let resp_der = resp_with_status_string(0x0C, &[0xFF, 0xFE, 0xFD]);
        let err = parse_timestamp_response(&resp_der)
            .expect_err("invalid UTF-8 statusString must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("UTF-8")),
            "expected invalid-UTF-8 rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_malformed_trailing_status_element() {
        // L-6 (PR review): PKIFreeText is SEQUENCE OF UTF8String — EVERY element
        // must be validated, not just the first. A valid first UTF8String
        // followed by a non-UTF8String element must still be rejected.
        let status_int = der_utils::encode_integer_u64(2); // rejection
        let mut free_text_body = der_utils::encode_tlv(0x0C, b"ok");
        free_text_body.extend_from_slice(&der_utils::encode_tlv(0x04, b"bad")); // OCTET STRING
        let free_text = der_utils::encode_sequence_raw(&free_text_body);
        let mut status_body = status_int;
        status_body.extend_from_slice(&free_text);
        let status_info = der_utils::encode_sequence_raw(&status_body);
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("a trailing non-UTF8String statusString element must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("UTF8String")),
            "expected UTF8String rejection of the trailing element, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_empty_status_string() {
        // L-6 (PR review): PKIFreeText is SEQUENCE SIZE (1..MAX) OF UTF8String.
        // A present-but-empty statusString SEQUENCE violates the size constraint
        // and must be rejected rather than silently leaving status_string None.
        let status_int = der_utils::encode_integer_u64(2); // rejection
        let free_text = der_utils::encode_sequence_raw(&[]); // empty SEQUENCE
        let mut status_body = status_int;
        status_body.extend_from_slice(&free_text);
        let status_info = der_utils::encode_sequence_raw(&status_body);
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("an empty statusString SEQUENCE must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("empty")),
            "expected empty-PKIFreeText rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_trailing_bytes_after_token() {
        // L-6 (PR review): the TimeStampToken must consume all remaining bytes of
        // the TimeStampResp; trailing bytes after it are malformed.
        let status_info = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(0));
        let token = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(1)); // dummy SEQUENCE
        let mut body = status_info;
        body.extend_from_slice(&token);
        body.extend_from_slice(&der_utils::encode_integer_u64(9)); // trailing junk
        let resp_der = der_utils::encode_sequence_raw(&body);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("trailing bytes after the TimeStampToken must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("trailing")),
            "expected trailing-data rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_non_sequence_token() {
        // L-6: a non-SEQUENCE where the optional TimeStampToken is expected is
        // malformed and must be rejected rather than yielding token_der = None.
        let status_info = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(0));
        let mut body = status_info;
        // Append a bogus token: an INTEGER instead of a ContentInfo SEQUENCE.
        body.extend_from_slice(&der_utils::encode_integer_u64(7));
        let resp_der = der_utils::encode_sequence_raw(&body);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("non-SEQUENCE TimeStampToken must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "expected InvalidResponse, got {err:?}"
        );
    }

    #[test]
    fn test_generate_nonce() {
        let n1 = generate_nonce().unwrap();
        // Brief pause to ensure different nonce
        std::thread::sleep(std::time::Duration::from_millis(1));
        let n2 = generate_nonce().unwrap();
        // They should differ (with extremely high probability)
        assert_ne!(n1, n2, "nonces should be unique");
    }

    // ── RFC 3161 token signature verification (C-1 fix) ──────────────────

    use cms::cert::CertificateChoices;
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignerIdentifier, SignerInfo, SignerInfos,
    };
    use der::asn1::{Any, SetOfVec};
    use der::{Decode, Tag};
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;
    use spki::AlgorithmIdentifierOwned;
    use std::sync::OnceLock;
    use x509_cert::attr::Attribute;
    use x509_cert::Certificate;

    const INTERMEDIATE_CERT_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/intermediate_ca_cert.pem"
    ));
    const INTERMEDIATE_KEY_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/intermediate_ca_key.pem"
    ));
    const ROOT_CERT_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ca_cert.pem"
    ));

    fn load_cert(pem: &str) -> Certificate {
        let (_, der) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
        Certificate::from_der(&der).unwrap()
    }

    fn load_key(pem: &str) -> RsaPrivateKey {
        let der = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap().1;
        RsaPrivateKey::from_pkcs8_der(&der).unwrap()
    }

    fn intermediate_cert() -> Certificate {
        load_cert(INTERMEDIATE_CERT_PEM)
    }

    fn intermediate_key() -> RsaPrivateKey {
        load_key(INTERMEDIATE_KEY_PEM)
    }

    /// A TSA signing identity (certificate + private key) generated at runtime,
    /// so no private key is committed to the repository. The certificate carries
    /// a critical id-kp-timeStamping EKU and is issued by the committed
    /// intermediate CA, so it chains to the committed test root.
    struct TsaIdentity {
        cert: Certificate,
        key: RsaPrivateKey,
    }

    fn tsa_identity() -> &'static TsaIdentity {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Keypair;
        use sha2::Sha256;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        static ID: OnceLock<TsaIdentity> = OnceLock::new();
        ID.get_or_init(|| {
            // Generate the TSA keypair at runtime.
            let mut rng = rand::thread_rng();
            let tsa_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
            let tsa_signing = SigningKey::<Sha256>::new(tsa_key.clone());
            let spki = SubjectPublicKeyInfoOwned::from_key(tsa_signing.verifying_key())
                .expect("SPKI from key");

            // Issue the TSA cert from the committed intermediate CA.
            let issuer = intermediate_cert();
            let ca_signer = SigningKey::<Sha256>::new(intermediate_key());
            let profile = Profile::Leaf {
                issuer: issuer.tbs_certificate.subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            };
            let serial = SerialNumber::new(&[0x2A]).unwrap();
            // Valid from "now" for ~10 years; clock-derived genTimes fall inside.
            let validity =
                Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();
            let subject: Name = "CN=Runtime Test TSA,O=ritsp-ltv tests".parse().unwrap();

            let mut builder =
                CertificateBuilder::new(profile, serial, validity, subject, spki, &ca_signer)
                    .expect("cert builder");
            // Critical because the EKU set does not include anyExtendedKeyUsage.
            builder
                .add_extension(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]))
                .expect("add EKU");
            let cert = builder
                .build::<rsa::pkcs1v15::Signature>()
                .expect("sign cert");

            TsaIdentity { cert, key: tsa_key }
        })
    }

    fn tsa_cert() -> Certificate {
        tsa_identity().cert.clone()
    }

    fn tsa_key() -> RsaPrivateKey {
        tsa_identity().key.clone()
    }

    const SHA256_OID_DER: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];

    /// Format a chrono UTC instant as GeneralizedTime contents (YYYYMMDDHHMMSSZ).
    fn fmt_generalized(dt: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        dt.format("%Y%m%d%H%M%SZ").to_string().into_bytes()
    }

    /// A genTime inside the runtime TSA cert validity. The cert is valid from
    /// "now" for ~10 years, so the current instant is always inside. Derived
    /// from the clock (not a hard-coded calendar date) so tests don't expire.
    fn gen_time_within() -> Vec<u8> {
        fmt_generalized(chrono::Utc::now())
    }

    /// A genTime past the runtime TSA cert's notAfter (~now + 10y).
    fn gen_time_after_validity() -> Vec<u8> {
        fmt_generalized(chrono::Utc::now() + chrono::Duration::days(365 * 20))
    }

    /// A `der::DateTime` for "now", used as the chain validation time.
    fn validation_time() -> der::DateTime {
        use chrono::{Datelike, Timelike};
        let n = chrono::Utc::now();
        der::DateTime::new(
            n.year() as u16,
            n.month() as u8,
            n.day() as u8,
            n.hour() as u8,
            n.minute() as u8,
            n.second() as u8,
        )
        .unwrap()
    }

    /// Build a DER-encoded TSTInfo with the given message imprint hash, nonce,
    /// and genTime (GeneralizedTime contents, i.e. b"YYYYMMDDHHMMSSZ").
    fn build_tst_info(hash: &[u8], nonce: u64, gen_time_bytes: &[u8]) -> Vec<u8> {
        let version = der_utils::encode_integer_u64(1);
        // policy OID (arbitrary but well-formed)
        let policy = der_utils::encode_tlv(0x06, &[0x2B, 0x06, 0x01, 0x04, 0x01]);
        // messageImprint { AlgorithmIdentifier{ sha256, NULL }, OCTET STRING hash }
        let alg = der_utils::encode_sequence_from_parts(&[SHA256_OID_DER, &[0x05, 0x00]]);
        let hashed = der_utils::encode_tlv(0x04, hash);
        let message_imprint = der_utils::encode_sequence_from_parts(&[&alg, &hashed]);
        let serial = der_utils::encode_integer_u64(42);
        let gen_time = der_utils::encode_tlv(0x18, gen_time_bytes);
        let nonce_int = der_utils::encode_integer_u64(nonce);
        let body = [
            version,
            policy,
            message_imprint,
            serial,
            gen_time,
            nonce_int,
        ]
        .concat();
        der_utils::encode_sequence_raw(&body)
    }

    fn null_params() -> Option<Any> {
        Some(Any::null())
    }

    /// Build a fully-formed CMS TimeStampToken (ContentInfo/SignedData) signed
    /// by `signer_key`, embedding `signer_cert` plus `extra_certs`.
    ///
    /// If `corrupt_sig` is true, the signature is computed over the wrong bytes
    /// so the token's signature will not verify.
    fn build_signed_token(
        signer_cert: &Certificate,
        signer_key: &RsaPrivateKey,
        extra_certs: &[Certificate],
        hash: &[u8],
        nonce: u64,
        corrupt_sig: bool,
    ) -> Vec<u8> {
        build_signed_token_gt(
            signer_cert,
            signer_key,
            extra_certs,
            hash,
            nonce,
            &gen_time_within(),
            true,
            corrupt_sig,
        )
    }

    /// Like [`build_signed_token`] but with an explicit genTime and control over
    /// whether the certificates are embedded (`embed_certs`), for testing the
    /// genTime-within-validity check and externally-supplied signer certs.
    #[allow(clippy::too_many_arguments)]
    fn build_signed_token_gt(
        signer_cert: &Certificate,
        signer_key: &RsaPrivateKey,
        extra_certs: &[Certificate],
        hash: &[u8],
        nonce: u64,
        gen_time_bytes: &[u8],
        embed_certs: bool,
        corrupt_sig: bool,
    ) -> Vec<u8> {
        use rsa::pkcs1v15::{Signature, SigningKey};
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::{Digest, Sha256};

        let tst_info_der = build_tst_info(hash, nonce, gen_time_bytes);

        // Signed attributes: content-type = id-ct-TSTInfo, message-digest = SHA256(eContent)
        let digest = Sha256::digest(&tst_info_der).to_vec();
        let ct_value = Any::encode_from(&ID_CT_TST_INFO).unwrap();
        let ct_attr = Attribute {
            oid: ID_CONTENT_TYPE_ATTR,
            values: SetOfVec::try_from(vec![ct_value]).unwrap(),
        };
        let md_value = Any::new(Tag::OctetString, digest).unwrap();
        let md_attr = Attribute {
            oid: ID_MESSAGE_DIGEST_ATTR,
            values: SetOfVec::try_from(vec![md_value]).unwrap(),
        };
        let cert_hash = Sha256::digest(signer_cert.to_der().unwrap());
        let ess_id = der_utils::encode_sequence_raw(&der_utils::encode_tlv(0x04, &cert_hash));
        let ess = der_utils::encode_sequence_raw(&der_utils::encode_sequence_raw(&ess_id));
        let ess_attr = Attribute {
            oid: ID_SIGNING_CERTIFICATE_V2,
            values: SetOfVec::try_from(vec![Any::from_der(&ess).unwrap()]).unwrap(),
        };
        let signed_attrs: x509_cert::attr::Attributes =
            SetOfVec::try_from(vec![ct_attr, md_attr, ess_attr]).unwrap();

        // Sign the DER of the SET OF signed attributes (RFC 5652 §5.4).
        let signed_attrs_der = signed_attrs.to_der().unwrap();
        let signing_key = SigningKey::<Sha256>::new(signer_key.clone());
        let to_sign: &[u8] = if corrupt_sig {
            b"not the signed attributes"
        } else {
            &signed_attrs_der
        };
        let signature: Signature = signing_key.sign(to_sign);

        let sha256_alg = AlgorithmIdentifierOwned {
            oid: DigestAlgorithm::Sha256.oid(),
            parameters: null_params(),
        };
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
                issuer: signer_cert.tbs_certificate.issuer.clone(),
                serial_number: signer_cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: sha256_alg.clone(),
            signed_attrs: Some(signed_attrs),
            // bare rsaEncryption — exercises resolve_cms_signature_oid()
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: OID_RSA_ENCRYPTION,
                parameters: null_params(),
            },
            signature: OctetString::new(signature.to_vec()).unwrap(),
            unsigned_attrs: None,
        };

        // Embedded certificates (optional): signer first, then any extras.
        let certificates = if embed_certs {
            let mut cert_choices = vec![CertificateChoices::Certificate(signer_cert.clone())];
            for cert in extra_certs {
                cert_choices.push(CertificateChoices::Certificate(cert.clone()));
            }
            Some(CertificateSet::from(
                SetOfVec::try_from(cert_choices).unwrap(),
            ))
        } else {
            None
        };

        let signed_data = cms::signed_data::SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![sha256_alg]).unwrap(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(Any::new(Tag::OctetString, tst_info_der).unwrap()),
            },
            certificates,
            crls: None,
            signer_infos: SignerInfos::from(SetOfVec::try_from(vec![signer_info]).unwrap()),
        };

        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).unwrap(),
        };
        content_info.to_der().unwrap()
    }

    fn ess_attribute(
        cert: &Certificate,
        v2: bool,
        algorithm: Option<DigestAlgorithm>,
        issuer_serial: bool,
    ) -> Attribute {
        let der = cert.to_der().unwrap();
        let digest = if v2 {
            algorithm.unwrap_or(DigestAlgorithm::Sha256).into()
        } else {
            riptering::HashAlgorithm::Sha1
        };
        let hash = riptering::digest::digest(digest, &der).unwrap();
        let mut id = Vec::new();
        if let Some(algorithm) = algorithm {
            id.extend_from_slice(&digest_algorithm_identifier(algorithm).to_der().unwrap());
        }
        id.extend_from_slice(&der_utils::encode_tlv(0x04, &hash));
        if issuer_serial {
            let issuer =
                der_utils::encode_tlv(0xA4, &cert.tbs_certificate.issuer.to_der().unwrap());
            let names = der_utils::encode_sequence_raw(&issuer);
            let serial = cert.tbs_certificate.serial_number.to_der().unwrap();
            id.extend_from_slice(&der_utils::encode_sequence_from_parts(&[&names, &serial]));
        }
        let value = der_utils::encode_sequence_raw(&der_utils::encode_sequence_raw(
            &der_utils::encode_sequence_raw(&id),
        ));
        Attribute {
            oid: if v2 {
                ID_SIGNING_CERTIFICATE_V2
            } else {
                ID_SIGNING_CERTIFICATE
            },
            values: SetOfVec::try_from(vec![Any::from_der(&value).unwrap()]).unwrap(),
        }
    }

    /// Re-sign a small local token fixture after changing authenticated fields.
    /// These tests verify rejection/acceptance at the public verifier boundary.
    fn rewrite_signed_fixture(
        token: &[u8],
        attributes: Option<Vec<Attribute>>,
        tsa: Option<&[u8]>,
    ) -> Vec<u8> {
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::{Digest, Sha256};
        let mut ci = ContentInfo::from_der(token).unwrap();
        let mut sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
        let mut si = sd.signer_infos.0.iter().next().unwrap().clone();
        let mut attrs: Vec<_> = si.signed_attrs.as_ref().unwrap().iter().cloned().collect();
        if let Some(attributes) = attributes {
            attrs.retain(|a| a.oid != ID_SIGNING_CERTIFICATE && a.oid != ID_SIGNING_CERTIFICATE_V2);
            attrs.extend(attributes);
        }
        if let Some(tsa) = tsa {
            let content = sd.encap_content_info.econtent.as_ref().unwrap().value();
            let (sequence, _) = parse_tst_field(content, 0x30, "test TSTInfo").unwrap();
            let body = [sequence.value(), &der_utils::encode_tlv(0xA0, tsa)].concat();
            let content = der_utils::encode_sequence_raw(&body);
            let digest = Sha256::digest(&content).to_vec();
            attrs.retain(|a| a.oid != ID_MESSAGE_DIGEST_ATTR);
            attrs.push(Attribute {
                oid: ID_MESSAGE_DIGEST_ATTR,
                values: SetOfVec::try_from(vec![Any::new(Tag::OctetString, digest).unwrap()])
                    .unwrap(),
            });
            sd.encap_content_info.econtent = Some(Any::new(Tag::OctetString, content).unwrap());
        }
        si.signed_attrs = Some(SetOfVec::try_from(attrs).unwrap());
        let signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(tsa_key());
        let signature: rsa::pkcs1v15::Signature =
            signing.sign(&si.signed_attrs.as_ref().unwrap().to_der().unwrap());
        si.signature = OctetString::new(signature.to_vec()).unwrap();
        sd.signer_infos = SignerInfos::from(SetOfVec::try_from(vec![si]).unwrap());
        ci.content = Any::encode_from(&sd).unwrap();
        ci.to_der().unwrap()
    }

    #[test]
    fn test_ess_v1_v2_bind_hash_issuer_and_serial_and_require_signed_attribute() {
        let cert = tsa_cert();
        let hash = [0x4A; 32];
        let token = build_signed_token(&cert, &tsa_key(), &[], &hash, 7, false);
        for attributes in [
            vec![ess_attribute(&cert, false, None, true)],
            vec![ess_attribute(&cert, true, None, false)],
            vec![ess_attribute(
                &cert,
                true,
                Some(DigestAlgorithm::Sha384),
                true,
            )],
            vec![
                ess_attribute(&cert, false, None, true),
                ess_attribute(&cert, true, None, true),
            ],
        ] {
            let fixture = rewrite_signed_fixture(&token, Some(attributes), None);
            verify_timestamp_token(
                &fixture,
                &hash,
                DigestAlgorithm::Sha256,
                Some(7),
                None,
                None,
                &[],
            )
            .unwrap();
        }
        let mut other_serial = cert.clone();
        other_serial.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[99]).unwrap();
        let mut other_issuer = cert.clone();
        other_issuer.tbs_certificate.issuer = "CN=Other Issuer".parse().unwrap();
        for invalid in [
            vec![],
            vec![ess_attribute(&other_serial, true, None, true)],
            vec![ess_attribute(&other_issuer, true, None, true)],
            vec![
                ess_attribute(&cert, false, None, false),
                ess_attribute(&other_serial, true, None, false),
            ],
            vec![
                ess_attribute(&cert, true, None, false),
                ess_attribute(&other_serial, true, None, false),
            ],
        ] {
            let fixture = rewrite_signed_fixture(&token, Some(invalid), None);
            assert!(verify_timestamp_token(
                &fixture,
                &hash,
                DigestAlgorithm::Sha256,
                Some(7),
                None,
                None,
                &[]
            )
            .is_err());
        }
        // Isolate issuer/serial matching independently of the certificate hash.
        let value = ess_attribute(&cert, true, None, true);
        let mut binding = parse_ess_binding(value.values.iter().next().unwrap(), true).unwrap();
        binding.issuer_serial.as_mut().unwrap().1 = other_serial.tbs_certificate.serial_number;
        assert!(!binding.matches(&cert).unwrap());
        binding.issuer_serial.as_mut().unwrap().0 = other_issuer.tbs_certificate.issuer;
        binding.issuer_serial.as_mut().unwrap().1 = cert.tbs_certificate.serial_number.clone();
        assert!(!binding.matches(&cert).unwrap());
    }

    #[test]
    fn test_ess_rejects_unsupported_restrictions_and_malformed_fields() {
        let id = der_utils::encode_sequence_raw(&der_utils::encode_tlv(0x04, &[0x11; 32]));
        let certs = der_utils::encode_sequence_raw(&id);
        for value in [
            der_utils::encode_sequence_raw(&der_utils::encode_sequence_raw(&[])),
            der_utils::encode_sequence_raw(&der_utils::encode_sequence_from_parts(&[&id, &id])),
            der_utils::encode_sequence_from_parts(&[&certs, &[0x30, 0x00]]),
            der_utils::encode_sequence_raw(&der_utils::encode_sequence_raw(
                &der_utils::encode_sequence_raw(&der_utils::encode_tlv(0x04, &[0x11; 31])),
            )),
        ] {
            assert!(parse_ess_binding(&Any::from_der(&value).unwrap(), true).is_err());
        }
    }

    #[test]
    fn test_timestamp_key_usage_and_eku_must_both_permit_signing() {
        let hash = [0x4E; 32];
        let oid = ObjectIdentifier::new_unwrap("2.5.29.15");
        for (value, allowed) in [
            (vec![0x03, 0x02, 0x00, 0x80], true),
            (vec![0x03, 0x02, 0x00, 0x40], true),
            (vec![0x03, 0x02, 0x00, 0x20], false),
            (vec![0x03, 0x02, 0x01, 0x81], false),
            (vec![0x03, 0x02, 0x00, 0x00], false),
            (vec![0x03, 0x02, 0x00, 0x80, 0x05, 0x00], false),
        ] {
            for critical in [true, false] {
                let mut cert = tsa_cert();
                cert.tbs_certificate
                    .extensions
                    .as_mut()
                    .unwrap()
                    .retain(|e| e.extn_id != oid);
                cert.tbs_certificate
                    .extensions
                    .as_mut()
                    .unwrap()
                    .push(x509_cert::ext::Extension {
                        extn_id: oid,
                        critical,
                        extn_value: OctetString::new(value.clone()).unwrap(),
                    });
                let token = build_signed_token(&cert, &tsa_key(), &[], &hash, 11, false);
                assert_eq!(
                    verify_timestamp_token(
                        &token,
                        &hash,
                        DigestAlgorithm::Sha256,
                        Some(11),
                        None,
                        None,
                        &[]
                    )
                    .is_ok(),
                    allowed
                );
                #[cfg(feature = "ltv")]
                assert_eq!(
                    crate::ltv::validate_extensions_for_role(
                        &cert,
                        crate::ltv::CertRole::TimestampSigner
                    )
                    .is_ok(),
                    allowed
                );
            }
        }
    }

    #[test]
    fn test_ess_selects_exact_certificate_and_rejects_unsigned_binding() {
        let cert = tsa_cert();
        let hash = [0x4D; 32];
        let token = build_signed_token(&cert, &tsa_key(), &[], &hash, 10, false);
        let mut ci = ContentInfo::from_der(&token).unwrap();
        let mut sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
        let mut substituted = cert.clone();
        substituted.signature = der::asn1::BitString::from_bytes(&[0x11; 256]).unwrap();
        sd.certificates = Some(CertificateSet::from(
            SetOfVec::try_from(vec![CertificateChoices::Certificate(substituted)]).unwrap(),
        ));
        ci.content = Any::encode_from(&sd).unwrap();
        let token = ci.to_der().unwrap();
        assert!(verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(10),
            None,
            None,
            &[]
        )
        .is_err());
        // The out-of-band original has identical TBS but distinct full DER.
        verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(10),
            None,
            None,
            std::slice::from_ref(&cert),
        )
        .unwrap();
        let mut si = sd.signer_infos.0.iter().next().unwrap().clone();
        si.unsigned_attrs =
            Some(SetOfVec::try_from(vec![ess_attribute(&cert, true, None, false)]).unwrap());
        sd.signer_infos = SignerInfos::from(SetOfVec::try_from(vec![si]).unwrap());
        ci.content = Any::encode_from(&sd).unwrap();
        let err = verify_timestamp_token(
            &ci.to_der().unwrap(),
            &hash,
            DigestAlgorithm::Sha256,
            Some(10),
            None,
            None,
            &[cert],
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be signed"));
    }

    #[test]
    fn test_authenticated_tsa_must_match_signer_subject_or_san() {
        let hash = [0x4B; 32];
        let cert = tsa_cert();
        let token = build_signed_token(&cert, &tsa_key(), &[], &hash, 8, false);
        let subject = der_utils::encode_tlv(0xA4, &cert.tbs_certificate.subject.to_der().unwrap());
        let valid = rewrite_signed_fixture(&token, None, Some(&subject));
        verify_timestamp_token(
            &valid,
            &hash,
            DigestAlgorithm::Sha256,
            Some(8),
            None,
            None,
            &[],
        )
        .unwrap();
        for name in [
            der_utils::encode_tlv(0x82, b"other.example"),
            vec![0xA3, 0x02, 0x30, 0x00],
        ] {
            let invalid = rewrite_signed_fixture(&token, None, Some(&name));
            assert!(verify_timestamp_token(
                &invalid,
                &hash,
                DigestAlgorithm::Sha256,
                Some(8),
                None,
                None,
                &[]
            )
            .is_err());
        }
        let mut cert = cert;
        let dns = der_utils::encode_tlv(0x82, b"TSA.example");
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(x509_cert::ext::Extension {
                extn_id: ObjectIdentifier::new_unwrap("2.5.29.17"),
                critical: false,
                extn_value: OctetString::new(der_utils::encode_sequence_raw(&dns)).unwrap(),
            });
        let token = build_signed_token(&cert, &tsa_key(), &[], &hash, 8, false);
        let valid = rewrite_signed_fixture(
            &token,
            None,
            Some(&der_utils::encode_tlv(0x82, b"tsa.example")),
        );
        verify_timestamp_token(
            &valid,
            &hash,
            DigestAlgorithm::Sha256,
            Some(8),
            None,
            None,
            &[],
        )
        .unwrap();
    }

    #[test]
    fn test_fractional_gen_time_and_exact_validity_end_boundary() {
        let cert = tsa_cert();
        let hash = [0x4C; 32];
        let seconds = gen_time_within();
        let fraction = [&seconds[..14], b".123456789123Z"].concat();
        let token = build_signed_token_gt(&cert, &tsa_key(), &[], &hash, 9, &fraction, true, false);
        let parsed = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(9),
            None,
            None,
            &[],
        )
        .unwrap();
        assert_eq!(parsed.gen_time_der, fraction);
        let end = cert.tbs_certificate.validity.not_after.to_date_time();
        let end = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            end.year(),
            end.month(),
            end.day(),
            end.hour(),
            end.minutes(),
            end.seconds()
        );
        let token = build_signed_token_gt(
            &cert,
            &tsa_key(),
            &[],
            &hash,
            9,
            format!("{end}.1Z").as_bytes(),
            true,
            false,
        );
        assert!(verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(9),
            None,
            None,
            &[]
        )
        .is_err());
        for invalid in [
            b"20260303120000.10Z".as_slice(),
            b"20260303120000,Z",
            b"20260303120000.Z",
            b"20260303120000.0Z",
        ] {
            let mut fields = synthetic_tst_info_fields();
            fields[4] = der_utils::encode_tlv(0x18, invalid);
            let info = parse_tst_info_body(&synthetic_tst_info(&fields)).unwrap();
            assert!(gen_time_datetime(&info).is_err());
        }
    }

    #[test]
    fn test_verify_valid_token_no_trust_store() {
        let hash = vec![0xABu8; 32];
        let nonce = 0xDEAD_BEEFu64;
        let token = build_signed_token(&tsa_cert(), &tsa_key(), &[], &hash, nonce, false);

        let tst = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(nonce),
            None,
            None,
            &[],
        )
        .expect("validly-signed token must verify");
        assert_eq!(tst.message_hash, hash);
        assert_eq!(tst.nonce, Some(nonce));
    }

    #[test]
    fn test_verify_valid_token_with_trust_store() {
        let hash = vec![0x11u8; 32];
        let nonce = 7u64;
        // Embed the intermediate so the chain reaches the root anchor.
        let token = build_signed_token(
            &tsa_cert(),
            &tsa_key(),
            &[intermediate_cert()],
            &hash,
            nonce,
            false,
        );

        let mut store = TrustStore::new();
        let (_, root_der) = pem_rfc7468::decode_vec(ROOT_CERT_PEM.as_bytes()).unwrap();
        store.add_der_certificate(&root_der).unwrap();

        let tst = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(nonce),
            Some(&store),
            Some(validation_time()),
            &[],
        )
        .expect("token chaining to a trusted root must verify");
        assert_eq!(tst.message_hash, hash);
    }

    #[test]
    fn test_trust_store_validation_time_defaults_to_gen_time() {
        // With a trust store but validation_time = None, the chain must still be
        // verified using the token's genTime (not skipped). genTime is "now",
        // within every cert's validity, so this must succeed.
        let hash = vec![0x88u8; 32];
        let token = build_signed_token(
            &tsa_cert(),
            &tsa_key(),
            &[intermediate_cert()],
            &hash,
            1,
            false,
        );
        let mut store = TrustStore::new();
        let (_, root_der) = pem_rfc7468::decode_vec(ROOT_CERT_PEM.as_bytes()).unwrap();
        store.add_der_certificate(&root_der).unwrap();

        verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            Some(&store),
            None, // -> defaults to genTime
            &[],
        )
        .expect("chain must verify at genTime when validation_time is None");
    }

    #[test]
    fn test_reject_gen_time_outside_validity_without_trust_store() {
        // genTime ~20 years out is past the TSA cert's notAfter (~now + 10y).
        // This must be rejected even when no trust store is supplied (RFC 3161).
        let hash = vec![0x77u8; 32];
        let token = build_signed_token_gt(
            &tsa_cert(),
            &tsa_key(),
            &[],
            &hash,
            1,
            &gen_time_after_validity(),
            true,  // embed certs
            false, // valid signature
        );
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "genTime outside TSA cert validity must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_tampered_signature() {
        let hash = vec![0x22u8; 32];
        let token = build_signed_token(&tsa_cert(), &tsa_key(), &[], &hash, 1, true);
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "tampered signature must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_untrusted_root() {
        // Token is validly signed but the trust store does NOT contain the root.
        let hash = vec![0x33u8; 32];
        let token = build_signed_token(
            &tsa_cert(),
            &tsa_key(),
            &[intermediate_cert()],
            &hash,
            1,
            false,
        );
        let empty_store = TrustStore::new();
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            Some(&empty_store),
            Some(validation_time()),
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "token not chaining to a trust anchor must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_signer_without_timestamping_eku() {
        // Sign with the intermediate CA key and present the intermediate CA cert
        // as the signer. The signature verifies, but the cert lacks the critical
        // id-kp-timeStamping EKU, so verification must fail.
        let hash = vec![0x44u8; 32];
        let token = build_signed_token(
            &intermediate_cert(),
            &intermediate_key(),
            &[],
            &hash,
            1,
            false,
        );
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "signer without timeStamping EKU must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_ca_signer_with_timestamping_eku() {
        // A CA certificate (basicConstraints cA:TRUE) that also carries a
        // critical id-kp-timeStamping EKU. The signature verifies and the EKU
        // check passes, so only the not-a-CA profile check can reject it. This
        // runs on the always-compiled CMS path (no trust store, no `ltv`), so
        // it proves both build configurations enforce the TSA-must-not-be-a-CA
        // requirement (PR #17 review).
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Keypair;
        use sha2::Sha256;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let ca_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let ca_signing = SigningKey::<Sha256>::new(ca_key.clone());
        let spki = SubjectPublicKeyInfoOwned::from_key(ca_signing.verifying_key()).expect("SPKI");
        let subject: Name = "CN=Rogue CA TSA,O=ritsp-ltv tests".parse().unwrap();
        let validity =
            Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();
        // Profile::Root emits basicConstraints cA:TRUE and self-signs.
        let mut builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::new(&[0x77]).unwrap(),
            validity,
            subject,
            spki,
            &ca_signing,
        )
        .expect("cert builder");
        builder
            .add_extension(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]))
            .expect("add EKU");
        let ca_cert = builder
            .build::<rsa::pkcs1v15::Signature>()
            .expect("sign cert");

        let hash = vec![0x66u8; 32];
        let token = build_signed_token(&ca_cert, &ca_key, &[], &hash, 1, false);
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(ref m) if m.contains("CA:TRUE")),
            "CA certificate must be rejected as a TSA signer, got {err:?}"
        );
    }

    #[test]
    fn test_reject_unsigned_token_old_behavior() {
        // A token with no SignerInfo — the kind the old (vulnerable) code would
        // have accepted because it only parsed TSTInfo. Must now be rejected.
        let hash = vec![0x55u8; 32];
        let tst_info_der = build_tst_info(&hash, 1, &gen_time_within());
        let signed_data = cms::signed_data::SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::new(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(Any::new(Tag::OctetString, tst_info_der).unwrap()),
            },
            certificates: None,
            crls: None,
            signer_infos: SignerInfos::from(SetOfVec::<SignerInfo>::new()),
        };
        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).unwrap(),
        };
        let token = content_info.to_der().unwrap();

        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "unsigned token must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_garbage_token() {
        let err = verify_timestamp_token(
            &[0x30, 0x03, 0x02, 0x01, 0x01],
            &[0u8; 32],
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, TspError::InvalidResponse(_)));
    }

    #[test]
    fn test_reject_wrong_message_imprint() {
        // Validly signed, but the caller expected a different hash than the one
        // in the (authenticated) TSTInfo.
        let real_hash = vec![0x66u8; 32];
        let token = build_signed_token(&tsa_cert(), &tsa_key(), &[], &real_hash, 1, false);
        let expected = vec![0x99u8; 32];
        let err = verify_timestamp_token(
            &token,
            &expected,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, TspError::InvalidResponse(_)));
    }

    /// Build an RSASSA-PSS `signatureAlgorithm` (OID + `RSASSA-PSS-params`) for
    /// the given hash and salt length, mirroring what a TSA emits.
    fn pss_algid<D>(salt_len: u8) -> AlgorithmIdentifierOwned
    where
        D: const_oid::AssociatedOid,
    {
        use rsa::pkcs1::RsaPssParams;
        let params = RsaPssParams::new::<D>(salt_len);
        let params_der = params.to_der().unwrap();
        AlgorithmIdentifierOwned {
            oid: OID_RSASSA_PSS,
            parameters: Some(der::Any::from_der(&params_der).unwrap()),
        }
    }

    #[test]
    fn test_pss_signature_bound_to_signerinfo_digest() {
        use rsa::pkcs8::EncodePublicKey;
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use sha2::Sha256;

        let key = tsa_key();
        let spki_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // Sign with RSA-PSS / SHA-256 using the default salt length (= 32).
        let signing = SigningKey::<Sha256>::new(key);
        let msg = b"the DER-encoded signed attributes";
        let mut rng = rand::thread_rng();
        let sig = signing.sign_with_rng(&mut rng, msg).to_vec();

        let algid = pss_algid::<Sha256>(32);

        // Verification bound to SHA-256 (matching SignerInfo.digestAlgorithm) succeeds.
        verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha256)
            .expect("PSS-SHA256 signature must verify when bound to SHA-256");

        // Verification bound to a different digest must NOT accept the signature
        // (previously the code tried multiple hashes and could mis-accept).
        assert!(
            verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha384).is_err(),
            "PSS signature must be rejected when the bound digest does not match"
        );
    }

    #[test]
    fn test_pss_signature_honours_nondefault_salt_length() {
        // Regression: PSS verification must use the saltLength from
        // RSASSA-PSS-params, not assume the default (= digest size). A token
        // signed with a non-default salt length must still verify.
        use rsa::pkcs8::EncodePublicKey;
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use sha2::Sha256;

        let key = tsa_key();
        let spki_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // Sign with a 48-byte salt (default for SHA-256 is 32).
        let signing = SigningKey::<Sha256>::new_with_salt_len(key, 48);
        let msg = b"the DER-encoded signed attributes";
        let mut rng = rand::thread_rng();
        let sig = signing.sign_with_rng(&mut rng, msg).to_vec();

        // With the matching saltLength in the params, verification succeeds.
        let algid = pss_algid::<Sha256>(48);
        let matching = verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha256);
        #[cfg(feature = "aws-lc")]
        assert!(
            matches!(matching, Err(TrustError::UnsupportedAlgorithm(ref message)) if message.contains("salt length 48")),
            "AWS-LC must report non-digest-length PSS salt as unsupported: {matching:?}"
        );
        #[cfg(not(feature = "aws-lc"))]
        matching.expect("PSS signature with non-default salt must verify when params declare it");

        // Declaring the wrong (default) salt length must fail: the parameters
        // are authoritative and PSS verification is salt-length sensitive.
        let wrong = pss_algid::<Sha256>(32);
        assert!(
            verify_cms_signature(msg, &sig, &spki_der, &wrong, DigestAlgorithm::Sha256).is_err(),
            "PSS signature must not verify when the declared salt length is wrong"
        );
    }

    #[test]
    fn test_pss_signature_requires_parameters() {
        // A bare RSASSA-PSS OID with no parameters is non-compliant (RFC 4055):
        // the hash/MGF/salt are undefined, so reject rather than guess defaults.
        let bare = AlgorithmIdentifierOwned {
            oid: OID_RSASSA_PSS,
            parameters: None,
        };
        let err =
            verify_cms_signature(b"x", b"y", b"z", &bare, DigestAlgorithm::Sha256).unwrap_err();
        assert!(
            matches!(err, TrustError::UnsupportedAlgorithm(_)),
            "PSS without parameters must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_combined_sig_algorithm_hash_must_match_digest_algorithm() {
        // Regression: a token whose signatureAlgorithm encodes a different hash
        // than SignerInfo.digestAlgorithm must be rejected, even though both the
        // signature and the message-digest attribute would individually verify.
        use const_oid::db;
        use rsa::pkcs1v15::{Signature, SigningKey};
        use rsa::pkcs8::EncodePublicKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;

        let key = tsa_key();
        let spki_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // A genuine sha256WithRSAEncryption signature.
        let signing = SigningKey::<Sha256>::new(key);
        let msg = b"the DER-encoded signed attributes";
        let sig: Signature = signing.sign(msg);
        let sig = sig.to_vec();

        let algid = AlgorithmIdentifierOwned {
            oid: db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: None,
        };

        // Consistent: signatureAlgorithm hash == digestAlgorithm -> verifies.
        verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha256)
            .expect("sha256WithRSA must verify when digestAlgorithm is SHA-256");

        // Inconsistent: digestAlgorithm = SHA-512 but signatureAlgorithm encodes
        // SHA-256. Must be rejected up front, not silently accepted.
        let err = verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha512)
            .unwrap_err();
        assert!(
            matches!(err, TrustError::SignatureVerification(ref m) if m.contains("disagrees")),
            "mismatched signatureAlgorithm/digestAlgorithm must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_verify_token_without_embedded_certs_via_extra_certs() {
        // A token that omits the CMS certificates field (e.g. certReq=false).
        // It cannot be verified on its own, but succeeds when the signer cert is
        // supplied out-of-band through `extra_certs`.
        let hash = vec![0xC0u8; 32];
        let token = build_signed_token_gt(
            &tsa_cert(),
            &tsa_key(),
            &[],
            &hash,
            1,
            &gen_time_within(),
            false, // do NOT embed certificates
            false,
        );

        // Without the cert there is no key to check the signature; this is
        // reported as InvalidResponse (missing material), not a crypto failure.
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "token without certs and no extra_certs must fail as InvalidResponse, got {err:?}"
        );

        // Supplying the signer cert out-of-band lets it verify.
        let tst = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[tsa_cert()],
        )
        .expect("token must verify with externally-supplied signer cert");
        assert_eq!(tst.message_hash, hash);
    }

    /// Regression for the ambiguous-embedded-chain case: when several embedded
    /// certs share the issuer's subject, `order_chain` must prefer the one whose
    /// key actually signed the current cert. Under `allow_legacy` a SHA-1 link
    /// is valid and must win over a same-subject decoy that the strict precheck
    /// would otherwise let it fall back to.
    #[test]
    fn test_order_chain_prefers_legacy_valid_issuer_among_same_subject_candidates() {
        use crate::crypto::verify::SignaturePolicy;
        use der::asn1::BitString;
        use der::{Any, Decode, Encode};
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Keypair;
        use rsa::{Pkcs1v15Sign, RsaPrivateKey};
        use sha1::{Digest as _, Sha1};
        use sha2::Sha256;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let validity =
            Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();
        let issuer_name: Name = "CN=Ambiguous Issuer,O=ritsp-ltv tests".parse().unwrap();

        let self_signed = |name: &Name, key: &RsaPrivateKey, serial: u8| {
            let signer = SigningKey::<Sha256>::new(key.clone());
            let spki = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap();
            CertificateBuilder::new(
                Profile::Root,
                SerialNumber::new(&[serial]).unwrap(),
                validity,
                name.clone(),
                spki,
                &signer,
            )
            .unwrap()
            .build()
            .unwrap()
        };

        // Real issuer and a decoy sharing the same subject but a different key.
        let real_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let real_issuer = self_signed(&issuer_name, &real_key, 0x01);
        let decoy_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let decoy = self_signed(&issuer_name, &decoy_key, 0x02);

        // Leaf issued by the real issuer, re-signed with SHA-1.
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_spki = SubjectPublicKeyInfoOwned::from_key(
            SigningKey::<Sha256>::new(leaf_key).verifying_key(),
        )
        .unwrap();
        let real_signer = SigningKey::<Sha256>::new(real_key.clone());
        let base = CertificateBuilder::new(
            Profile::Leaf {
                issuer: issuer_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::new(&[0x03]).unwrap(),
            validity,
            "CN=Ambiguous Leaf,O=ritsp-ltv tests".parse().unwrap(),
            leaf_spki,
            &real_signer,
        )
        .unwrap()
        .build()
        .unwrap();
        // Set the inner tbsCertificate.signature to SHA-1 too, so the leaf is
        // well-formed (outer == inner per RFC 5280 §4.1.1.2) and genuinely
        // SHA-1-signed — otherwise verify (under allow_legacy) would reject it on
        // the signatureAlgorithm-mismatch check (L-5) before reaching the curve.
        let sha1_algid = AlgorithmIdentifierOwned {
            oid: crate::crypto::algorithm::OID_SHA1_WITH_RSA,
            parameters: Some(Any::from_der(&[0x05, 0x00]).unwrap()),
        };
        let mut tbs = base.tbs_certificate.clone();
        tbs.signature = sha1_algid.clone();
        let tbs_der = tbs.to_der().unwrap();
        let hash = Sha1::digest(&tbs_der);
        let sig = real_key
            .sign(Pkcs1v15Sign::new::<Sha1>(), &hash)
            .expect("SHA-1 RSA sign");
        let leaf = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sha1_algid,
            signature: BitString::from_bytes(&sig).unwrap(),
        };

        // Decoy first, so the strict fallback (first name match) picks it.
        let embedded = vec![decoy.clone(), real_issuer.clone()];
        let real_spki = real_issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let decoy_spki = decoy
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();

        // Strict: the SHA-1 link can't be verified, so order_chain falls back to
        // the first same-subject match — the wrong (decoy) cert.
        let strict = order_chain(&leaf, &embedded, SignaturePolicy::strict());
        assert_eq!(strict.len(), 2);
        assert_eq!(
            strict[1]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            decoy_spki,
            "strict precheck falls back to the wrong same-subject cert"
        );

        // allow_legacy: order_chain prefers the cryptographically-correct issuer.
        let legacy = order_chain(&leaf, &embedded, SignaturePolicy::allow_legacy());
        assert_eq!(legacy.len(), 2);
        assert_eq!(
            legacy[1]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            real_spki,
            "allow_legacy prefers the issuer whose key actually signed the leaf"
        );
    }
}
