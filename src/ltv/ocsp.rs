//! OCSP client, response parsing, and revocation checking.
//!
//! Builds OCSP requests (with optional nonce), sends them to OCSP responders
//! discovered from certificate AIA extensions, parses responses per RFC 6960,
//! verifies responder signatures, and checks revocation status.
//!
//! # RFC 6960 Structure (simplified)
//!
//! ```text
//! OCSPResponse ::= SEQUENCE {
//!     responseStatus   OCSPResponseStatus (ENUMERATED),
//!     responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL
//! }
//! ResponseBytes ::= SEQUENCE {
//!     responseType     OID (id-pkix-ocsp-basic),
//!     response         OCTET STRING (DER BasicOCSPResponse)
//! }
//! BasicOCSPResponse ::= SEQUENCE {
//!     tbsResponseData  ResponseData,
//!     signatureAlgorithm AlgorithmIdentifier,
//!     signature         BIT STRING,
//!     certs        [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
//! }
//! ResponseData ::= SEQUENCE {
//!     version          [0] EXPLICIT Version DEFAULT v1,
//!     responderID      ResponderID,
//!     producedAt       GeneralizedTime,
//!     responses        SEQUENCE OF SingleResponse,
//!     responseExtensions [1] EXPLICIT Extensions OPTIONAL
//! }
//! SingleResponse ::= SEQUENCE {
//!     certID           CertID,
//!     certStatus       CertStatus,
//!     thisUpdate       GeneralizedTime,
//!     nextUpdate   [0] EXPLICIT GeneralizedTime OPTIONAL,
//!     singleExtensions [1] EXPLICIT Extensions OPTIONAL
//! }
//! CertStatus ::= CHOICE {
//!     good    [0] IMPLICIT NULL,
//!     revoked [1] IMPLICIT RevokedInfo,
//!     unknown [2] IMPLICIT UnknownInfo
//! }
//! RevokedInfo ::= SEQUENCE {
//!     revocationTime    GeneralizedTime,
//!     revocationReason  [0] EXPLICIT CRLReason OPTIONAL
//! }
//! ```

use std::time::Duration;

use chrono::{Datelike, Timelike};
use der::Encode;
use x509_cert::Certificate;

use crate::der_utils;
use crate::error::LtvError;
use crate::ltv::status::{RevocationReason, RevocationSource, ValidationStatus};
use crate::net::AttestedHttpClient;

/// OCSP request Content-Type.
const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";

/// OCSP good response status.
const OCSP_RESPONSE_SUCCESSFUL: u8 = 0;

/// OID for id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1).
const OCSP_BASIC_RESPONSE_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// OID for id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2) — raw OID bytes.
const OCSP_NONCE_OID_BYTES: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

/// SHA-1 CertID hash algorithm used in every request (1.3.14.3.2.26).
const CERT_ID_HASH_ALGORITHM_OID: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];

/// Nonce size in bytes (matches Java stack: 30 bytes).
const NONCE_SIZE: usize = 30;

/// Generous upper bound for an OCSP response, including embedded certificates.
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

// ── Parsed OCSP response types ─────────────────────────────────────

/// Cert status from an OCSP SingleResponse.
#[derive(Debug, Clone)]
pub enum CertStatus {
    /// Certificate is not revoked.
    Good,
    /// Certificate has been revoked.
    Revoked {
        /// When the certificate was revoked.
        revocation_time: chrono::DateTime<chrono::Utc>,
        /// Reason for revocation, if provided.
        reason: RevocationReason,
    },
    /// Responder doesn't know about this certificate.
    Unknown,
}

/// A parsed SingleResponse from an OCSP BasicOCSPResponse.
#[derive(Debug, Clone)]
pub struct SingleResponse {
    /// CertID hash algorithm OID bytes (raw, without tag/length).
    pub hash_algorithm_oid: Vec<u8>,
    /// Issuer name hash (from CertID).
    pub issuer_name_hash: Vec<u8>,
    /// Issuer key hash (from CertID).
    pub issuer_key_hash: Vec<u8>,
    /// Serial number of the certificate (leading-zero-stripped).
    pub serial_number: Vec<u8>,
    /// The revocation status.
    pub cert_status: CertStatus,
    /// thisUpdate for this response.
    pub this_update: chrono::DateTime<chrono::Utc>,
    /// nextUpdate (optional).
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,
}

/// A parsed BasicOCSPResponse.
#[derive(Debug)]
pub struct ParsedBasicOcspResponse {
    /// Raw tbsResponseData bytes (for signature verification).
    pub tbs_response_data: Vec<u8>,
    /// Signature algorithm (OID plus any parameters, e.g. RSASSA-PSS-params).
    pub signature_algorithm: spki::AlgorithmIdentifierOwned,
    /// Raw signature bytes (BIT STRING contents, without unused-bits byte).
    pub signature_bytes: Vec<u8>,
    /// Responder ID — either byName (DER Name) or byKeyHash (OCTET STRING body).
    pub responder_id: ResponderId,
    /// producedAt timestamp.
    pub produced_at: chrono::DateTime<chrono::Utc>,
    /// Individual certificate responses.
    pub responses: Vec<SingleResponse>,
    /// Nonce from response extensions, if present.
    pub nonce: Option<Vec<u8>>,
    /// Embedded certificates (from \[0\] EXPLICIT SEQUENCE OF Certificate).
    pub embedded_certs_der: Vec<Vec<u8>>,
}

/// Responder identification.
#[derive(Debug, Clone)]
pub enum ResponderId {
    /// byName \[1\] — DER-encoded Name (the responder's DN).
    ByName(Vec<u8>),
    /// byKeyHash \[2\] — SHA-1 hash of responder's public key.
    ByKeyHash(Vec<u8>),
}

// ── OCSP client ────────────────────────────────────────────────────

/// OCSP client for querying certificate revocation status.
#[derive(Debug, Clone)]
pub struct OcspClient {
    http_client: AttestedHttpClient,
    timeout: Duration,
    max_body_size: usize,
}

impl OcspClient {
    /// Create a new OCSP client with default settings.
    pub fn new() -> Result<Self, LtvError> {
        Ok(Self {
            http_client: crate::net::hardened_http_client()?,
            timeout: Duration::from_secs(30),
            max_body_size: MAX_BODY_SIZE,
        })
    }

    /// Set the HTTP client.
    pub fn http_client(mut self, client: AttestedHttpClient) -> Self {
        self.http_client = client;
        self
    }

    /// Explicitly inject an unattested reqwest client outside FIPS mode.
    #[cfg(not(feature = "fips"))]
    pub fn unverified_http_client(mut self, client: reqwest::Client) -> Result<Self, LtvError> {
        self.http_client = crate::net::unverified_http_client(client)?;
        Ok(self)
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum downloaded OCSP response size (10 MiB by default).
    pub fn max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = max;
        self
    }

    /// Extract OCSP responder URLs from a certificate's AIA extension.
    pub fn extract_ocsp_urls(cert: &Certificate) -> Vec<String> {
        extract_aia_urls(cert, AiaAccessMethod::Ocsp)
    }

    /// Fetch an OCSP response for a certificate.
    ///
    /// Builds an OCSP request for `cert` issued by `issuer`, sends it
    /// to the OCSP responder URL found in the certificate's AIA extension,
    /// and returns the raw DER-encoded OCSP response.
    pub async fn fetch_ocsp_response(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<Vec<u8>, LtvError> {
        let urls = Self::extract_ocsp_urls(cert);
        if urls.is_empty() {
            return Err(LtvError::Ocsp(
                "no OCSP responder URL in certificate AIA extension".into(),
            ));
        }

        // Build the OCSP request
        let ocsp_request = build_ocsp_request(cert, issuer)?;

        let mut last_error = None;

        for url in &urls {
            match self.send_ocsp_request(url, &ocsp_request).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("OCSP request to {url} failed: {e}");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LtvError::Ocsp("all OCSP responder URLs failed".into())))
    }

    /// Fetch an OCSP response with a nonce for replay protection.
    ///
    /// Returns `(response_der, nonce_bytes)` — the nonce must be passed
    /// to [`check_revocation`] for validation.
    pub async fn fetch_ocsp_response_with_nonce(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<(Vec<u8>, Vec<u8>), LtvError> {
        let urls = Self::extract_ocsp_urls(cert);
        if urls.is_empty() {
            return Err(LtvError::Ocsp(
                "no OCSP responder URL in certificate AIA extension".into(),
            ));
        }

        let (ocsp_request, nonce) = build_ocsp_request_with_nonce(cert, issuer)?;

        let mut last_error = None;

        for url in &urls {
            match self.send_ocsp_request(url, &ocsp_request).await {
                Ok(response) => return Ok((response, nonce)),
                Err(e) => {
                    log::warn!("OCSP request to {url} failed: {e}");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LtvError::Ocsp("all OCSP responder URLs failed".into())))
    }

    /// Send an OCSP request to the given URL.
    async fn send_ocsp_request(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, LtvError> {
        // Bound the SSRF guard's DNS resolution by the same timeout as the HTTP
        // request, so a slow/blocked resolver cannot hang past `self.timeout`.
        match tokio::time::timeout(self.timeout, crate::net::validate_fetch_url(url)).await {
            Ok(result) => result.map_err(|e| LtvError::Ocsp(format!("URL rejected: {e}")))?,
            Err(_) => {
                return Err(LtvError::Ocsp(format!(
                    "URL validation timed out after {:?}",
                    self.timeout
                )))
            }
        }

        log::debug!(
            "Sending OCSP request to {url} ({} bytes)",
            request_der.len()
        );

        let response = self
            .http_client
            .client()
            .post(url)
            .header("Content-Type", OCSP_REQUEST_CONTENT_TYPE)
            .timeout(self.timeout)
            .body(request_der.to_vec())
            .send()
            .await
            .map_err(|e| LtvError::Ocsp(format!("OCSP request to {url} failed: {e}")))?;

        // Handle redirects — some responders redirect HTTP to HTTPS
        let status = response.status();
        if !status.is_success() {
            return Err(LtvError::Ocsp(format!(
                "OCSP responder {url} returned HTTP {status}"
            )));
        }

        let resp_bytes = self.read_response_body(response, url).await?;

        if resp_bytes.is_empty() {
            return Err(LtvError::Ocsp(format!(
                "OCSP responder {url} returned empty response"
            )));
        }

        // Basic validation: check it's a SEQUENCE (DER-encoded OCSPResponse)
        if resp_bytes[0] != 0x30 {
            return Err(LtvError::Ocsp(format!(
                "OCSP response from {url} does not appear to be DER-encoded"
            )));
        }

        // Validate the response status
        validate_ocsp_response_status(&resp_bytes)?;

        log::debug!("OCSP response from {url}: {} bytes", resp_bytes.len());

        Ok(resp_bytes)
    }

    /// Bound the body before allocating and while streaming, including when the
    /// responder omits Content-Length or uses chunked transfer encoding.
    async fn read_response_body(
        &self,
        mut response: reqwest::Response,
        url: &str,
    ) -> Result<Vec<u8>, LtvError> {
        if let Some(len) = response.content_length() {
            if len > self.max_body_size as u64 {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response from {url} exceeds max body size ({len} > {})",
                    self.max_body_size
                )));
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| LtvError::Ocsp(format!("failed to read OCSP response body: {e}")))?
        {
            if chunk.len() > self.max_body_size.saturating_sub(body.len()) {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response from {url} exceeds max body size (> {})",
                    self.max_body_size
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

// ── AIA extension parsing ──────────────────────────────────────────

/// AIA access method type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiaAccessMethod {
    /// OCSP (1.3.6.1.5.5.7.48.1)
    Ocsp,
    /// CA Issuers (1.3.6.1.5.5.7.48.2)
    CaIssuers,
}

/// Extract URLs from a certificate's Authority Information Access extension.
pub fn extract_aia_urls(cert: &Certificate, method: AiaAccessMethod) -> Vec<String> {
    let mut urls = Vec::new();

    // AIA extension OID: 1.3.6.1.5.5.7.1.1
    let aia_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

    let method_oid = match method {
        AiaAccessMethod::Ocsp => const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1"),
        AiaAccessMethod::CaIssuers => const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2"),
    };

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == aia_oid {
                if let Ok(parsed) = parse_aia_extension(ext.extn_value.as_bytes(), &method_oid) {
                    urls.extend(parsed);
                }
            }
        }
    }

    urls
}

/// Parse AIA extension value to extract URLs for a specific access method.
///
/// ```text
/// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
/// AccessDescription ::= SEQUENCE {
///     accessMethod    OBJECT IDENTIFIER,
///     accessLocation  GeneralName
/// }
/// ```
fn parse_aia_extension(
    der_bytes: &[u8],
    target_method_oid: &const_oid::ObjectIdentifier,
) -> Result<Vec<String>, LtvError> {
    let mut urls = Vec::new();

    let (tag, body) = der_utils::parse_tlv(der_bytes)
        .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "AIA: expected SEQUENCE, got 0x{tag:02x}"
        )));
    }

    let target_oid_der = target_method_oid
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode target OID: {e}")))?;

    let mut pos = &body[..];
    while !pos.is_empty() {
        let (ad_tag, ad_body, rest) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
        if ad_tag == 0x30 {
            // AccessDescription SEQUENCE
            // First: accessMethod OID
            let (oid_tag, oid_body, ad_rest) = der_utils::parse_tlv_with_rest(ad_body)
                .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
            if oid_tag == 0x06 {
                let oid_tlv = der_utils::encode_tlv(0x06, oid_body);
                if oid_tlv == target_oid_der {
                    // Match — extract accessLocation GeneralName
                    // Look for uniformResourceIdentifier [6]
                    if !ad_rest.is_empty() {
                        let (gn_tag, gn_body, _) = der_utils::parse_tlv_with_rest(ad_rest)
                            .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
                        if gn_tag == 0x86 {
                            // [6] IMPLICIT IA5String — URI
                            if let Ok(uri) = std::str::from_utf8(gn_body) {
                                urls.push(uri.to_string());
                            }
                        }
                    }
                }
            }
        }
        pos = rest;
    }

    Ok(urls)
}

// ── OCSP request building ──────────────────────────────────────────

/// Build an OCSP request for a certificate (without nonce).
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest    TBSRequest,
///     optionalSignature [0] EXPLICIT Signature OPTIONAL
/// }
/// TBSRequest ::= SEQUENCE {
///     version           [0] EXPLICIT Version DEFAULT v1,
///     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
///     requestList       SEQUENCE OF Request,
///     requestExtensions [2] EXPLICIT Extensions OPTIONAL
/// }
/// Request ::= SEQUENCE {
///     reqCert    CertID,
///     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
/// }
/// CertID ::= SEQUENCE {
///     hashAlgorithm     AlgorithmIdentifier,
///     issuerNameHash    OCTET STRING,
///     issuerKeyHash     OCTET STRING,
///     serialNumber      CertificateSerialNumber
/// }
/// ```
fn build_ocsp_request(cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>, LtvError> {
    let cert_id = build_cert_id(cert, issuer)?;

    // Request SEQUENCE { reqCert CertID }
    let request = der_utils::encode_sequence_from_parts(&[&cert_id]);

    // requestList SEQUENCE OF Request
    let request_list = der_utils::encode_sequence_from_parts(&[&request]);

    // TBSRequest SEQUENCE { requestList }
    let tbs_request = der_utils::encode_sequence_from_parts(&[&request_list]);

    // OCSPRequest SEQUENCE { tbsRequest }
    let ocsp_request = der_utils::encode_sequence_from_parts(&[&tbs_request]);

    Ok(ocsp_request)
}

/// Build an OCSP request with a random nonce extension.
///
/// Returns `(request_der, nonce_bytes)`.
pub fn build_ocsp_request_with_nonce(
    cert: &Certificate,
    issuer: &Certificate,
) -> Result<(Vec<u8>, Vec<u8>), LtvError> {
    let cert_id = build_cert_id(cert, issuer)?;

    // Request SEQUENCE { reqCert CertID }
    let request = der_utils::encode_sequence_from_parts(&[&cert_id]);

    // requestList SEQUENCE OF Request
    let request_list = der_utils::encode_sequence_from_parts(&[&request]);

    // Generate a 30-byte random nonce (matches Java stack)
    let nonce = generate_nonce()?;

    // Build nonce extension:
    // Extension ::= SEQUENCE {
    //     extnID    OID (id-pkix-ocsp-nonce),
    //     extnValue OCTET STRING (wrapping the nonce OCTET STRING)
    // }
    let nonce_oid_tlv = der_utils::encode_tlv(0x06, OCSP_NONCE_OID_BYTES);
    let nonce_inner = der_utils::encode_tlv(0x04, &nonce); // inner OCTET STRING
    let nonce_outer = der_utils::encode_tlv(0x04, &nonce_inner); // wrapped in extnValue OCTET STRING
    let nonce_ext = der_utils::encode_sequence_from_parts(&[&nonce_oid_tlv, &nonce_outer]);

    // Extensions SEQUENCE
    let extensions_seq = der_utils::encode_sequence_from_parts(&[&nonce_ext]);

    // requestExtensions [2] EXPLICIT Extensions
    let request_extensions = der_utils::encode_tlv(0xA2, &extensions_seq);

    // TBSRequest SEQUENCE { requestList, requestExtensions }
    let tbs_request = der_utils::encode_sequence_from_parts(&[&request_list, &request_extensions]);

    // OCSPRequest SEQUENCE { tbsRequest }
    let ocsp_request = der_utils::encode_sequence_from_parts(&[&tbs_request]);

    Ok((ocsp_request, nonce))
}

/// Build a CertID SEQUENCE for an OCSP request.
fn build_cert_id(cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>, LtvError> {
    // Hash the issuer's distinguished name
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode issuer name: {e}")))?;
    let issuer_name_hash = sha1_hash(&issuer_name_der)?;

    // Hash the issuer's public key
    let issuer_key_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    let issuer_key_hash = sha1_hash(&issuer_key_der)?;

    // Serial number of the cert being checked
    let serial_der = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode serial number: {e}")))?;

    // Build CertID
    let sha1_alg_id = build_sha1_algorithm_identifier()?;
    let issuer_name_hash_oct = der_utils::encode_tlv(0x04, &issuer_name_hash);
    let issuer_key_hash_oct = der_utils::encode_tlv(0x04, &issuer_key_hash);

    Ok(der_utils::encode_sequence_from_parts(&[
        &sha1_alg_id,
        &issuer_name_hash_oct,
        &issuer_key_hash_oct,
        &serial_der,
    ]))
}

/// Generate a cryptographically random nonce of NONCE_SIZE bytes.
fn generate_nonce() -> Result<Vec<u8>, LtvError> {
    Ok(riptering::random_bytes(NONCE_SIZE)?)
}

/// Build SHA-1 AlgorithmIdentifier (SEQUENCE { OID, NULL }).
fn build_sha1_algorithm_identifier() -> Result<Vec<u8>, LtvError> {
    let sha1_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let oid_der = sha1_oid
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode SHA-1 OID: {e}")))?;
    let null_der = vec![0x05, 0x00]; // NULL
    Ok(der_utils::encode_sequence_from_parts(&[
        &oid_der, &null_der,
    ]))
}

// ── OCSP response parsing ──────────────────────────────────────────

/// Validate the OCSPResponse status field.
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///     responseStatus  OCSPResponseStatus,
///     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
/// }
/// OCSPResponseStatus ::= ENUMERATED { successful(0), ... }
/// ```
fn validate_ocsp_response_status(der_bytes: &[u8]) -> Result<(), LtvError> {
    let (tag, body) = der_utils::parse_tlv(der_bytes)
        .map_err(|e| LtvError::Ocsp(format!("OCSP response parse error: {e}")))?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "OCSP response: expected SEQUENCE, got 0x{tag:02x}"
        )));
    }

    // First element: responseStatus ENUMERATED
    let (status_tag, status_body, _) = der_utils::parse_tlv_with_rest(&body)
        .map_err(|e| LtvError::Ocsp(format!("OCSP response parse error: {e}")))?;
    if status_tag != 0x0A {
        return Err(LtvError::Ocsp(format!(
            "OCSP response: expected ENUMERATED status, got 0x{status_tag:02x}"
        )));
    }

    if status_body.is_empty() {
        return Err(LtvError::Ocsp("OCSP response: empty status".into()));
    }

    let status = status_body[0];
    if status != OCSP_RESPONSE_SUCCESSFUL {
        return Err(LtvError::OcspResponderStatus(format!(
            "{} ({status})",
            ocsp_response_status_name(status)
        )));
    }

    Ok(())
}

/// Human-readable name for an OCSP `OCSPResponseStatus` code (RFC 6960 §4.2.1).
fn ocsp_response_status_name(status: u8) -> &'static str {
    match status {
        0 => "successful",
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "unknown",
    }
}

/// Parse a DER-encoded OCSPResponse into a BasicOCSPResponse.
///
/// Validates the response status and extracts the BasicOCSPResponse body.
pub fn parse_ocsp_response(response_der: &[u8]) -> Result<ParsedBasicOcspResponse, LtvError> {
    // OCSPResponse SEQUENCE
    let (outer_tag, outer_body) = der_utils::parse_tlv(response_der)
        .map_err(|e| LtvError::Ocsp(format!("OCSPResponse outer: {e}")))?;
    if outer_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected OCSPResponse SEQUENCE, got 0x{outer_tag:02x}"
        )));
    }

    // responseStatus ENUMERATED
    let (status_tag, status_body, rest) = der_utils::parse_tlv_with_rest(&outer_body)
        .map_err(|e| LtvError::Ocsp(format!("responseStatus: {e}")))?;
    if status_tag != 0x0A || status_body.is_empty() {
        return Err(LtvError::Ocsp("invalid responseStatus".into()));
    }
    if status_body[0] != OCSP_RESPONSE_SUCCESSFUL {
        // Responder-side / transient status (tryLater, internalError, ...) —
        // non-determinative, not an integrity failure. Typed distinctly so the
        // revocation orchestrator maps it to Unknown, not Invalid.
        return Err(LtvError::OcspResponderStatus(format!(
            "{} ({})",
            ocsp_response_status_name(status_body[0]),
            status_body[0]
        )));
    }

    // responseBytes [0] EXPLICIT ResponseBytes
    if rest.is_empty() {
        return Err(LtvError::Ocsp(
            "OCSP response successful but no responseBytes".into(),
        ));
    }
    let (rb_tag, rb_body, _) = der_utils::parse_tlv_with_rest(rest)
        .map_err(|e| LtvError::Ocsp(format!("responseBytes: {e}")))?;
    if rb_tag != 0xA0 {
        return Err(LtvError::Ocsp(format!(
            "expected responseBytes [0], got 0x{rb_tag:02x}"
        )));
    }

    // ResponseBytes SEQUENCE { responseType OID, response OCTET STRING }
    let (rb_seq_tag, rb_seq_body) = der_utils::parse_tlv(rb_body)
        .map_err(|e| LtvError::Ocsp(format!("ResponseBytes SEQUENCE: {e}")))?;
    if rb_seq_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected ResponseBytes SEQUENCE, got 0x{rb_seq_tag:02x}"
        )));
    }

    // responseType OID
    let (oid_tag, oid_body, rb_rest) = der_utils::parse_tlv_with_rest(&rb_seq_body)
        .map_err(|e| LtvError::Ocsp(format!("responseType OID: {e}")))?;
    if oid_tag != 0x06 {
        return Err(LtvError::Ocsp("expected responseType OID".into()));
    }
    if oid_body != OCSP_BASIC_RESPONSE_OID {
        return Err(LtvError::Ocsp(
            "responseType is not id-pkix-ocsp-basic".into(),
        ));
    }

    // response OCTET STRING (contains DER BasicOCSPResponse)
    let (oct_tag, oct_body, _) = der_utils::parse_tlv_with_rest(rb_rest)
        .map_err(|e| LtvError::Ocsp(format!("response OCTET STRING: {e}")))?;
    if oct_tag != 0x04 {
        return Err(LtvError::Ocsp("expected response OCTET STRING".into()));
    }

    // Parse BasicOCSPResponse
    parse_basic_ocsp_response(oct_body)
}

/// Parse a DER-encoded BasicOCSPResponse.
fn parse_basic_ocsp_response(der: &[u8]) -> Result<ParsedBasicOcspResponse, LtvError> {
    // BasicOCSPResponse SEQUENCE
    let (tag, body) =
        der_utils::parse_tlv(der).map_err(|e| LtvError::Ocsp(format!("BasicOCSPResponse: {e}")))?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected BasicOCSPResponse SEQUENCE, got 0x{tag:02x}"
        )));
    }

    // tbsResponseData SEQUENCE
    let (tbs_tag, tbs_value, rest) = der_utils::parse_tlv_with_rest(&body)
        .map_err(|e| LtvError::Ocsp(format!("tbsResponseData: {e}")))?;
    if tbs_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected tbsResponseData SEQUENCE, got 0x{tbs_tag:02x}"
        )));
    }

    // Reconstruct TBS DER (tag + length + value) for signature verification
    let tbs_consumed = body.len() - rest.len();
    let tbs_response_data = body[..tbs_consumed].to_vec();

    // signatureAlgorithm AlgorithmIdentifier SEQUENCE. Keep the full structure
    // (OID + parameters) so RSASSA-PSS-params are available when the signature
    // is verified, rather than discarding everything but the OID.
    let sig_alg_input = rest;
    let (sig_alg_tag, _sig_alg_body, rest) = der_utils::parse_tlv_with_rest(sig_alg_input)
        .map_err(|e| LtvError::Ocsp(format!("signatureAlgorithm: {e}")))?;
    if sig_alg_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected signatureAlgorithm SEQUENCE, got 0x{sig_alg_tag:02x}"
        )));
    }
    let sig_alg_der = &sig_alg_input[..sig_alg_input.len() - rest.len()];
    let signature_algorithm = {
        use der::Decode as _;
        spki::AlgorithmIdentifierOwned::from_der(sig_alg_der)
            .map_err(|e| LtvError::Ocsp(format!("signatureAlgorithm decode: {e}")))?
    };

    // signature BIT STRING
    let (sig_tag, sig_body, rest) = der_utils::parse_tlv_with_rest(rest)
        .map_err(|e| LtvError::Ocsp(format!("signature BIT STRING: {e}")))?;
    if sig_tag != 0x03 {
        return Err(LtvError::Ocsp(format!(
            "expected signature BIT STRING, got 0x{sig_tag:02x}"
        )));
    }
    if sig_body.is_empty() {
        return Err(LtvError::Ocsp("empty signature BIT STRING".into()));
    }
    let signature_bytes = sig_body[1..].to_vec(); // skip unused-bits byte

    // certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    let mut embedded_certs_der = Vec::new();
    if !rest.is_empty() {
        let (certs_tag, certs_body, _) = der_utils::parse_tlv_with_rest(rest)
            .map_err(|e| LtvError::Ocsp(format!("certs [0]: {e}")))?;
        if certs_tag == 0xA0 {
            // SEQUENCE OF Certificate
            let (seq_tag, seq_body) = der_utils::parse_tlv(certs_body)
                .map_err(|e| LtvError::Ocsp(format!("certs SEQUENCE: {e}")))?;
            if seq_tag == 0x30 {
                // Walk through certificates
                let mut cert_pos = &seq_body[..];
                while !cert_pos.is_empty() {
                    let (cert_tag, _cert_value, cert_rest) =
                        der_utils::parse_tlv_with_rest(cert_pos)
                            .map_err(|e| LtvError::Ocsp(format!("embedded cert: {e}")))?;
                    if cert_tag == 0x30 {
                        let cert_len = cert_pos.len() - cert_rest.len();
                        embedded_certs_der.push(cert_pos[..cert_len].to_vec());
                    }
                    cert_pos = cert_rest;
                }
            }
        }
    }

    // Parse tbsResponseData body
    let mut tbs_pos = tbs_value;

    // version [0] EXPLICIT INTEGER — optional, default v1
    if !tbs_pos.is_empty() && tbs_pos[0] == 0xA0 {
        let (_, _, r) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("version: {e}")))?;
        tbs_pos = r;
    }

    // responderID: CHOICE {
    //   byName [1] EXPLICIT Name,
    //   byKeyHash [2] EXPLICIT OCTET STRING
    // }
    let responder_id = if !tbs_pos.is_empty() && tbs_pos[0] == 0xA1 {
        // byName [1]
        let (_, name_body, r) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responderID byName: {e}")))?;
        tbs_pos = r;
        ResponderId::ByName(name_body.to_vec())
    } else if !tbs_pos.is_empty() && tbs_pos[0] == 0xA2 {
        // byKeyHash [2]
        let (_, hash_wrapper, r) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responderID byKeyHash: {e}")))?;
        tbs_pos = r;
        // Inside [2]: OCTET STRING
        let (oct_tag, oct_body, _) = der_utils::parse_tlv_with_rest(hash_wrapper)
            .map_err(|e| LtvError::Ocsp(format!("responderID keyHash OCTET STRING: {e}")))?;
        if oct_tag != 0x04 {
            return Err(LtvError::Ocsp(format!(
                "expected OCTET STRING in byKeyHash, got 0x{oct_tag:02x}"
            )));
        }
        ResponderId::ByKeyHash(oct_body.to_vec())
    } else {
        return Err(LtvError::Ocsp("missing or unknown responderID".into()));
    };

    // producedAt GeneralizedTime
    let (pa_tag, pa_body, rest_after_pa) = der_utils::parse_tlv_with_rest(tbs_pos)
        .map_err(|e| LtvError::Ocsp(format!("producedAt: {e}")))?;
    if pa_tag != 0x18 {
        return Err(LtvError::Ocsp(format!(
            "expected producedAt GeneralizedTime (0x18), got 0x{pa_tag:02x}"
        )));
    }
    let produced_at = der_utils::parse_generalized_time(pa_body)
        .map_err(|e| LtvError::Ocsp(format!("producedAt parse: {e}")))?;
    tbs_pos = rest_after_pa;

    // responses SEQUENCE OF SingleResponse
    let (resp_seq_tag, resp_seq_body, rest_after_responses) =
        der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responses SEQUENCE: {e}")))?;
    if resp_seq_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected responses SEQUENCE, got 0x{resp_seq_tag:02x}"
        )));
    }

    let mut responses = Vec::new();
    let mut sr_pos = resp_seq_body;
    while !sr_pos.is_empty() {
        let (sr_tag, sr_body, sr_rest) = der_utils::parse_tlv_with_rest(sr_pos)
            .map_err(|e| LtvError::Ocsp(format!("SingleResponse: {e}")))?;
        if sr_tag == 0x30 {
            responses.push(parse_single_response(sr_body)?);
        }
        sr_pos = sr_rest;
    }

    tbs_pos = rest_after_responses;

    // responseExtensions [1] EXPLICIT Extensions OPTIONAL
    let mut nonce = None;
    if !tbs_pos.is_empty() {
        let (tag, ext_wrapper, trailing) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responseExtensions: {e}")))?;
        if tag != 0xA1 || !trailing.is_empty() {
            return Err(LtvError::Ocsp(
                "unexpected or duplicate responseExtensions fields".into(),
            ));
        }
        nonce = parse_ocsp_extensions(ext_wrapper, true)?;
    }

    Ok(ParsedBasicOcspResponse {
        tbs_response_data,
        signature_algorithm,
        signature_bytes,
        responder_id,
        produced_at,
        responses,
        nonce,
        embedded_certs_der,
    })
}

/// Parse a SingleResponse from its SEQUENCE body.
fn parse_single_response(body: &[u8]) -> Result<SingleResponse, LtvError> {
    let mut pos = body;

    // certID SEQUENCE
    let (cid_tag, cid_body, rest) =
        der_utils::parse_tlv_with_rest(pos).map_err(|e| LtvError::Ocsp(format!("CertID: {e}")))?;
    if cid_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected CertID SEQUENCE, got 0x{cid_tag:02x}"
        )));
    }
    pos = rest;

    // Parse CertID body: hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber
    let (alg_tag, alg_body, cid_rest) = der_utils::parse_tlv_with_rest(cid_body)
        .map_err(|e| LtvError::Ocsp(format!("CertID hashAlgorithm: {e}")))?;
    if alg_tag != 0x30 {
        return Err(LtvError::Ocsp("expected hashAlgorithm SEQUENCE".into()));
    }
    // Extract OID from AlgorithmIdentifier
    let (oid_tag, oid_body, _) = der_utils::parse_tlv_with_rest(alg_body)
        .map_err(|e| LtvError::Ocsp(format!("hashAlgorithm OID: {e}")))?;
    if oid_tag != 0x06 {
        return Err(LtvError::Ocsp("expected OID in hashAlgorithm".into()));
    }
    let hash_algorithm_oid = oid_body.to_vec();

    // issuerNameHash OCTET STRING
    let (inh_tag, inh_body, cid_rest) = der_utils::parse_tlv_with_rest(cid_rest)
        .map_err(|e| LtvError::Ocsp(format!("issuerNameHash: {e}")))?;
    if inh_tag != 0x04 {
        return Err(LtvError::Ocsp(
            "expected issuerNameHash OCTET STRING".into(),
        ));
    }
    let issuer_name_hash = inh_body.to_vec();

    // issuerKeyHash OCTET STRING
    let (ikh_tag, ikh_body, cid_rest) = der_utils::parse_tlv_with_rest(cid_rest)
        .map_err(|e| LtvError::Ocsp(format!("issuerKeyHash: {e}")))?;
    if ikh_tag != 0x04 {
        return Err(LtvError::Ocsp("expected issuerKeyHash OCTET STRING".into()));
    }
    let issuer_key_hash = ikh_body.to_vec();

    // serialNumber INTEGER
    let (sn_tag, sn_body, _) = der_utils::parse_tlv_with_rest(cid_rest)
        .map_err(|e| LtvError::Ocsp(format!("serialNumber: {e}")))?;
    if sn_tag != 0x02 {
        return Err(LtvError::Ocsp("expected serialNumber INTEGER".into()));
    }
    let serial_number = der_utils::parse_integer_body(sn_body);

    // certStatus: CHOICE { good [0], revoked [1], unknown [2] }
    let (cs_tag, cs_body, rest_after_status) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| LtvError::Ocsp(format!("certStatus: {e}")))?;
    pos = rest_after_status;

    let cert_status = match cs_tag {
        0x80 => {
            // good [0] IMPLICIT NULL
            CertStatus::Good
        }
        0xA1 => {
            // revoked [1] IMPLICIT RevokedInfo
            // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
            //                            revocationReason [0] EXPLICIT CRLReason OPTIONAL }
            parse_revoked_info(cs_body)?
        }
        0x82 => {
            // unknown [2] IMPLICIT UnknownInfo (NULL)
            CertStatus::Unknown
        }
        _ => {
            return Err(LtvError::Ocsp(format!(
                "unknown certStatus tag: 0x{cs_tag:02x}"
            )));
        }
    };

    // thisUpdate GeneralizedTime
    let (tu_tag, tu_body, rest_after_tu) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| LtvError::Ocsp(format!("thisUpdate: {e}")))?;
    if tu_tag != 0x18 {
        return Err(LtvError::Ocsp(format!(
            "expected thisUpdate GeneralizedTime, got 0x{tu_tag:02x}"
        )));
    }
    let this_update = der_utils::parse_generalized_time(tu_body)
        .map_err(|e| LtvError::Ocsp(format!("thisUpdate parse: {e}")))?;
    pos = rest_after_tu;

    // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
    let mut next_update = None;
    if !pos.is_empty() && pos[0] == 0xA0 {
        let (_, nu_inner, rest_after_nu) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| LtvError::Ocsp(format!("nextUpdate [0]: {e}")))?;
        let (nu_tag, nu_body, _) = der_utils::parse_tlv_with_rest(nu_inner)
            .map_err(|e| LtvError::Ocsp(format!("nextUpdate GeneralizedTime: {e}")))?;
        if nu_tag == 0x18 {
            next_update = Some(
                der_utils::parse_generalized_time(nu_body)
                    .map_err(|e| LtvError::Ocsp(format!("nextUpdate parse: {e}")))?,
            );
        }
        pos = rest_after_nu;
    }

    if !pos.is_empty() {
        let (tag, extensions, trailing) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| LtvError::Ocsp(format!("singleExtensions: {e}")))?;
        if tag != 0xA1 || !trailing.is_empty() {
            return Err(LtvError::Ocsp(
                "unexpected or duplicate singleExtensions fields".into(),
            ));
        }
        parse_ocsp_extensions(extensions, false)?;
    }

    Ok(SingleResponse {
        hash_algorithm_oid,
        issuer_name_hash,
        issuer_key_hash,
        serial_number,
        cert_status,
        this_update,
        next_update,
    })
}

/// Parse RevokedInfo from the [1] body.
fn parse_revoked_info(body: &[u8]) -> Result<CertStatus, LtvError> {
    // revocationTime GeneralizedTime
    let (rt_tag, rt_body, rest) = der_utils::parse_tlv_with_rest(body)
        .map_err(|e| LtvError::Ocsp(format!("revocationTime: {e}")))?;
    if rt_tag != 0x18 {
        return Err(LtvError::Ocsp(format!(
            "expected revocationTime GeneralizedTime, got 0x{rt_tag:02x}"
        )));
    }
    let revocation_time = der_utils::parse_generalized_time(rt_body)
        .map_err(|e| LtvError::Ocsp(format!("revocationTime parse: {e}")))?;

    // revocationReason [0] EXPLICIT CRLReason OPTIONAL
    let mut reason = RevocationReason::Unspecified;
    if !rest.is_empty() && rest[0] == 0xA0 {
        let (_, reason_inner, _) = der_utils::parse_tlv_with_rest(rest)
            .map_err(|e| LtvError::Ocsp(format!("revocationReason: {e}")))?;
        // CRLReason is ENUMERATED
        if let Some(enum_body) = der_utils::find_tagged_value(reason_inner, 0x0A) {
            if !enum_body.is_empty() {
                reason = RevocationReason::from_code(enum_body[0]);
            }
        }
    }

    Ok(CertStatus::Revoked {
        revocation_time,
        reason,
    })
}

/// Extract nonce value from response extensions.
///
/// The nonce extension (OID 1.3.6.1.5.5.7.48.1.2) may contain the nonce
/// as raw bytes or wrapped in a DER OCTET STRING. We handle both formats.
fn parse_ocsp_extensions(
    ext_area: &[u8],
    response_level: bool,
) -> Result<Option<Vec<u8>>, LtvError> {
    use der::Decode;
    let extensions = x509_cert::ext::Extensions::from_der(ext_area)
        .map_err(|e| LtvError::Ocsp(format!("OCSP extensions: {e}")))?;
    if extensions.is_empty() {
        return Err(LtvError::Ocsp("empty OCSP Extensions".into()));
    }
    let nonce_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
    let mut seen = std::collections::HashSet::new();
    let mut nonce = None;
    for extension in extensions {
        if !seen.insert(extension.extn_id) {
            return Err(LtvError::Ocsp(format!(
                "duplicate OCSP extension {}",
                extension.extn_id
            )));
        }
        if extension.extn_id == nonce_oid {
            if !response_level {
                return Err(LtvError::Ocsp(
                    "nonce is not permitted in singleExtensions".into(),
                ));
            }
            let value = extension.extn_value.as_bytes();
            // Preserve legacy raw nonce interoperability, but never discard
            // trailing bytes from an apparent DER OCTET STRING wrapper.
            nonce = Some(match der_utils::parse_tlv_with_rest(value) {
                Ok((0x04, body, [])) => body.to_vec(),
                _ => value.to_vec(),
            });
        } else if extension.critical {
            return Err(LtvError::Ocsp(format!(
                "unsupported critical OCSP extension {}",
                extension.extn_id
            )));
        }
    }
    Ok(nonce)
}

// ── Responder signature verification ───────────────────────────────

/// Verify the OCSP response signature.
///
/// Tries embedded certificates first, then falls back to the issuer certificate.
fn verify_ocsp_response_signature(
    parsed: &ParsedBasicOcspResponse,
    issuer: &Certificate,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<Certificate, LtvError> {
    use der::Decode;

    // Strategy: try embedded certs first, then issuer
    let mut candidates: Vec<Certificate> = Vec::new();

    // Embedded certs
    for cert_der in &parsed.embedded_certs_der {
        if let Ok(cert) = Certificate::from_der(cert_der) {
            candidates.push(cert);
        }
    }

    // Add issuer as fallback
    candidates.push(issuer.clone());

    // Try each candidate
    for candidate in &candidates {
        let spki_der = match candidate.tbs_certificate.subject_public_key_info.to_der() {
            Ok(d) => d,
            Err(_) => continue,
        };

        let result = crate::crypto::verify::verify_signature_by_algid_with_policy(
            &parsed.tbs_response_data,
            &parsed.signature_bytes,
            &spki_der,
            &parsed.signature_algorithm,
            policy,
        );

        if result.is_ok() {
            // Embedded certs are unsigned discovery hints. A same-name/key
            // direct issuer must use the exact caller-authenticated metadata,
            // including validity and constraints, rather than embedded fields.
            return Ok(if certs_have_same_identity(candidate, issuer) {
                issuer.clone()
            } else {
                candidate.clone()
            });
        }
    }

    Err(LtvError::Ocsp(
        "OCSP response signature could not be verified against any candidate certificate".into(),
    ))
}

// ── Responder trust validation ─────────────────────────────────────

/// Outcome of responder trust validation: whether the (now-trusted) OCSP
/// responder still needs its **own** revocation status checked.
///
/// Per RFC 6960 §4.2.2.2.1, a *delegated* responder certificate (one issued by
/// the CA with `id-kp-OCSPSigning`) that does **not** carry the
/// `id-pkix-ocsp-nocheck` extension must itself be revocation-checked — the CA
/// is asserting it may be revoked. A responder that **is** the issuing CA, or a
/// delegated responder that carries `nocheck`, needs no such check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderRevocationCheck {
    /// No further check needed (responder is the issuing CA, or a delegated
    /// responder bearing `id-pkix-ocsp-nocheck`).
    NotRequired,
    /// The responder is a delegated signer lacking `nocheck`; its own revocation
    /// status (against the CA `issuer`) must be checked by the caller.
    Required,
}

/// Validate that the OCSP responder is trusted, matching it to the response's
/// `responderID`.
///
/// Per RFC 6960 §4.2.2.2, the response signer must be one of:
/// 1. The CA that issued the certificate being checked (issuer == responder)
/// 2. A responder whose certificate is issued by the CA and has the
///    id-kp-OCSPSigning extended key usage
///
/// The responder certificate is additionally bound to the response's
/// `responderID` (byName: subject DN match; byKeyHash: SHA-1 of the responder's
/// public key), so a valid-but-unrelated certificate cannot be substituted.
///
/// The responder certificate's own validity period is checked against `now`.
/// The return value reports whether the responder's **own** revocation status
/// must still be checked (a delegated responder without
/// `id-pkix-ocsp-nocheck`) — see [`ResponderRevocationCheck`].
fn validate_responder_trust(
    responder_cert: &Certificate,
    issuer: &Certificate,
    parsed: &ParsedBasicOcspResponse,
    policy: &crate::crypto::verify::SignaturePolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ResponderRevocationCheck, LtvError> {
    // Check the responder certificate's own validity period (M-6).
    let validity = &responder_cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_date_time();
    let not_after = validity.not_after.to_date_time();
    // Convert der::DateTime to chrono for comparison
    let nb = chrono::DateTime::parse_from_rfc3339(&format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        not_before.year(),
        { not_before.month() },
        { not_before.day() },
        { not_before.hour() },
        { not_before.minutes() },
        { not_before.seconds() }
    ))
    .map_err(|e| LtvError::Ocsp(format!("invalid responder notBefore: {e}")))?
    .with_timezone(&chrono::Utc);
    let na = chrono::DateTime::parse_from_rfc3339(&format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        not_after.year(),
        { not_after.month() },
        { not_after.day() },
        { not_after.hour() },
        { not_after.minutes() },
        { not_after.seconds() }
    ))
    .map_err(|e| LtvError::Ocsp(format!("invalid responder notAfter: {e}")))?
    .with_timezone(&chrono::Utc);

    if now < nb {
        return Err(LtvError::Ocsp(format!(
            "OCSP responder certificate is not yet valid (notBefore: {nb})"
        )));
    }
    if now > na {
        return Err(LtvError::Ocsp(format!(
            "OCSP responder certificate is expired (notAfter: {na})"
        )));
    }

    // Bind the responder certificate to the response's responderID, so a
    // valid-but-unrelated certificate (e.g. another cert signed by the same CA)
    // cannot be substituted for the one the response names.
    responder_matches_responder_id(responder_cert, &parsed.responder_id)?;

    // Case 1: responder IS the issuer. The CA signs its own OCSP responses; no
    // separate responder-revocation check applies.
    if certs_have_same_identity(responder_cert, issuer) {
        return Ok(ResponderRevocationCheck::NotRequired);
    }

    // Case 2: responder is a delegated OCSP signer.
    // Must be issued by the same CA (issuer).
    if responder_cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(LtvError::Ocsp(
            "OCSP responder issuer name does not match the expected CA".into(),
        ));
    }
    let issuer_signed = crate::crypto::verify::verify_certificate_signature_with_policy(
        responder_cert,
        issuer,
        policy,
    );
    if issuer_signed.is_err() {
        return Err(LtvError::Ocsp(
            "OCSP responder certificate is not issued by the expected CA".into(),
        ));
    }

    validate_delegated_responder_extensions(responder_cert)?;

    // The directly authorizing CA's constraints must also apply to the
    // delegated signer. Ancestor constraints are applied by the path-aware
    // check below; issuer-only APIs cannot complete that validation.
    let mut constraints = crate::ltv::name_constraints::NameConstraintState::default();
    constraints
        .add_from_cert(issuer)
        .and_then(|()| constraints.check_cert(responder_cert))
        .map_err(|e| LtvError::Ocsp(format!("delegated OCSP responder name constraints: {e}")))?;

    // RFC 6960 §4.2.2.2.1: a delegated responder without id-pkix-ocsp-nocheck
    // must itself be revocation-checked. With nocheck, the CA waives that.
    if has_ocsp_nocheck_extension(responder_cert) {
        Ok(ResponderRevocationCheck::NotRequired)
    } else {
        Ok(ResponderRevocationCheck::Required)
    }
}

/// Bind the responder certificate to the response's `responderID`
/// (RFC 6960 §4.2.1): byName matches the responder's subject DN; byKeyHash
/// matches the SHA-1 of the responder's subjectPublicKey BIT STRING contents.
fn responder_matches_responder_id(
    responder_cert: &Certificate,
    responder_id: &ResponderId,
) -> Result<(), LtvError> {
    match responder_id {
        ResponderId::ByName(name_der) => {
            let subject_der = responder_cert
                .tbs_certificate
                .subject
                .to_der()
                .map_err(|e| LtvError::Ocsp(format!("responder subject encode: {e}")))?;
            if &subject_der != name_der {
                return Err(LtvError::Ocsp(
                    "OCSP responder certificate subject does not match responderID (byName)".into(),
                ));
            }
            Ok(())
        }
        ResponderId::ByKeyHash(key_hash) => {
            // Hash the SPKI public-key bit-string slice directly; no need to
            // allocate a temporary Vec on every OCSP response verification.
            let key_bytes = responder_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let computed = sha1_hash(key_bytes)?;
            if &computed != key_hash {
                return Err(LtvError::Ocsp(
                    "OCSP responder certificate key hash does not match responderID (byKeyHash)"
                        .into(),
                ));
            }
            Ok(())
        }
    }
}

/// Bind direct-issuer authorization to its name AND public key. Comparing the
/// subject alone would let an unrelated embedded certificate claim CA identity.
/// Same-key CA reissues remain interoperable even when their serials differ.
fn certs_have_same_identity(a: &Certificate, b: &Certificate) -> bool {
    a.tbs_certificate.subject == b.tbs_certificate.subject
        && a.tbs_certificate.subject_public_key_info == b.tbs_certificate.subject_public_key_info
}

/// Enforce delegated-signing restrictions without adding CA-only restrictions
/// to the direct-issuer path. Critical extensions must have a processing path
/// here; the delegated certificate is not passed through TrustStore validation.
fn validate_delegated_responder_extensions(cert: &Certificate) -> Result<(), LtvError> {
    use const_oid::AssociatedOid;
    use der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName};

    let mut seen = Vec::new();
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if seen.contains(&ext.extn_id) {
                return Err(LtvError::Ocsp(format!(
                    "OCSP responder certificate has duplicate extension {}",
                    ext.extn_id
                )));
            }
            seen.push(ext.extn_id);
            let value = ext.extn_value.as_bytes();
            let processed = match ext.extn_id {
                oid if oid == KeyUsage::OID => {
                    // The typed flag decoder masks unused bits; the shared
                    // strict parser additionally validates their zero padding.
                    crate::ltv::x509_ext::check_key_usage(cert)?;
                    let ku = KeyUsage::from_der(value)
                        .map_err(|e| LtvError::Ocsp(format!("responder keyUsage: {e}")))?;
                    if !ku.digital_signature() && !ku.non_repudiation() {
                        return Err(LtvError::Ocsp(
                            "OCSP responder certificate keyUsage does not permit signing".into(),
                        ));
                    }
                    true
                }
                oid if oid == BasicConstraints::OID => {
                    BasicConstraints::from_der(value)
                        .map_err(|e| LtvError::Ocsp(format!("responder basicConstraints: {e}")))?;
                    true
                }
                oid if oid == ExtendedKeyUsage::OID => {
                    ExtendedKeyUsage::from_der(value)
                        .map_err(|e| LtvError::Ocsp(format!("responder extendedKeyUsage: {e}")))?;
                    true
                }
                oid if oid == SubjectAltName::OID => {
                    // The OCSP responder's identity is bound to responderID;
                    // alternative names do not replace that binding.
                    SubjectAltName::from_der(value)
                        .map_err(|e| LtvError::Ocsp(format!("responder subjectAltName: {e}")))?;
                    true
                }
                oid if oid == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5") => {
                    if value != [0x05, 0x00] {
                        return Err(LtvError::Ocsp(
                            "OCSP responder nocheck extension is not DER NULL".into(),
                        ));
                    }
                    true
                }
                _ => false,
            };
            if ext.critical && !processed {
                return Err(LtvError::Ocsp(format!(
                    "OCSP responder certificate has an unprocessed critical extension {}",
                    ext.extn_id
                )));
            }
        }
    }
    crate::ltv::x509_ext::validate_extensions_for_role(
        cert,
        crate::ltv::x509_ext::CertRole::OcspResponder,
    )
    .map_err(|e| LtvError::Ocsp(format!("OCSP responder certificate profile: {e}")))
}

/// Check if a certificate has the id-pkix-ocsp-nocheck extension.
///
/// When present, the responder's own revocation status need not be checked.
pub fn has_ocsp_nocheck_extension(cert: &Certificate) -> bool {
    let nocheck_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == nocheck_oid && ext.extn_value.as_bytes() == [0x05, 0x00] {
                return true;
            }
        }
    }
    false
}

// ── Nonce validation ───────────────────────────────────────────────

/// Validate the OCSP response nonce against the request nonce.
///
/// Supports dual-format comparison per the Java stack:
/// - Direct comparison of raw nonce bytes
/// - Comparison with DER OCTET STRING wrapped nonce
fn validate_nonce(request_nonce: &[u8], response_nonce: &[u8]) -> Result<(), LtvError> {
    // Direct comparison
    if response_nonce == request_nonce {
        return Ok(());
    }

    // DER-wrapped comparison: response may contain raw bytes that match
    // when we wrap our nonce in OCTET STRING
    let wrapped_nonce = der_utils::encode_tlv(0x04, request_nonce);
    if response_nonce == wrapped_nonce.as_slice() {
        return Ok(());
    }

    // Or the response nonce may be DER-wrapped and our request nonce is raw
    if !response_nonce.is_empty() && response_nonce[0] == 0x04 {
        if let Ok((0x04, inner, rest)) = der_utils::parse_tlv_with_rest(response_nonce) {
            if rest.is_empty() && inner == request_nonce {
                return Ok(());
            }
        }
    }

    Err(LtvError::Ocsp("OCSP response nonce mismatch".into()))
}

// ── Freshness policy ───────────────────────────────────────────────

/// Freshness policy for OCSP responses (RFC 6960 §4.2.2.1).
///
/// An OCSP response carries a validity window: the status is asserted as of
/// `thisUpdate` and the responder promises fresher information by `nextUpdate`.
/// A response must not be relied upon once the validation time is past
/// `nextUpdate` (widened by an allowed clock skew); without this check a
/// legitimately-issued "good" response can be replayed forever — including
/// after the certificate has been compromised and revoked.
///
/// All comparisons are made against the *validation time* (`now`), which for
/// long-term validation is the historical instant being validated, not the
/// wall clock. A response produced *after* that instant (later-collected
/// archival evidence) is accepted; only staleness relative to `now` is a
/// failure.
#[derive(Debug, Clone)]
pub struct OcspFreshness {
    /// Clock skew tolerance applied to staleness/max-age comparisons.
    /// Accommodates small differences between the responder's and the
    /// validator's clocks. Default: 5 minutes.
    pub clock_skew: chrono::Duration,

    /// Maximum age (measured from `thisUpdate`) tolerated for a response that
    /// omits the optional `nextUpdate` field. RFC 6960 allows `nextUpdate` to be
    /// absent ("fresher information is always available"); rather than treat
    /// such a response as eternally fresh, it is rejected once it is older than
    /// this bound. Default: 24 hours.
    pub max_age_without_next_update: chrono::Duration,
}

impl Default for OcspFreshness {
    fn default() -> Self {
        Self {
            clock_skew: chrono::Duration::minutes(5),
            max_age_without_next_update: chrono::Duration::hours(24),
        }
    }
}

/// Validate that an OCSP response is fresh enough to be relied upon at `now`.
///
/// The anti-replay guarantee (RFC 6960 §4.2.2.1) is that a response must not be
/// **stale** as of the validation time: the validation instant must not be past
/// `nextUpdate`. When `nextUpdate` is absent, the response is instead bounded by
/// [`OcspFreshness::max_age_without_next_update`] measured from `thisUpdate`.
///
/// A response produced *after* the validation instant is explicitly **accepted**:
/// in archival / long-term validation, `validation_time` is the historical
/// instant being validated (e.g. signing or timestamp `genTime`) and the
/// revocation evidence is normally collected shortly afterwards, so its
/// `thisUpdate`/`producedAt` legitimately fall after `validation_time`.
/// `producedAt` is the time the responder signed the response — not a status
/// assertion time — so it is not used to gate freshness at all.
///
/// Fails closed: an out-of-range (stale) response returns an `Err`, which the
/// orchestrator classifies as a definitive `Invalid` (a received-but-unusable
/// response), never the fail-open `Unknown`.
fn validate_response_freshness(
    sr: &SingleResponse,
    now: chrono::DateTime<chrono::Utc>,
    freshness: &OcspFreshness,
) -> Result<(), LtvError> {
    let skew = freshness.clock_skew;

    match sr.next_update {
        Some(next_update) => {
            // Sanity: a window that ends before it starts is malformed.
            if next_update < sr.this_update {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response has nextUpdate ({next_update}) before thisUpdate ({})",
                    sr.this_update
                )));
            }
            // Anti-replay: reject once the validation instant is past nextUpdate.
            // (A response whose window lies at/after the validation instant —
            // later-collected archival evidence — is not stale and is kept.)
            if now > next_update + skew {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response is stale: nextUpdate ({next_update}) is before validation time ({now})"
                )));
            }
        }
        None => {
            // No nextUpdate: bound the response's age from thisUpdate so an old
            // response cannot be relied on indefinitely. A response whose window
            // starts at/after the validation time is always within bound.
            let max_valid = sr.this_update + freshness.max_age_without_next_update + skew;
            if now > max_valid {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response without nextUpdate is too old: thisUpdate ({}), validation time ({now}), max age {}",
                    sr.this_update, freshness.max_age_without_next_update
                )));
            }
        }
    }

    Ok(())
}

// ── Main revocation check function ─────────────────────────────────

/// Check whether a certificate is revoked according to an OCSP response.
///
/// Performs the full OCSP validation pipeline:
/// 1. Parse the OCSP response (BasicOCSPResponse)
/// 2. Verify the response signature (try embedded certs, then issuer)
/// 3. Validate responder trust (issuer match or delegated signer with EKU)
/// 4. If nonce provided, validate it matches the response
/// 5. Match the certificate's CertID in the response
/// 6. Time-aware: if `revocationTime > validation_time` → `Valid`
///
/// Returns a [`ValidationStatus`] indicating the result.
///
/// # Warning — no fail-closed policy is applied
///
/// This function (and its `_with_policy` / `_with_options` / `_detailed`
/// variants) returns the **raw** status of this single OCSP response:
/// `Unknown` here means "status could not be established" and is *not*
/// upgraded to a blocking result, and the delegated-responder revocation
/// check (RFC 6960 §4.2.2.2.1) is reported but not recursed into. Callers
/// making a trust decision should use
/// [`check_certificate_revocation`](crate::ltv::check_certificate_revocation),
/// which orchestrates OCSP + CRL and enforces the
/// [`RevocationConfig`](crate::ltv::RevocationConfig) fail-closed policy.
pub fn check_revocation(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<ValidationStatus, LtvError> {
    check_revocation_with_policy(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        &crate::crypto::verify::SignaturePolicy::default(),
    )
}

/// Like [`check_revocation`] but with an explicit
/// [`SignaturePolicy`](crate::crypto::verify::SignaturePolicy) for the response
/// and responder-certificate signature checks. The default rejects OCSP
/// material signed with MD5/SHA-1/SHA-224.
///
/// Freshness is validated with [`OcspFreshness::default`]; use
/// [`check_revocation_with_options`] to supply a custom freshness policy.
#[allow(clippy::too_many_arguments)]
pub fn check_revocation_with_policy(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<ValidationStatus, LtvError> {
    check_revocation_with_options(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        policy,
        &OcspFreshness::default(),
    )
}

/// Like [`check_revocation_with_policy`] but with an explicit [`OcspFreshness`]
/// policy controlling the RFC 6960 §4.2.2.1 time-window check.
///
/// A response that is stale as of `validation_time` (the validation instant is
/// past `nextUpdate`, or — lacking `nextUpdate` — the response is older than the
/// configured maximum age) fails closed with an `Err`, classified by the
/// orchestrator as `Invalid` (a received-but-unusable response), never the
/// fail-open `Unknown`. Later-collected evidence (window at/after the validation
/// instant) is accepted.
/// A delegated signer without `nocheck` requires its own revocation check.
/// This synchronous convenience API returns an error in that case; use the
/// async revocation orchestrator, or [`check_revocation_detailed`] and complete
/// the required responder check before relying on its status.
#[allow(clippy::too_many_arguments)]
pub fn check_revocation_with_options(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
    freshness: &OcspFreshness,
) -> Result<ValidationStatus, LtvError> {
    check_revocation_detailed(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        policy,
        freshness,
    )
    .and_then(complete_ocsp_outcome)
}

fn complete_ocsp_outcome(outcome: OcspCheckOutcome) -> Result<ValidationStatus, LtvError> {
    if outcome.delegated_responder.is_some() {
        return Err(LtvError::Ocsp(
            "delegated responder requires its own revocation check; use check_revocation_detailed or the async orchestrator".into(),
        ));
    }
    Ok(outcome.status)
}

/// The result of an OCSP revocation check, including any delegated responder
/// certificate whose **own** revocation status the caller must still verify.
#[derive(Debug, Clone)]
pub struct OcspCheckOutcome {
    /// The certificate-status result for the queried certificate.
    pub status: ValidationStatus,
    /// When `Some`, the OCSP response was signed by a *delegated* responder
    /// (issued by the CA, `id-kp-OCSPSigning`) that does **not** carry
    /// `id-pkix-ocsp-nocheck`. Per RFC 6960 §4.2.2.2.1 the caller must check this
    /// responder certificate's own revocation status (against the CA `issuer`);
    /// if it is revoked, the OCSP response must not be relied upon. When `None`,
    /// no further responder check is required (the responder is the issuing CA,
    /// or a delegated responder bearing `nocheck`).
    pub delegated_responder: Option<Certificate>,
}

/// Issuer-only detailed OCSP validation. Direct-issuer responses are supported;
/// delegated responses require [`check_revocation_detailed_with_issuer_path`]
/// so inherited CA/anchor constraints are not silently omitted.
///
/// Requested nonce echo is opportunistic here: absence is accepted subject to
/// freshness, while a present mismatch rejects. Use the nonce-policy or
/// issuer-path variants for strict required nonce echo.
#[allow(clippy::too_many_arguments)]
pub fn check_revocation_detailed(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
    freshness: &OcspFreshness,
) -> Result<OcspCheckOutcome, LtvError> {
    check_revocation_detailed_inner(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        policy,
        freshness,
        None,
        false,
    )
}

/// Complete OCSP validation using the issuing CA's full certificate path.
///
/// `issuer_chain` starts with the exact `issuer` supplied for the CertID and
/// continues toward `trust_store`. Delegated responder path validation uses
/// the OCSP-signing role and applies all issuer/anchor name constraints.
/// `require_nonce` rejects a missing nonce as well as a mismatch; it requires
/// a request nonce. The default issuer-only APIs keep opportunistic nonce
/// behavior but reject delegated responders because they lack path context.
#[allow(clippy::too_many_arguments)]
pub fn check_revocation_detailed_with_issuer_path(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
    freshness: &OcspFreshness,
    issuer_chain: &[Certificate],
    trust_store: &crate::trust::TrustStore,
    require_nonce: bool,
) -> Result<OcspCheckOutcome, LtvError> {
    if issuer_chain.first() != Some(issuer) {
        return Err(LtvError::Ocsp(
            "OCSP issuer path does not start with the expected issuer".into(),
        ));
    }
    check_revocation_detailed_inner(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        policy,
        freshness,
        Some((issuer_chain, trust_store)),
        require_nonce,
    )
}

/// Strict nonce binding for direct-issuer responses without a delegated path.
#[allow(clippy::too_many_arguments)]
pub fn check_revocation_detailed_with_nonce_policy(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
    freshness: &OcspFreshness,
    require_nonce: bool,
) -> Result<OcspCheckOutcome, LtvError> {
    check_revocation_detailed_inner(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        policy,
        freshness,
        None,
        require_nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_revocation_detailed_inner(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
    freshness: &OcspFreshness,
    issuer_path: Option<(&[Certificate], &crate::trust::TrustStore)>,
    require_nonce: bool,
) -> Result<OcspCheckOutcome, LtvError> {
    let now = validation_time.unwrap_or_else(chrono::Utc::now);
    if require_nonce && nonce.is_none_or(|nonce| nonce.is_empty()) {
        return Err(LtvError::Ocsp(
            "strict OCSP nonce policy requires a nonempty request nonce".into(),
        ));
    }

    // 1. Parse OCSP response
    let parsed = parse_ocsp_response(response_der)?;

    // 2. Verify signature — returns the responder certificate
    let responder_cert = verify_ocsp_response_signature(&parsed, issuer, policy)?;

    if let Some((chain, store)) = issuer_path {
        validate_ocsp_certificate_path(
            chain,
            store,
            crate::ltv::CertRole::IntermediateCa,
            policy,
            now,
        )?;
    }

    // 3. Validate responder trust (responderID match, cert validity vs. now,
    //    issuer/EKU for delegated responders) and learn whether the responder's
    //    own revocation status must still be checked.
    let responder_check = validate_responder_trust(&responder_cert, issuer, &parsed, policy, now)?;
    if !certs_have_same_identity(&responder_cert, issuer) {
        let (issuer_chain, trust_store) = issuer_path.ok_or_else(|| LtvError::Ocsp(
            "delegated OCSP responder requires complete issuer path validation; use check_revocation_detailed_with_issuer_path".into()
        ))?;
        let mut path = Vec::with_capacity(issuer_chain.len() + 1);
        path.push(responder_cert.clone());
        path.extend_from_slice(issuer_chain);
        validate_ocsp_certificate_path(
            &path,
            trust_store,
            crate::ltv::CertRole::OcspResponder,
            policy,
            now,
        )?;
    }
    let delegated_responder = match responder_check {
        ResponderRevocationCheck::Required => Some(responder_cert.clone()),
        ResponderRevocationCheck::NotRequired => None,
    };

    // 4. Validate nonce (if provided)
    if let Some(request_nonce) = nonce {
        match &parsed.nonce {
            Some(response_nonce) => {
                validate_nonce(request_nonce, response_nonce)?;
            }
            None => {
                if require_nonce {
                    return Err(LtvError::Ocsp(
                        "OCSP response is missing the required nonce".into(),
                    ));
                }
                // Some responders don't support nonces — log warning but continue
                log::warn!("OCSP response does not contain a nonce (nonce was requested)");
            }
        }
    }

    // 5. Find the matching SingleResponse for our certificate
    // Build the expected CertID components
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("issuer name encode: {e}")))?;
    let expected_name_hash = sha1_hash(&issuer_name_der)?;

    let issuer_key_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    let expected_key_hash = sha1_hash(&issuer_key_bytes)?;

    let cert_serial = der_utils::parse_integer_body(cert.tbs_certificate.serial_number.as_bytes());

    let matching_response = find_matching_response(
        &parsed.responses,
        &expected_name_hash,
        &expected_key_hash,
        &cert_serial,
    )?;

    let sr = match matching_response {
        Some(sr) => sr,
        None => {
            return Ok(OcspCheckOutcome {
                status: ValidationStatus::Unknown {
                    reason: "certificate not found in OCSP response".into(),
                },
                // The response was not about our certificate; no responder
                // revocation check is warranted.
                delegated_responder: None,
            });
        }
    };

    // 6. Validate response freshness (RFC 6960 §4.2.2.1). A response that is
    //    stale as of `now` (validation instant past nextUpdate) is rejected —
    //    fail closed — so a stale "good" response cannot be replayed
    //    indefinitely. Later-collected evidence (window at/after `now`) is kept.
    validate_response_freshness(sr, now, freshness)?;

    // 7. Map CertStatus to ValidationStatus
    let status = match &sr.cert_status {
        CertStatus::Good => ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: now,
        },
        CertStatus::Revoked {
            revocation_time,
            reason,
        } => {
            // Time-aware: if revocationTime > validation_time → Valid
            if *revocation_time > now {
                log::debug!(
                    "cert found revoked in OCSP but revocation_time ({revocation_time}) is after validation_time ({now})"
                );
                ValidationStatus::Valid {
                    source: RevocationSource::Ocsp,
                    checked_at: now,
                }
            } else {
                ValidationStatus::Revoked {
                    source: RevocationSource::Ocsp,
                    reason: *reason,
                    revocation_time: *revocation_time,
                }
            }
        }
        CertStatus::Unknown => ValidationStatus::Unknown {
            reason: "OCSP responder reported certificate status as unknown".into(),
        },
    };

    Ok(OcspCheckOutcome {
        status,
        delegated_responder,
    })
}

fn validate_ocsp_certificate_path(
    chain: &[Certificate],
    store: &crate::trust::TrustStore,
    role: crate::ltv::CertRole,
    policy: &crate::crypto::verify::SignaturePolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), LtvError> {
    let year = u16::try_from(now.year())
        .map_err(|_| LtvError::Ocsp("OCSP validation year is outside DER DateTime range".into()))?;
    let at = der::DateTime::new(
        year,
        now.month() as u8,
        now.day() as u8,
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
    )
    .map_err(|e| LtvError::Ocsp(format!("OCSP path validation time: {e}")))?;
    // Intersect both policies before path selection, so a legacy store cannot
    // weaken a strict OCSP check or select a weak first alternative anchor.
    let effective = if policy.legacy_allowed() && store.signature_policy().legacy_allowed() {
        crate::crypto::verify::SignaturePolicy::allow_legacy()
    } else {
        crate::crypto::verify::SignaturePolicy::strict()
    };
    let scoped = if effective == store.signature_policy() {
        std::borrow::Cow::Borrowed(store)
    } else {
        std::borrow::Cow::Owned(store.clone().with_signature_policy(effective))
    };
    scoped
        .verify_chain_for_purpose_with_fraction(chain, at, role, now.nanosecond() != 0)
        .map_err(|e| LtvError::Ocsp(format!("OCSP certificate issuer path: {e}")))?;
    Ok(())
}

/// A CertID includes its hash algorithm as well as its hashes. Do not interpret
/// hash bytes as SHA-1 when the response declares another algorithm. Responses
/// for unrelated certificates may use other algorithms without affecting ours.
fn find_matching_response<'a>(
    responses: &'a [SingleResponse],
    issuer_name_hash: &[u8],
    issuer_key_hash: &[u8],
    serial_number: &[u8],
) -> Result<Option<&'a SingleResponse>, LtvError> {
    for response in responses {
        if response.issuer_name_hash == issuer_name_hash
            && response.issuer_key_hash == issuer_key_hash
            && der_utils::integer_bodies_equal(&response.serial_number, serial_number)
        {
            if response.hash_algorithm_oid != CERT_ID_HASH_ALGORITHM_OID {
                return Err(LtvError::Ocsp(
                    "matching OCSP CertID declares an unsupported hash algorithm (expected SHA-1)"
                        .into(),
                ));
            }
            return Ok(Some(response));
        }
    }
    Ok(None)
}

/// Compute SHA-1 hash of data.
fn sha1_hash(data: &[u8]) -> Result<Vec<u8>, LtvError> {
    Ok(riptering::digest::digest(
        riptering::HashAlgorithm::Sha1,
        data,
    )?)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn test_ocsp_client_default() {
        let client = OcspClient::new().unwrap();
        assert_eq!(client.timeout, Duration::from_secs(30));
        assert_eq!(client.max_body_size, MAX_BODY_SIZE);
    }

    #[test]
    fn convenience_status_requires_completed_responder_revocation() {
        let status = ValidationStatus::Unknown {
            reason: "synthetic outcome".into(),
        };
        assert!(complete_ocsp_outcome(OcspCheckOutcome {
            status: status.clone(),
            delegated_responder: None,
        })
        .is_ok());
        assert!(complete_ocsp_outcome(OcspCheckOutcome {
            status,
            delegated_responder: Some(signer_cert()),
        })
        .unwrap_err()
        .to_string()
        .contains("own revocation check"));
    }

    /// Ordinary HTTP framing fixtures exercise the private body reader directly;
    /// production URL validation continues to refuse loopback before egress.
    async fn local_http_response(bytes: &'static [u8]) -> reqwest::Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream.write_all(bytes).await.unwrap();
        });
        let response = OcspClient::new()
            .unwrap()
            .http_client
            .client()
            .get(format!("http://{addr}/"))
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .unwrap();
        server.await.unwrap();
        response
    }

    #[tokio::test]
    async fn response_body_rejects_oversized_content_length() {
        let response = local_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        )
        .await;
        let error = OcspClient::new()
            .unwrap()
            .max_body_size(4)
            .read_response_body(response, "fixture")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds max body size"));
    }

    #[tokio::test]
    async fn response_body_bounds_chunked_downloads() {
        let response = local_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        )
        .await;
        let error = OcspClient::new()
            .unwrap()
            .max_body_size(4)
            .read_response_body(response, "fixture")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds max body size"));

        let response = local_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nABCD",
        )
        .await;
        let body = OcspClient::new()
            .unwrap()
            .max_body_size(4)
            .read_response_body(response, "fixture")
            .await
            .unwrap();
        assert_eq!(body, b"ABCD");
    }

    #[tokio::test]
    async fn test_send_ocsp_request_rejects_loopback_url() {
        let client = OcspClient::new().unwrap();
        let err = client
            .send_ocsp_request("http://127.0.0.1/ocsp", &[0x30, 0x00])
            .await
            .expect_err("loopback OCSP responder URL must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("non-public") || msg.contains("SSRF"),
            "expected SSRF rejection, got: {msg}"
        );
    }

    #[test]
    fn test_sha1_hash() {
        let hash = sha1_hash(b"test").unwrap();
        assert_eq!(hash.len(), 20); // SHA-1 is 20 bytes
    }

    #[test]
    fn matching_cert_id_is_bound_to_the_declared_hash_algorithm() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut response = SingleResponse {
            hash_algorithm_oid: CERT_ID_HASH_ALGORITHM_OID.to_vec(),
            issuer_name_hash: vec![1; 20],
            issuer_key_hash: vec![2; 20],
            serial_number: vec![3],
            cert_status: CertStatus::Good,
            this_update: now,
            next_update: None,
        };
        assert!(
            find_matching_response(&[response.clone()], &[1; 20], &[2; 20], &[3])
                .unwrap()
                .is_some()
        );

        response.hash_algorithm_oid =
            const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1")
                .as_bytes()
                .to_vec();
        let error =
            find_matching_response(&[response.clone()], &[1; 20], &[2; 20], &[3]).unwrap_err();
        assert!(error.to_string().contains("unsupported hash algorithm"));
        // Unrelated responses are not interpreted or used as evidence for ours.
        assert!(
            find_matching_response(&[response], &[1; 20], &[2; 20], &[4])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_build_sha1_algorithm_identifier() {
        let alg_id = build_sha1_algorithm_identifier().unwrap();
        assert_eq!(alg_id[0], 0x30); // SEQUENCE
    }

    #[test]
    fn test_extract_ocsp_urls_from_fixture_cert() {
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let pem_data = pem_rfc7468::decode_vec(cert_pem.as_bytes());
        if let Ok((_label, der)) = pem_data {
            if let Ok(cert) = Certificate::from_der(&der) {
                let urls = OcspClient::extract_ocsp_urls(&cert);
                let _ = urls;
            }
        }
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce().unwrap();
        assert_eq!(nonce1.len(), NONCE_SIZE);

        // Two nonces generated at the same time should still differ
        // (because of wrapping_add with index)
        let nonce2 = generate_nonce().unwrap();
        assert_eq!(nonce2.len(), NONCE_SIZE);
    }

    #[test]
    fn test_build_ocsp_request_with_nonce() {
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let issuer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));
        let (_, cert_der) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).unwrap();
        let (_, issuer_der) = pem_rfc7468::decode_vec(issuer_pem.as_bytes()).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();
        let issuer = Certificate::from_der(&issuer_der).unwrap();

        let (request, nonce) = build_ocsp_request_with_nonce(&cert, &issuer).unwrap();
        assert!(!request.is_empty());
        assert_eq!(request[0], 0x30); // SEQUENCE
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_validate_nonce_direct_match() {
        let nonce = b"test-nonce-12345678901234567890";
        assert!(validate_nonce(nonce, nonce).is_ok());
    }

    #[test]
    fn test_validate_nonce_der_wrapped() {
        let nonce = b"test-nonce-data-here";
        let wrapped = der_utils::encode_tlv(0x04, nonce);
        // Response has DER-wrapped nonce, request has raw nonce
        assert!(validate_nonce(nonce, &wrapped).is_ok());
    }

    #[test]
    fn test_validate_nonce_mismatch() {
        let nonce1 = b"nonce-one-aaaaaaaaaaaaaaaaaaa";
        let nonce2 = b"nonce-two-bbbbbbbbbbbbbbbbbbb";
        assert!(validate_nonce(nonce1, nonce2).is_err());
    }

    // ── Synthetic OCSP response tests ────────────────────────────────

    fn load_test_cert(pem_str: &str) -> Certificate {
        let (_, der) = pem_rfc7468::decode_vec(pem_str.as_bytes()).unwrap();
        Certificate::from_der(&der).unwrap()
    }

    fn intermediate_ca_cert() -> Certificate {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));
        load_test_cert(pem)
    }

    fn intermediate_ca_key_pem_path() -> &'static str {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_key.pem"
        )
    }

    fn signer_cert() -> Certificate {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        load_test_cert(pem)
    }

    /// Build a synthetic OCSP response signed by the intermediate CA key.
    ///
    /// Constructs a minimal OCSPResponse → BasicOCSPResponse by hand:
    /// - responseStatus: successful
    /// - tbsResponseData with responderID byName, producedAt, single response
    /// - Signed with the intermediate CA's RSA key
    fn build_test_ocsp_response(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        cert: &Certificate,
        status: &CertStatus,
        nonce: Option<&[u8]>,
    ) -> Vec<u8> {
        // Default window: produced/thisUpdate 2026-06-01T12:00Z,
        // nextUpdate 2026-06-08T12:00Z.
        build_test_ocsp_response_with_times(
            issuer_cert,
            issuer_key_pem,
            cert,
            status,
            nonce,
            "20260601120000Z",
            "20260601120000Z",
            Some("20260608120000Z"),
        )
    }

    /// Build a synthetic OCSP response with the given (already-encoded)
    /// responderID TLV, signed with `issuer_key_pem`. Lets a test stamp a
    /// responderID that intentionally does NOT match the signer.
    fn build_test_ocsp_response_with_responder_id(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        cert: &Certificate,
        status: &CertStatus,
        responder_id_tlv: &[u8],
    ) -> Vec<u8> {
        build_test_ocsp_response_full(
            issuer_cert,
            issuer_key_pem,
            cert,
            status,
            None,
            "20260601120000Z",
            "20260601120000Z",
            Some("20260608120000Z"),
            responder_id_tlv,
        )
    }

    /// Like [`build_test_ocsp_response`] but with explicit `producedAt`,
    /// `thisUpdate`, and optional `nextUpdate` GeneralizedTime strings.
    #[allow(clippy::too_many_arguments)]
    fn build_test_ocsp_response_with_times(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        cert: &Certificate,
        status: &CertStatus,
        nonce: Option<&[u8]>,
        produced_at_str: &str,
        this_update_str: &str,
        next_update_str: Option<&str>,
    ) -> Vec<u8> {
        // Default: responderID byName = the issuer's subject (the responder is
        // the issuing CA).
        let issuer_subject_der = issuer_cert.tbs_certificate.subject.to_der().unwrap();
        let responder_id = der_utils::encode_tlv(0xA1, &issuer_subject_der);
        build_test_ocsp_response_full(
            issuer_cert,
            issuer_key_pem,
            cert,
            status,
            nonce,
            produced_at_str,
            this_update_str,
            next_update_str,
            &responder_id,
        )
    }

    /// Core synthetic-OCSP-response builder taking every field explicitly,
    /// including the already-encoded responderID TLV.
    #[allow(clippy::too_many_arguments)]
    fn build_test_ocsp_response_full(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        cert: &Certificate,
        status: &CertStatus,
        nonce: Option<&[u8]>,
        produced_at_str: &str,
        this_update_str: &str,
        next_update_str: Option<&str>,
        responder_id_tlv: &[u8],
    ) -> Vec<u8> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;

        // Build tbsResponseData body
        let mut tbs_body = Vec::new();

        // responderID: caller-supplied [1] byName / [2] byKeyHash TLV.
        tbs_body.extend_from_slice(responder_id_tlv);

        // producedAt GeneralizedTime
        let produced_at = der_utils::encode_tlv(0x18, produced_at_str.as_bytes());
        tbs_body.extend_from_slice(&produced_at);

        // Build SingleResponse
        let single_response = build_test_single_response_with_times(
            issuer_cert,
            cert,
            status,
            this_update_str,
            next_update_str,
        );

        // responses SEQUENCE OF SingleResponse
        let responses_seq = der_utils::encode_sequence_from_parts(&[&single_response]);
        tbs_body.extend_from_slice(&responses_seq);

        // responseExtensions [1] with nonce if provided
        if let Some(nonce_bytes) = nonce {
            let nonce_oid_tlv = der_utils::encode_tlv(0x06, OCSP_NONCE_OID_BYTES);
            let nonce_inner = der_utils::encode_tlv(0x04, nonce_bytes);
            let nonce_outer = der_utils::encode_tlv(0x04, &nonce_inner);
            let nonce_ext = der_utils::encode_sequence_from_parts(&[&nonce_oid_tlv, &nonce_outer]);
            let extensions_seq = der_utils::encode_sequence_from_parts(&[&nonce_ext]);
            let response_extensions = der_utils::encode_tlv(0xA1, &extensions_seq);
            tbs_body.extend_from_slice(&response_extensions);
        }

        // Wrap as tbsResponseData SEQUENCE
        let tbs_der = der_utils::encode_sequence_raw(&tbs_body);

        // Sign TBS
        let key_der = pem_rfc7468::decode_vec(issuer_key_pem.as_bytes())
            .unwrap()
            .1;
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature: rsa::pkcs1v15::Signature = signing_key.sign(&tbs_der);
        let sig_bytes = signature.to_vec();

        // signatureAlgorithm: sha256WithRSAEncryption
        let sha256_rsa_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let alg_id = der_utils::encode_sequence_from_parts(&[sha256_rsa_oid, &[0x05, 0x00]]);

        // signature BIT STRING
        let mut bit_string_value = vec![0x00];
        bit_string_value.extend_from_slice(&sig_bytes);
        let sig_bit_string = der_utils::encode_tlv(0x03, &bit_string_value);

        // BasicOCSPResponse SEQUENCE { tbs, alg, sig }
        let basic_response =
            der_utils::encode_sequence_from_parts(&[&tbs_der, &alg_id, &sig_bit_string]);

        // ResponseBytes SEQUENCE { responseType OID, response OCTET STRING }
        let basic_oid_tlv = der_utils::encode_tlv(0x06, OCSP_BASIC_RESPONSE_OID);
        let basic_octet = der_utils::encode_tlv(0x04, &basic_response);
        let response_bytes_seq =
            der_utils::encode_sequence_from_parts(&[&basic_oid_tlv, &basic_octet]);

        // responseBytes [0] EXPLICIT
        let response_bytes_tagged = der_utils::encode_tlv(0xA0, &response_bytes_seq);

        // responseStatus ENUMERATED successful (0)
        let response_status = der_utils::encode_tlv(0x0A, &[0x00]);

        // OCSPResponse SEQUENCE
        der_utils::encode_sequence_from_parts(&[&response_status, &response_bytes_tagged])
    }

    /// Build a synthetic SingleResponse for a certificate with explicit
    /// `thisUpdate` and optional `nextUpdate` GeneralizedTime strings.
    fn build_test_single_response_with_times(
        issuer_cert: &Certificate,
        cert: &Certificate,
        status: &CertStatus,
        this_update_str: &str,
        next_update_str: Option<&str>,
    ) -> Vec<u8> {
        // CertID
        let issuer_name_der = issuer_cert.tbs_certificate.subject.to_der().unwrap();
        let issuer_name_hash = sha1_hash(&issuer_name_der).unwrap();
        let issuer_key_bytes = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let issuer_key_hash = sha1_hash(&issuer_key_bytes).unwrap();

        let serial = cert.tbs_certificate.serial_number.to_der().unwrap();

        let sha1_alg_id = build_sha1_algorithm_identifier().unwrap();
        let name_hash_oct = der_utils::encode_tlv(0x04, &issuer_name_hash);
        let key_hash_oct = der_utils::encode_tlv(0x04, &issuer_key_hash);
        let cert_id = der_utils::encode_sequence_from_parts(&[
            &sha1_alg_id,
            &name_hash_oct,
            &key_hash_oct,
            &serial,
        ]);

        // certStatus
        let cert_status_der = match status {
            CertStatus::Good => {
                // good [0] IMPLICIT NULL
                der_utils::encode_tlv(0x80, &[])
            }
            CertStatus::Revoked {
                revocation_time,
                reason,
            } => {
                // revoked [1] IMPLICIT RevokedInfo
                let rt_str = revocation_time.format("%Y%m%d%H%M%SZ").to_string();
                let mut revoked_body = der_utils::encode_tlv(0x18, rt_str.as_bytes());
                if *reason != RevocationReason::Unspecified {
                    let reason_enum = der_utils::encode_tlv(0x0A, &[reason.code()]);
                    let reason_explicit = der_utils::encode_tlv(0xA0, &reason_enum);
                    revoked_body.extend_from_slice(&reason_explicit);
                }
                der_utils::encode_tlv(0xA1, &revoked_body)
            }
            CertStatus::Unknown => {
                // unknown [2] IMPLICIT NULL
                der_utils::encode_tlv(0x82, &[])
            }
        };

        // thisUpdate GeneralizedTime
        let this_update = der_utils::encode_tlv(0x18, this_update_str.as_bytes());

        // SingleResponse SEQUENCE { certID, certStatus, thisUpdate[, nextUpdate] }
        let mut parts: Vec<&[u8]> = vec![&cert_id, &cert_status_der, &this_update];

        // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
        let next_update;
        if let Some(nu_str) = next_update_str {
            let next_update_gt = der_utils::encode_tlv(0x18, nu_str.as_bytes());
            next_update = der_utils::encode_tlv(0xA0, &next_update_gt);
            parts.push(&next_update);
        }

        der_utils::encode_sequence_from_parts(&parts)
    }

    #[test]
    fn test_parse_ocsp_response_good() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        let parsed = parse_ocsp_response(&response_der).unwrap();
        assert_eq!(parsed.responses.len(), 1);
        assert!(matches!(parsed.responses[0].cert_status, CertStatus::Good));
        assert!(parsed.nonce.is_none());
        assert!(parsed.embedded_certs_der.is_empty());
    }

    #[test]
    fn test_parse_ocsp_response_revoked() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let revocation_time = chrono::DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let status = CertStatus::Revoked {
            revocation_time,
            reason: RevocationReason::KeyCompromise,
        };

        let response_der = build_test_ocsp_response(&issuer, &key_pem, &cert, &status, None);

        let parsed = parse_ocsp_response(&response_der).unwrap();
        assert_eq!(parsed.responses.len(), 1);
        match &parsed.responses[0].cert_status {
            CertStatus::Revoked { reason, .. } => {
                assert_eq!(*reason, RevocationReason::KeyCompromise);
            }
            other => panic!("expected Revoked, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_ocsp_response_with_nonce() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let nonce = b"test-nonce-1234567890abcdef1234";

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, Some(nonce));

        let parsed = parse_ocsp_response(&response_der).unwrap();
        assert!(parsed.nonce.is_some());
        assert_eq!(parsed.nonce.as_deref(), Some(nonce.as_slice()));
    }

    #[test]
    fn test_check_revocation_good() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_valid(), "should be valid: {status}");
    }

    #[test]
    fn test_check_revocation_revoked() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let revocation_time = chrono::DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cert_status = CertStatus::Revoked {
            revocation_time,
            reason: RevocationReason::Superseded,
        };

        let response_der = build_test_ocsp_response(&issuer, &key_pem, &cert, &cert_status, None);

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_revoked(), "should be revoked: {status}");
    }

    #[test]
    fn test_check_revocation_time_aware_future_revocation() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // Revocation time is 2027-01-01, validation time is 2026-06-01
        // → should be VALID at validation_time
        let revocation_time = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cert_status = CertStatus::Revoked {
            revocation_time,
            reason: RevocationReason::Unspecified,
        };

        let response_der = build_test_ocsp_response(&issuer, &key_pem, &cert, &cert_status, None);

        // Validation time (2026-06-01T00:00Z) is the historical instant; the
        // response was produced shortly after (thisUpdate 2026-06-01T12:00Z,
        // nextUpdate 2026-06-08T12:00Z). Later-collected evidence is accepted,
        // and the 2027 revocation is in the future, so the result is Valid.
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(
            status.is_valid(),
            "should be valid (revocation in future): {status}"
        );
    }

    // ── H-2: OCSP response freshness (RFC 6960 §4.2.2.1) ─────────────

    #[test]
    fn test_check_revocation_rejects_stale_good() {
        // A legitimately-signed "good" response is replayed long after its
        // nextUpdate (2026-06-08T12:00Z). It must NOT be accepted as Valid.
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        // Far past nextUpdate (the replay window the old code accepted forever).
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-09-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let err = check_revocation(&response_der, &cert, &issuer, None, Some(validation_time))
            .expect_err("stale OCSP response must be rejected");
        assert!(
            matches!(err, LtvError::Ocsp(ref m) if m.contains("stale")),
            "expected stale error, got: {err}"
        );
    }

    #[test]
    fn test_check_revocation_accepts_later_produced_evidence() {
        // Archival/LTV: the response is produced *after* the historical
        // validation instant. With thisUpdate <= validation_time < producedAt
        // <= nextUpdate, the response is valid evidence and must be accepted —
        // producedAt being after the validation instant is not a freshness
        // failure (producedAt is the responder's signing time, not a status
        // assertion time).
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // thisUpdate 12:00, producedAt 14:00, nextUpdate 2026-06-08; the
        // validation instant 13:00 sits between thisUpdate and producedAt.
        let response_der = build_test_ocsp_response_with_times(
            &issuer,
            &key_pem,
            &cert,
            &CertStatus::Good,
            None,
            "20260601140000Z",       // producedAt (after validation_time)
            "20260601120000Z",       // thisUpdate (<= validation_time)
            Some("20260608120000Z"), // nextUpdate
        );

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T13:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(
            status.is_valid(),
            "later-produced OCSP evidence must remain acceptable: {status}"
        );
    }

    #[test]
    fn test_check_revocation_accepts_stale_within_skew() {
        // Just past nextUpdate (2026-06-08T12:00Z) but within the default 5m
        // clock skew — still accepted.
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        // 3 minutes after nextUpdate — inside the 5-minute skew.
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-08T12:03:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_valid(), "should be valid within skew: {status}");
    }

    #[test]
    fn test_validate_response_freshness_no_next_update_max_age() {
        // With nextUpdate absent, the response is fresh up to max_age from
        // thisUpdate and stale beyond it.
        let this_update = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let sr = SingleResponse {
            hash_algorithm_oid: vec![],
            issuer_name_hash: vec![],
            issuer_key_hash: vec![],
            serial_number: vec![],
            cert_status: CertStatus::Good,
            this_update,
            next_update: None,
        };
        let freshness = OcspFreshness::default(); // 24h max age, 5m skew

        // 12 hours later — within the 24h bound.
        let within = this_update + chrono::Duration::hours(12);
        assert!(validate_response_freshness(&sr, within, &freshness).is_ok());

        // Validation instant *before* thisUpdate (later-collected evidence) is
        // always within bound.
        let before = this_update - chrono::Duration::hours(6);
        assert!(validate_response_freshness(&sr, before, &freshness).is_ok());

        // 25 hours later — beyond the 24h bound (+ skew).
        let beyond = this_update + chrono::Duration::hours(25);
        let err = validate_response_freshness(&sr, beyond, &freshness)
            .expect_err("response older than max age must be rejected");
        assert!(
            matches!(err, LtvError::Ocsp(ref m) if m.contains("too old")),
            "got: {err}"
        );
    }

    #[test]
    fn test_check_revocation_unknown_status() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Unknown, None);

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_unknown(), "should be unknown: {status}");
    }

    #[test]
    fn test_check_revocation_with_valid_nonce() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();
        let nonce = b"test-nonce-1234567890abcdef1234";

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, Some(nonce));

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status = check_revocation(
            &response_der,
            &cert,
            &issuer,
            Some(nonce),
            Some(validation_time),
        )
        .unwrap();
        assert!(status.is_valid(), "should be valid with nonce: {status}");
    }

    #[test]
    fn strict_nonce_requires_echo_without_changing_opportunistic_default() {
        let issuer = intermediate_ca_cert();
        let cert = signer_cert();
        let key = std::fs::read_to_string(intermediate_ca_key_pem_path()).unwrap();
        let nonce = b"nonce-binding-test";
        let at = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let policy = crate::crypto::verify::SignaturePolicy::strict();
        let freshness = OcspFreshness::default();
        let absent = build_test_ocsp_response(&issuer, &key, &cert, &CertStatus::Good, None);
        // Even direct-issuer responses must reach the supplied trust store
        // when using the complete-path API; an arbitrary caller-provided CA
        // must not bypass that trust boundary.
        let empty_store = crate::trust::TrustStore::new();
        assert!(check_revocation_detailed_with_issuer_path(
            &absent,
            &cert,
            &issuer,
            None,
            Some(at),
            &policy,
            &freshness,
            std::slice::from_ref(&issuer),
            &empty_store,
            false
        )
        .is_err());
        assert!(check_revocation_detailed(
            &absent,
            &cert,
            &issuer,
            Some(nonce),
            Some(at),
            &policy,
            &freshness
        )
        .unwrap()
        .status
        .is_valid());
        assert!(check_revocation_detailed_with_nonce_policy(
            &absent,
            &cert,
            &issuer,
            Some(nonce),
            Some(at),
            &policy,
            &freshness,
            true
        )
        .is_err());
        assert!(check_revocation_detailed_with_nonce_policy(
            &absent,
            &cert,
            &issuer,
            None,
            Some(at),
            &policy,
            &freshness,
            true
        )
        .is_err());
        assert!(check_revocation_detailed_with_nonce_policy(
            &absent,
            &cert,
            &issuer,
            Some(&[]),
            Some(at),
            &policy,
            &freshness,
            true
        )
        .is_err());
        for response_nonce in [nonce.as_slice(), b"different-nonce".as_slice()] {
            let response = build_test_ocsp_response(
                &issuer,
                &key,
                &cert,
                &CertStatus::Good,
                Some(response_nonce),
            );
            assert_eq!(
                check_revocation_detailed_with_nonce_policy(
                    &response,
                    &cert,
                    &issuer,
                    Some(nonce),
                    Some(at),
                    &policy,
                    &freshness,
                    true
                )
                .is_ok(),
                response_nonce == nonce
            );
        }
    }

    fn encode_parsed_ocsp_fixture(parsed: &ParsedBasicOcspResponse) -> Vec<u8> {
        use der::asn1::BitString;
        let signature = BitString::from_bytes(&parsed.signature_bytes)
            .unwrap()
            .to_der()
            .unwrap();
        let certs = der_utils::encode_tlv(
            0xA0,
            &der_utils::encode_sequence_raw(&parsed.embedded_certs_der.concat()),
        );
        let basic = der_utils::encode_sequence_from_parts(&[
            &parsed.tbs_response_data,
            &parsed.signature_algorithm.to_der().unwrap(),
            &signature,
            &certs,
        ]);
        let response_bytes = der_utils::encode_sequence_from_parts(&[
            &const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1")
                .to_der()
                .unwrap(),
            &der_utils::encode_tlv(0x04, &basic),
        ]);
        der_utils::encode_sequence_from_parts(&[
            &[0x0A, 0x01, 0x00],
            &der_utils::encode_tlv(0xA0, &response_bytes),
        ])
    }

    #[test]
    fn signed_ocsp_rejects_critical_duplicate_and_malformed_extensions_in_both_contexts() {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;
        let issuer = intermediate_ca_cert();
        let cert = signer_cert();
        let pem = std::fs::read_to_string(intermediate_ca_key_pem_path()).unwrap();
        let key =
            rsa::RsaPrivateKey::from_pkcs8_der(&pem_rfc7468::decode_vec(pem.as_bytes()).unwrap().1)
                .unwrap();
        let direct = build_test_ocsp_response(&issuer, &pem, &cert, &CertStatus::Good, None);
        let mut parsed = parse_ocsp_response(&direct).unwrap();
        let (_, body) = der_utils::parse_tlv(&parsed.tbs_response_data).unwrap();
        let mut fields = Vec::new();
        let mut pos = body.as_slice();
        while !pos.is_empty() {
            let (_, _, rest) = der_utils::parse_tlv_with_rest(pos).unwrap();
            fields.push(pos[..pos.len() - rest.len()].to_vec());
            pos = rest;
        }
        let optional = responder_extension("1.2.3.4.5", false, &[0x05, 0x00])
            .to_der()
            .unwrap();
        let critical = responder_extension("1.2.3.4.5", true, &[0x05, 0x00])
            .to_der()
            .unwrap();
        let nonce = responder_extension(
            "1.3.6.1.5.5.7.48.1.2",
            false,
            &der_utils::encode_tlv(0x04, b"bounded-nonce"),
        )
        .to_der()
        .unwrap();
        let cases = [
            (optional.clone(), true, true),
            (critical, false, false),
            ([optional.clone(), optional].concat(), false, false),
            ([nonce.clone(), nonce.clone()].concat(), false, false),
            (nonce, true, false),
            (vec![0x30, 0x03, 0x06, 0x01, 0x2A], false, false),
        ];
        let at = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for (extensions, response_allowed, single_allowed) in cases {
            for single in [false, true] {
                let mut new_fields = fields.clone();
                let wrapper =
                    der_utils::encode_tlv(0xA1, &der_utils::encode_sequence_raw(&extensions));
                if single {
                    let (_, responses) = der_utils::parse_tlv(&new_fields[2]).unwrap();
                    let (_, single_body) = der_utils::parse_tlv(&responses).unwrap();
                    new_fields[2] = der_utils::encode_sequence_raw(
                        &der_utils::encode_sequence_raw(&[single_body, wrapper].concat()),
                    );
                } else {
                    new_fields.push(wrapper);
                }
                parsed.tbs_response_data = der_utils::encode_sequence_raw(&new_fields.concat());
                let signature: rsa::pkcs1v15::Signature =
                    rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
                        .sign(&parsed.tbs_response_data);
                parsed.signature_bytes = signature.to_vec();
                let response = encode_parsed_ocsp_fixture(&parsed);
                assert_eq!(
                    check_revocation(&response, &cert, &issuer, None, Some(at)).is_ok(),
                    if single {
                        single_allowed
                    } else {
                        response_allowed
                    }
                );
            }
        }
        let wrapped = [
            der_utils::encode_tlv(0x04, b"bounded-nonce"),
            vec![0x05, 0x00],
        ]
        .concat();
        assert!(validate_nonce(b"bounded-nonce", &wrapped).is_err());
    }

    #[test]
    fn direct_issuer_uses_exact_caller_validity_despite_embedded_same_key_hints() {
        let issuer = intermediate_ca_cert();
        let cert = signer_cert();
        let key = std::fs::read_to_string(intermediate_ca_key_pem_path()).unwrap();
        let response = build_test_ocsp_response(&issuer, &key, &cert, &CertStatus::Good, None);
        let mut parsed = parse_ocsp_response(&response).unwrap();
        let mut hint = issuer.clone();
        hint.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[91]).unwrap();
        hint.tbs_certificate.validity.not_before =
            x509_cert::time::Time::GeneralTime(der::asn1::GeneralizedTime::from_date_time(
                der::DateTime::new(2027, 1, 1, 0, 0, 0).unwrap(),
            ));
        parsed.embedded_certs_der = vec![hint.to_der().unwrap()];
        let at = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let policy = crate::crypto::verify::SignaturePolicy::strict();
        assert_eq!(
            verify_ocsp_response_signature(&parsed, &issuer, &policy).unwrap(),
            issuer
        );
        let response = encode_parsed_ocsp_fixture(&parsed);
        assert!(check_revocation(&response, &cert, &issuer, None, Some(at))
            .unwrap()
            .is_valid());
        let mut expired_caller = issuer;
        expired_caller.tbs_certificate.validity.not_after =
            x509_cert::time::Time::GeneralTime(der::asn1::GeneralizedTime::from_date_time(
                der::DateTime::new(2025, 1, 1, 0, 0, 0).unwrap(),
            ));
        assert!(
            check_revocation(&response, &cert, &expired_caller, None, Some(at))
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
    }

    #[test]
    fn delegated_ocsp_requires_complete_path_and_obeys_ancestor_constraints_even_with_nocheck() {
        use der::asn1::BitString;
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
        use rsa::signature::{Keypair, SignatureEncoding, Signer};
        use sha2::Sha256;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;
        let root_pem = std::fs::read_to_string(intermediate_ca_key_pem_path()).unwrap();
        let root_key = rsa::RsaPrivateKey::from_pkcs8_der(
            &pem_rfc7468::decode_vec(root_pem.as_bytes()).unwrap().1,
        )
        .unwrap();
        let issuer_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let responder_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let issue = |profile,
                     subject: &str,
                     key: &rsa::RsaPrivateKey,
                     signer_key: &rsa::RsaPrivateKey,
                     extensions: Vec<x509_cert::ext::Extension>| {
            let subject_signer = SigningKey::<Sha256>::new(key.clone());
            let signer = SigningKey::<Sha256>::new(signer_key.clone());
            let spki = SubjectPublicKeyInfoOwned::from_key(subject_signer.verifying_key()).unwrap();
            let mut cert = CertificateBuilder::new(
                profile,
                SerialNumber::new(&[1]).unwrap(),
                Validity::from_now(Duration::from_secs(3600)).unwrap(),
                subject.parse().unwrap(),
                spki,
                &signer,
            )
            .unwrap()
            .build()
            .unwrap();
            cert.tbs_certificate
                .extensions
                .get_or_insert_default()
                .extend(extensions);
            let signature: rsa::pkcs1v15::Signature =
                signer.sign(&cert.tbs_certificate.to_der().unwrap());
            cert.signature = BitString::from_bytes(&signature.to_vec()).unwrap();
            cert
        };
        let dns_constraint = der_utils::encode_sequence_raw(&der_utils::encode_tlv(
            0xA0,
            &der_utils::encode_sequence_raw(&der_utils::encode_tlv(0x82, b".allowed.example")),
        ));
        let root = issue(
            Profile::Root,
            "CN=Responder Path Root",
            &root_key,
            &root_key,
            vec![responder_extension("2.5.29.30", true, &dns_constraint)],
        );
        let mut issuer = issue(
            Profile::SubCA {
                issuer: root.tbs_certificate.subject.clone(),
                path_len_constraint: None,
            },
            "CN=Responder Path Issuer",
            &issuer_key,
            &root_key,
            vec![],
        );
        // RFC 5280 permits CA certificates without KeyUsage. The path-aware
        // OCSP API must agree with generic TrustStore validation on this.
        issuer
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|ext| ext.extn_id.to_string() != "2.5.29.15");
        let issuer_signature: rsa::pkcs1v15::Signature =
            SigningKey::<Sha256>::new(root_key.clone())
                .sign(&issuer.tbs_certificate.to_der().unwrap());
        issuer.signature = BitString::from_bytes(&issuer_signature.to_vec()).unwrap();
        let mut store = crate::trust::TrustStore::new();
        store.add_certificate(root).unwrap();
        let issuer_pem = issuer_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        // Certificate construction can cross a second on busy hosts; keep
        // the validation instant after all generated notBefore values.
        let now = chrono::Utc::now() + chrono::Duration::minutes(1);
        let at_string = now.format("%Y%m%d%H%M%SZ").to_string();
        let next = (now + chrono::Duration::minutes(10))
            .format("%Y%m%d%H%M%SZ")
            .to_string();
        let direct = build_test_ocsp_response_with_times(
            &issuer,
            &issuer_pem,
            &signer_cert(),
            &CertStatus::Good,
            None,
            &at_string,
            &at_string,
            Some(&next),
        );
        let parsed = parse_ocsp_response(&direct).unwrap();
        for (dns, valid) in [
            ("responder.allowed.example", true),
            ("responder.other.example", false),
        ] {
            let eku = der_utils::encode_sequence_raw(
                &const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9")
                    .to_der()
                    .unwrap(),
            );
            let san = der_utils::encode_sequence_raw(&der_utils::encode_tlv(0x82, dns.as_bytes()));
            let responder = issue(
                Profile::Leaf {
                    issuer: issuer.tbs_certificate.subject.clone(),
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                },
                "CN=Delegated Responder",
                &responder_key,
                &issuer_key,
                vec![
                    responder_extension("2.5.29.37", false, &eku),
                    responder_extension("2.5.29.17", false, &san),
                    responder_extension("1.3.6.1.5.5.7.48.1.5", false, &[0x05, 0x00]),
                ],
            );
            let (_, body) = der_utils::parse_tlv(&parsed.tbs_response_data).unwrap();
            let (_, _, after_id) = der_utils::parse_tlv_with_rest(&body).unwrap();
            let responder_id =
                der_utils::encode_tlv(0xA1, &responder.tbs_certificate.subject.to_der().unwrap());
            let tbs = der_utils::encode_sequence_raw(&[responder_id, after_id.to_vec()].concat());
            let signature: rsa::pkcs1v15::Signature =
                SigningKey::<Sha256>::new(responder_key.clone()).sign(&tbs);
            let signature = BitString::from_bytes(&signature.to_vec())
                .unwrap()
                .to_der()
                .unwrap();
            let certs = der_utils::encode_tlv(
                0xA0,
                &der_utils::encode_sequence_raw(&responder.to_der().unwrap()),
            );
            let basic = der_utils::encode_sequence_from_parts(&[
                &tbs,
                &parsed.signature_algorithm.to_der().unwrap(),
                &signature,
                &certs,
            ]);
            let response_bytes = der_utils::encode_sequence_from_parts(&[
                &const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1")
                    .to_der()
                    .unwrap(),
                &der_utils::encode_tlv(0x04, &basic),
            ]);
            let response = der_utils::encode_sequence_from_parts(&[
                &[0x0A, 0x01, 0x00],
                &der_utils::encode_tlv(0xA0, &response_bytes),
            ]);
            let policy = crate::crypto::verify::SignaturePolicy::strict();
            let freshness = OcspFreshness::default();
            let denied = check_revocation_detailed(
                &response,
                &signer_cert(),
                &issuer,
                None,
                Some(now),
                &policy,
                &freshness,
            )
            .unwrap_err();
            assert!(
                denied.to_string().contains("complete issuer path"),
                "{denied}"
            );
            let result = check_revocation_detailed_with_issuer_path(
                &response,
                &signer_cert(),
                &issuer,
                None,
                Some(now),
                &policy,
                &freshness,
                std::slice::from_ref(&issuer),
                &store,
                false,
            );
            assert_eq!(result.is_ok(), valid, "{dns}: {result:?}");
            if valid {
                assert!(result.unwrap().status.is_valid());
                let mut restricted_issuer = issuer.clone();
                restricted_issuer
                    .tbs_certificate
                    .extensions
                    .as_mut()
                    .unwrap()
                    .push(responder_extension("2.5.29.37", true, &eku));
                let signature: rsa::pkcs1v15::Signature =
                    SigningKey::<Sha256>::new(root_key.clone())
                        .sign(&restricted_issuer.tbs_certificate.to_der().unwrap());
                restricted_issuer.signature = BitString::from_bytes(&signature.to_vec()).unwrap();
                let err = check_revocation_detailed_with_issuer_path(
                    &response,
                    &signer_cert(),
                    &restricted_issuer,
                    None,
                    Some(now),
                    &policy,
                    &freshness,
                    std::slice::from_ref(&restricted_issuer),
                    &store,
                    false,
                )
                .unwrap_err();
                assert!(
                    err.to_string().contains("critical CA extendedKeyUsage"),
                    "{err}"
                );
            }
        }
    }

    #[test]
    fn test_parse_ocsp_response_invalid_data() {
        // Not a valid OCSP response
        let result = parse_ocsp_response(&[0x04, 0x00]); // OCTET STRING
        assert!(result.is_err());
    }

    #[test]
    fn test_has_ocsp_nocheck_extension() {
        // Our test certs don't have this extension, so this tests the negative case
        let cert = signer_cert();
        assert!(!has_ocsp_nocheck_extension(&cert));
    }

    fn responder_extension(oid: &str, critical: bool, value: &[u8]) -> x509_cert::ext::Extension {
        x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new(oid).unwrap(),
            critical,
            extn_value: der::asn1::OctetString::new(value).unwrap(),
        }
    }

    fn delegated_profile_cert() -> Certificate {
        let mut cert = signer_cert();
        let oid = der_utils::encode_tlv(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]);
        let eku = der_utils::encode_sequence_from_parts(&[&oid]);
        cert.tbs_certificate.extensions = Some(vec![responder_extension("2.5.29.37", false, &eku)]);
        cert
    }

    #[test]
    fn issuer_identity_requires_the_public_key_and_allows_same_key_reissue() {
        let issuer = intermediate_ca_cert();
        let mut reissued = issuer.clone();
        reissued.tbs_certificate.serial_number = signer_cert().tbs_certificate.serial_number;
        assert!(certs_have_same_identity(&reissued, &issuer));

        reissued.tbs_certificate.subject_public_key_info =
            signer_cert().tbs_certificate.subject_public_key_info;
        assert!(!certs_have_same_identity(&reissued, &issuer));
    }

    #[test]
    fn responder_trust_rejects_same_name_with_a_different_key() {
        let issuer = intermediate_ca_cert();
        let mut responder = signer_cert();
        responder.tbs_certificate.subject = issuer.tbs_certificate.subject.clone();
        let now = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // Only authorization is under test; no response or signature is built.
        let parsed = ParsedBasicOcspResponse {
            tbs_response_data: Vec::new(),
            signature_algorithm: issuer.signature_algorithm.clone(),
            signature_bytes: Vec::new(),
            responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.to_der().unwrap()),
            produced_at: now,
            responses: Vec::new(),
            nonce: None,
            embedded_certs_der: Vec::new(),
        };
        let error = validate_responder_trust(
            &responder,
            &issuer,
            &parsed,
            &crate::crypto::verify::SignaturePolicy::default(),
            now,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not issued by the expected CA"));
    }

    #[test]
    fn delegated_responder_key_usage_must_permit_signing() {
        assert!(validate_delegated_responder_extensions(&delegated_profile_cert()).is_ok());
        let mut malformed = delegated_profile_cert();
        malformed
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(responder_extension(
                "2.5.29.15",
                true,
                &[0x03, 0x02, 0x01, 0x81],
            ));
        assert!(validate_delegated_responder_extensions(&malformed).is_err());
        for allowed in [0x80, 0x40] {
            let mut cert = delegated_profile_cert();
            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(responder_extension(
                    "2.5.29.15",
                    true,
                    &der_utils::encode_tlv(0x03, &[0x00, allowed]),
                ));
            assert!(validate_delegated_responder_extensions(&cert).is_ok());
        }
        let mut cert = delegated_profile_cert();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(responder_extension(
                "2.5.29.15",
                true,
                &der_utils::encode_tlv(0x03, &[0x00, 0x20]),
            ));
        let error = validate_delegated_responder_extensions(&cert).unwrap_err();
        assert!(error
            .to_string()
            .contains("keyUsage does not permit signing"));
    }

    #[test]
    fn delegated_responder_rejects_unprocessed_critical_and_duplicate_extensions() {
        let mut cert = delegated_profile_cert();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(responder_extension("1.2.3.4", true, &[0x05, 0x00]));
        let error = validate_delegated_responder_extensions(&cert).unwrap_err();
        assert!(error.to_string().contains("unprocessed critical extension"));
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .last_mut()
            .unwrap()
            .critical = false;
        assert!(validate_delegated_responder_extensions(&cert).is_ok());

        let mut cert = delegated_profile_cert();
        let duplicate = cert.tbs_certificate.extensions.as_ref().unwrap()[0].clone();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(duplicate);
        assert!(validate_delegated_responder_extensions(&cert)
            .unwrap_err()
            .to_string()
            .contains("duplicate extension"));
    }

    #[test]
    fn delegated_responder_nocheck_requires_der_null() {
        let mut cert = delegated_profile_cert();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(responder_extension(
                "1.3.6.1.5.5.7.48.1.5",
                false,
                &[0x05, 0x00],
            ));
        assert!(has_ocsp_nocheck_extension(&cert));
        assert!(validate_delegated_responder_extensions(&cert).is_ok());

        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .last_mut()
            .unwrap()
            .extn_value = der::asn1::OctetString::new([0x04, 0x00]).unwrap();
        assert!(!has_ocsp_nocheck_extension(&cert));
        assert!(validate_delegated_responder_extensions(&cert).is_err());
    }

    #[test]
    fn test_responder_id_variants() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        let parsed = parse_ocsp_response(&response_der).unwrap();
        // Our synthetic response uses byName
        assert!(matches!(parsed.responder_id, ResponderId::ByName(_)));
    }

    // ── B2/M7: responder_id matching + nocheck consultation ───────────

    #[test]
    fn test_responder_matches_responder_id_byname() {
        let issuer = intermediate_ca_cert();
        let issuer_subject = issuer.tbs_certificate.subject.to_der().unwrap();

        // Correct byName matches the issuer (the responder) subject.
        assert!(responder_matches_responder_id(
            &issuer,
            &ResponderId::ByName(issuer_subject.clone())
        )
        .is_ok());

        // A different DN (the signer's subject) must NOT match.
        let other = signer_cert().tbs_certificate.subject.to_der().unwrap();
        let err = responder_matches_responder_id(&issuer, &ResponderId::ByName(other))
            .expect_err("mismatched responderID byName must be rejected");
        assert!(
            matches!(err, LtvError::Ocsp(ref m) if m.contains("byName")),
            "got {err}"
        );
    }

    #[test]
    fn test_responder_matches_responder_id_bykeyhash() {
        let issuer = intermediate_ca_cert();
        let key_bytes = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let correct = sha1_hash(&key_bytes).unwrap();
        assert!(responder_matches_responder_id(&issuer, &ResponderId::ByKeyHash(correct)).is_ok());

        let wrong = sha1_hash(b"not the responder key").unwrap();
        let err = responder_matches_responder_id(&issuer, &ResponderId::ByKeyHash(wrong))
            .expect_err("mismatched responderID byKeyHash must be rejected");
        assert!(
            matches!(err, LtvError::Ocsp(ref m) if m.contains("byKeyHash")),
            "got {err}"
        );
    }

    #[test]
    fn test_check_revocation_rejects_wrong_responder_id() {
        // B2/M7: a response whose responderID (byName) names a *different*
        // certificate than the one whose key actually signed it must be
        // rejected — the responder cannot be substituted.
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };
        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // Sign with the issuer key but stamp the responderID byName as the
        // *signer's* DN (which is not the responder/issuer).
        let wrong_name = cert.tbs_certificate.subject.to_der().unwrap();
        let response_der = build_test_ocsp_response_with_responder_id(
            &issuer,
            &key_pem,
            &cert,
            &CertStatus::Good,
            &der_utils::encode_tlv(0xA1, &wrong_name),
        );

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err = check_revocation(&response_der, &cert, &issuer, None, Some(validation_time))
            .expect_err("a response with a mismatched responderID must be rejected");
        assert!(
            matches!(err, LtvError::Ocsp(ref m) if m.contains("responderID")),
            "expected responderID mismatch rejection, got: {err}"
        );
    }

    #[test]
    fn test_issuer_responder_needs_no_revocation_check() {
        // When the responder IS the issuing CA (not delegated), no responder
        // revocation check is required and the detailed outcome carries no
        // delegated responder.
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };
        let issuer = intermediate_ca_cert();
        let cert = signer_cert();
        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let outcome = check_revocation_detailed(
            &response_der,
            &cert,
            &issuer,
            None,
            Some(validation_time),
            &crate::crypto::verify::SignaturePolicy::default(),
            &OcspFreshness::default(),
        )
        .unwrap();
        assert!(outcome.status.is_valid());
        assert!(
            outcome.delegated_responder.is_none(),
            "a CA-signed (non-delegated) response needs no responder revocation check"
        );
    }
}
