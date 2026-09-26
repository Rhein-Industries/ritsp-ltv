//! Shared HTTP-fetch SSRF hardening for attacker-influenced URLs.
//!
//! Certificate-validation material — CRL distribution points (RFC 5280
//! §4.2.1.13) and AIA `caIssuers`/OCSP URLs (RFC 5280 §4.2.2.1) — is carried
//! *inside the certificate under validation*, so the fetch target is
//! attacker-controlled. Without a guard, presenting a crafted certificate turns
//! the validator into a Server-Side Request Forgery gadget: `http://127.0.0.1/`,
//! `http://169.254.169.254/` (cloud metadata), or any RFC 1918 host. A scheme
//! allowlist alone does not close this — `http://169.254.169.254/` passes a
//! scheme check yet still reaches an internal endpoint — so the guard also
//! filters the *resolved destination address*.
//!
//! This module is the single source of truth for those controls, originally
//! introduced for the CRL fetch path (ADR-0010) and shared with the AIA
//! chain-builder so both paths apply identical filtering rather than duplicating
//! the logic.
//!
//! Controls provided:
//! - [`validate_fetch_url`] — `http`/`https` scheme allowlist **and**
//!   resolved-IP filtering (loopback, private, link-local/metadata, unique-local,
//!   multicast, CGNAT, ...), run before any network egress.
//! - [`hardened_http_client`] — a `reqwest::Client` whose redirect policy is
//!   bounded ([`MAX_REDIRECTS`]) and refuses to follow redirects to literal
//!   non-public addresses. Its connection resolver checks every DNS answer,
//!   including redirect hostnames, before returning the addresses to reqwest.
//! - [`is_disallowed_ip`] — the address classifier shared by both.
//!
//! Hardened clients disable automatic environment proxies because a proxy can
//! resolve the destination itself and bypass the connection resolver. They have
//! default connection and whole-request timeouts; per-request timeouts can still
//! be configured by callers. An initial literal-IP URL bypasses DNS, so callers
//! handling attacker-influenced initial URLs must retain [`validate_fetch_url`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;

/// Failure while constructing an attested HTTP/TLS client.
#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    #[error(transparent)]
    Crypto(#[from] riptering::Error),
    #[error("failed to build hardened HTTP client: {0}")]
    Build(#[from] reqwest::Error),
}

/// A reqwest client paired with compile-time provider attestation.
///
/// The inner client is intentionally not exposed publicly: callers can only
/// inject another attested wrapper, preventing an accidental TLS-provider
/// substitution at API boundaries.
#[derive(Clone)]
pub struct AttestedHttpClient {
    inner: Client,
    backend: riptering::BackendInfo,
    verified: bool,
}

impl std::fmt::Debug for AttestedHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedHttpClient")
            .field("backend", &self.backend)
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

impl AttestedHttpClient {
    /// Provider state attested when the client was constructed.
    #[must_use]
    pub fn backend_info(&self) -> &riptering::BackendInfo {
        &self.backend
    }

    /// Whether this client was constructed from riptering's selected TLS provider.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.verified
    }

    pub(crate) fn client(&self) -> &Client {
        &self.inner
    }
}

/// Maximum HTTP redirects followed by a [`hardened_http_client`].
pub const MAX_REDIRECTS: usize = 5;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve and check the exact address set handed to the HTTP connector.
/// This covers new connections to redirect hostnames as well as initial hosts.
#[derive(Debug)]
struct PublicDnsResolver;

impl reqwest::dns::Resolve for PublicDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = resolve_public_host(&host, 0).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Classify an IPv4 address as non-public so the SSRF guard can refuse it.
///
/// This is the stable-Rust equivalent of "not [`Ipv4Addr::is_global`]" (which
/// is still nightly-only): rather than enumerate an allow-list, we deny every
/// block that is not globally routable. A hand-maintained subset would silently
/// miss reserved ranges as they are defined, so the deny-list mirrors the std
/// `is_global` definition and adds multicast (never a valid fetch target).
fn is_disallowed_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_multicast()
        // "This network" 0.0.0.0/8 (RFC 1122)
        || o[0] == 0
        // CGNAT shared address space 100.64.0.0/10 (RFC 6598)
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
        // IETF protocol assignments 192.0.0.0/24 (RFC 6890)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // Benchmarking 198.18.0.0/15 (RFC 2544)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        // Reserved for future use 240.0.0.0/4 (RFC 1112), incl. broadcast
        || o[0] >= 240
}

/// Classify an IP address as non-public, so an SSRF guard can refuse fetches
/// whose host resolves to an internal or metadata address. IPv4-mapped IPv6
/// addresses are unwrapped and re-checked.
pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_disallowed_ipv4(v4);
            }
            let segments = v6.segments();
            let first = segments[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7
                || (first & 0xfe00) == 0xfc00
                // link-local unicast fe80::/10
                || (first & 0xffc0) == 0xfe80
                // deprecated site-local unicast fec0::/10
                || (first & 0xffc0) == 0xfec0
                // documentation 2001:db8::/32 and 3fff::/20
                || (first == 0x2001 && segments[1] == 0x0db8)
                || (first == 0x3fff && (segments[1] & 0xf000) == 0)
                // discard-only 100::/64
                || (first == 0x0100 && segments[1..4] == [0, 0, 0])
        }
    }
}

/// Strip the brackets `reqwest`/`url` place around IPv6 literal hosts
/// (`[::1]`) so the inner address can be parsed.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Build an HTTP client with bounded redirects, connect/request timeouts and a
/// resolver that refuses non-public destinations, including redirect hostnames.
/// Initial literal addresses must still be checked by [`validate_fetch_url`].
///
/// Fails closed: a build or provider-attestation failure is returned rather
/// than degrading to reqwest's default TLS or redirect behavior.
pub fn hardened_http_client() -> Result<AttestedHttpClient, HttpClientError> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = riptering::build_tls_client_config(roots)?;
    attested_http_client(tls)
}

/// Build a hardened HTTP client from a riptering-attested TLS configuration.
///
/// Automatic environment proxies are disabled to preserve destination-address
/// checks. Deployments requiring a proxy must supply their own network policy
/// through the explicit non-FIPS `unverified_http_client` escape hatch.
pub fn attested_http_client(
    tls: riptering::AttestedTlsConfig,
) -> Result<AttestedHttpClient, HttpClientError> {
    build_attested_http_client(tls, |builder| builder)
}

fn build_attested_http_client(
    tls: riptering::AttestedTlsConfig,
    configure: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Result<AttestedHttpClient, HttpClientError> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        if let Some(host) = attempt.url().host_str() {
            if let Ok(ip) = unbracket(host).parse::<IpAddr>() {
                if is_disallowed_ip(ip) {
                    // Stop following; the caller sees the 3xx and rejects it.
                    return attempt.stop();
                }
            }
        }
        attempt.follow()
    });
    let config = tls.config();
    let builder = Client::builder()
        .redirect(policy)
        .dns_resolver(Arc::new(PublicDnsResolver))
        .no_proxy()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .use_preconfigured_tls((*config).clone());
    let inner = configure(builder).build().map_err(HttpClientError::Build)?;
    Ok(AttestedHttpClient {
        inner,
        backend: riptering::backend_info()?,
        verified: true,
    })
}

/// Explicit escape hatch for an externally-built, unattested reqwest client.
///
/// This API does not exist in FIPS builds, where every HTTPS operation must be
/// tied to a provider configuration that has passed FIPS attestation.
#[cfg(not(feature = "fips"))]
pub fn unverified_http_client(client: Client) -> Result<AttestedHttpClient, HttpClientError> {
    Ok(AttestedHttpClient {
        inner: client,
        backend: riptering::backend_info()?,
        verified: false,
    })
}

/// An error from [`validate_fetch_url`], with a category so callers can wrap it
/// in their own domain error type with an appropriate message prefix.
#[derive(Debug)]
pub enum UrlGuardError {
    /// The URL did not parse.
    Parse(String),
    /// The scheme was not `http`/`https`.
    Scheme(String),
    /// The URL had no host component.
    NoHost,
    /// DNS resolution failed (task error or lookup error).
    Resolution(String),
    /// The host resolved to no addresses.
    NoAddresses(String),
    /// The host is (or resolves to) a non-public address — SSRF guard.
    NonPublic(String),
}

impl std::fmt::Display for UrlGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlGuardError::Parse(m) => write!(f, "invalid URL: {m}"),
            UrlGuardError::Scheme(s) => {
                write!(
                    f,
                    "URL scheme not allowed: {s} (only http/https are supported)"
                )
            }
            UrlGuardError::NoHost => write!(f, "URL has no host"),
            UrlGuardError::Resolution(m) => write!(f, "failed to resolve host: {m}"),
            UrlGuardError::NoAddresses(h) => write!(f, "host {h} resolved to no addresses"),
            UrlGuardError::NonPublic(m) => {
                write!(f, "host {m} is a non-public address (SSRF guard)")
            }
        }
    }
}

impl std::error::Error for UrlGuardError {}

async fn resolve_public_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, UrlGuardError> {
    let host_for_lookup = host.to_owned();
    let addrs = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host_for_lookup.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| UrlGuardError::Resolution(format!("DNS resolution task failed: {e}")))?
    .map_err(|e| UrlGuardError::Resolution(format!("{host}: {e}")))?;
    validate_resolved_addresses(host, addrs)
}

fn validate_resolved_addresses(
    host: &str,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, UrlGuardError> {
    if addrs.is_empty() {
        return Err(UrlGuardError::NoAddresses(host.to_owned()));
    }
    for addr in &addrs {
        if is_disallowed_ip(addr.ip()) {
            return Err(UrlGuardError::NonPublic(format!(
                "{host} resolved to {}",
                addr.ip()
            )));
        }
    }
    Ok(addrs)
}

/// Validate that a URL is safe to fetch before any network egress.
///
/// Enforces an `http`/`https` scheme allowlist **and** resolves the host,
/// rejecting the fetch when any resolved address is loopback, private,
/// link-local, unique-local, multicast, or otherwise non-public. Scheme
/// filtering alone does not stop SSRF (see the module docs); the destination
/// address is the thing that matters.
///
/// A literal-IP host is checked directly (no DNS). A hostname is resolved off
/// the async executor (via `spawn_blocking`) and **every** resolved address is
/// checked.
pub async fn validate_fetch_url(url: &str) -> Result<(), UrlGuardError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| UrlGuardError::Parse(format!("{url}: {e}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(UrlGuardError::Scheme(other.to_string())),
    }
    let host = parsed.host_str().ok_or(UrlGuardError::NoHost)?;
    let host_bare = unbracket(host);

    // A literal IP needs no DNS — check it directly.
    if let Ok(ip) = host_bare.parse::<IpAddr>() {
        if is_disallowed_ip(ip) {
            return Err(UrlGuardError::NonPublic(host_bare.to_string()));
        }
        return Ok(());
    }

    // Hostname: resolve off the async executor and reject any non-public
    // destination among the resolved addresses.
    let port = parsed.port_or_known_default().unwrap_or(0);
    resolve_public_host(host_bare, port).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn https_fixture() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("test certificate generation");
        let private_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        (cert.der().clone(), private_key.into())
    }

    async fn spawn_https_server(
        certificate: CertificateDer<'static>,
        private_key: PrivateKeyDer<'static>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let provider = rustls::crypto::ring::default_provider();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("test TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .expect("test TLS identity");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind HTTPS fixture");
        let port = listener.local_addr().expect("fixture address").port();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("fixture connection");
            // Validation-failure tests intentionally abort during the handshake.
            if let Ok(mut stream) = acceptor.accept(stream).await {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nOK",
                    )
                    .await;
                let _ = stream.shutdown().await;
            }
        });
        (port, task)
    }

    fn attested_client_with_root(root: Option<CertificateDer<'static>>) -> AttestedHttpClient {
        attested_client_for_fixture(root, "localhost")
    }

    fn attested_client_for_fixture(
        root: Option<CertificateDer<'static>>,
        host: &str,
    ) -> AttestedHttpClient {
        #[cfg(feature = "fips")]
        riptering::initialize_backend().expect("initialize FIPS backend for HTTPS unit test");

        let mut roots = rustls::RootCertStore::empty();
        if let Some(root) = root {
            roots.add(root).expect("add test trust anchor");
        }
        let tls = riptering::build_tls_client_config(roots).expect("attested test TLS config");
        // Test fixtures need an explicit loopback override. Production clients
        // call the same builder with no overrides or resolver exceptions.
        build_attested_http_client(tls, |builder| {
            builder.resolve(host, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        })
        .expect("attested test HTTP client")
    }

    #[test]
    fn loopback_and_metadata_are_disallowed() {
        assert!(is_disallowed_ip("127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("169.254.169.254".parse().unwrap()));
        assert!(is_disallowed_ip("10.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("192.168.1.1".parse().unwrap()));
        assert!(is_disallowed_ip("172.16.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(is_disallowed_ip("::1".parse().unwrap()));
        assert!(is_disallowed_ip("fe80::1".parse().unwrap()));
        assert!(is_disallowed_ip("fc00::1".parse().unwrap()));
        // IPv4-mapped loopback
        assert!(is_disallowed_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_addresses_are_allowed() {
        assert!(!is_disallowed_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_disallowed_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_disallowed_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn reserved_ipv4_ranges_are_disallowed() {
        // Blocks that a hand-maintained allow-list previously missed but that
        // are not globally routable (mirrors Ipv4Addr::is_global).
        assert!(is_disallowed_ip("0.1.2.3".parse().unwrap())); // 0.0.0.0/8 "this network"
        assert!(is_disallowed_ip("192.0.0.1".parse().unwrap())); // 192.0.0.0/24 IETF
        assert!(is_disallowed_ip("198.18.0.1".parse().unwrap())); // 198.18.0.0/15 benchmarking
        assert!(is_disallowed_ip("198.19.255.255".parse().unwrap())); // 198.18.0.0/15 upper half
        assert!(is_disallowed_ip("240.0.0.1".parse().unwrap())); // 240.0.0.0/4 reserved
        assert!(is_disallowed_ip("255.255.255.255".parse().unwrap())); // broadcast
                                                                       // Documentation block stays blocked.
        assert!(is_disallowed_ip("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn reserved_ipv6_ranges_are_disallowed() {
        for address in [
            "2001:db8::1",              // documentation
            "2001:db8:ffff:ffff::1",    // documentation upper boundary
            "3fff::1",                  // documentation
            "3fff:fff:ffff:ffff::1",    // documentation upper boundary
            "100::1",                   // discard-only
            "100::ffff:ffff:ffff:ffff", // discard-only upper boundary
            "fec0::1",                  // deprecated site-local
            "feff:ffff:ffff:ffff::1",   // site-local upper boundary
            "::ffff:203.0.113.7",       // IPv4-mapped documentation
        ] {
            assert!(
                is_disallowed_ip(address.parse().unwrap()),
                "{address} must not be fetched"
            );
        }
    }

    #[test]
    fn connection_resolver_rejects_empty_or_mixed_non_public_answers() {
        assert!(matches!(
            validate_resolved_addresses("fixture.test", Vec::new()),
            Err(UrlGuardError::NoAddresses(_))
        ));
        let public: SocketAddr = "8.8.8.8:0".parse().unwrap();
        for blocked in ["127.0.0.1:0", "10.0.0.1:0", "[2001:db8::1]:0"] {
            let blocked = blocked.parse().unwrap();
            for answers in [vec![public, blocked], vec![blocked, public]] {
                assert!(matches!(
                    validate_resolved_addresses("fixture.test", answers),
                    Err(UrlGuardError::NonPublic(_))
                ));
            }
        }
        let answers = vec![public, "[2606:4700:4700::1111]:0".parse().unwrap()];
        assert_eq!(
            validate_resolved_addresses("fixture.test", answers.clone()).unwrap(),
            answers,
            "the checked addresses must be the addresses supplied to the connector"
        );
    }

    #[tokio::test]
    async fn connection_resolver_rejects_localhost() {
        use reqwest::dns::Resolve;

        let result = PublicDnsResolver
            .resolve("localhost".parse().unwrap())
            .await;
        let err = match result {
            Ok(_) => panic!("production resolver must reject local hostname destinations"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("non-public address"));
    }

    #[tokio::test]
    async fn redirect_to_non_public_hostname_is_rejected() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://localhost:{port}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        // Only the synthetic first-hop host is overridden. The redirect uses
        // the production resolver, which must reject localhost before connect.
        let client = attested_client_for_fixture(None, "fixture.test");
        let err = client
            .client()
            .get(format!("http://fixture.test:{port}/"))
            .send()
            .await
            .expect_err("redirect to an internal hostname must reject");
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        let mut rejected_by_guard = false;
        while let Some(error) = cause {
            if matches!(
                error.downcast_ref::<UrlGuardError>(),
                Some(UrlGuardError::NonPublic(_))
            ) {
                rejected_by_guard = true;
                break;
            }
            cause = error.source();
        }
        assert!(
            rejected_by_guard,
            "expected the connection-time address guard, got: {err:?}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let err = validate_fetch_url("file:///etc/passwd").await.unwrap_err();
        assert!(matches!(err, UrlGuardError::Scheme(_)));
    }

    #[tokio::test]
    async fn rejects_literal_loopback() {
        let err = validate_fetch_url("http://127.0.0.1/x").await.unwrap_err();
        assert!(matches!(err, UrlGuardError::NonPublic(_)));
    }

    #[tokio::test]
    async fn rejects_literal_metadata() {
        let err = validate_fetch_url("http://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(matches!(err, UrlGuardError::NonPublic(_)));
    }

    #[tokio::test]
    async fn rejects_localhost_without_duplicate_non_public_message() {
        let err = validate_fetch_url("http://localhost/x").await.unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, UrlGuardError::NonPublic(_)));
        assert_eq!(
            msg.matches("non-public address").count(),
            1,
            "non-public wording should not be duplicated: {msg}"
        );
    }

    #[tokio::test]
    async fn selected_tls_provider_connects_to_trusted_https_fixture() {
        let (certificate, private_key) = https_fixture();
        let (port, server) = spawn_https_server(certificate.clone(), private_key).await;
        let client = attested_client_with_root(Some(certificate));

        let response = client
            .client()
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .expect("trusted HTTPS request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        server.await.expect("HTTPS fixture task");
    }

    #[tokio::test]
    async fn selected_tls_provider_rejects_wrong_hostname() {
        let (certificate, private_key) = https_fixture();
        let (port, server) = spawn_https_server(certificate.clone(), private_key).await;
        let client = attested_client_with_root(Some(certificate));

        let result = client
            .client()
            .get(format!("https://127.0.0.1:{port}/"))
            .send()
            .await;
        assert!(result.is_err(), "hostname mismatch unexpectedly succeeded");
        server.await.expect("HTTPS fixture task");
    }

    #[tokio::test]
    async fn selected_tls_provider_rejects_untrusted_certificate() {
        let (certificate, private_key) = https_fixture();
        let (port, server) = spawn_https_server(certificate, private_key).await;
        let client = attested_client_with_root(None);

        let result = client
            .client()
            .get(format!("https://localhost:{port}/"))
            .send()
            .await;
        assert!(
            result.is_err(),
            "untrusted certificate unexpectedly succeeded"
        );
        server.await.expect("HTTPS fixture task");
    }
}
