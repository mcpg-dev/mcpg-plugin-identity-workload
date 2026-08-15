//! X.509-SVID validation primitives.
//!
//! The plugin holds an immutable [`X509TrustStore`] (built once at
//! bundle load, replaced atomically on bundle reload) and uses it
//! to validate every X.509-SVID chain the gateway hands us via
//! [`mcpg_plugin_protocol::types::TlsInfo::client_cert_chain_der`].
//!
//! Two layers:
//!
//! - `rustls-webpki` does the chain-of-trust verification (signature
//!   chain, validity windows, basic constraints, EKU). It's the same
//!   verification rustls itself runs during the TLS handshake — we
//!   re-run it because the gateway's handshake-time verifier is
//!   configured against an *operator* CA bundle which is
//!   typically a superset of the SPIFFE trust roots. This second
//!   pass narrows acceptance to the SPIFFE bundle.
//! - `x509-parser` does the SAN URI extraction. `rustls-webpki`
//!   intentionally doesn't expose extension parsing, and SPIFFE
//!   IDs live in SubjectAltName URIs.

use std::sync::Arc;

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::EndEntityCert;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

const SPIFFE_URI_PREFIX: &str = "spiffe://";

#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    #[error("x509-svid: cert chain is empty")]
    EmptyChain,
    #[error("x509-svid: chain validation failed: {0}")]
    ChainInvalid(String),
    #[error("x509-svid: leaf cert parse failed: {0}")]
    LeafParseFailed(String),
    #[error("x509-svid: leaf cert has no spiffe:// URI in SubjectAltName")]
    NoSpiffeUri,
    #[error("x509-svid: leaf cert SAN URIs not valid UTF-8")]
    InvalidSanUtf8,
}

/// Owned X.509 trust store. Cheap to clone (an `Arc`) — held by
/// the live bundle struct and atomically swapped on reload.
#[derive(Clone)]
pub struct X509TrustStore {
    /// DER-encoded trust roots, owned. Cloned per-request when
    /// building the verifier's anchor list — `webpki::TrustAnchor`
    /// borrows from these bytes, so the owning store must outlive
    /// the borrow.
    roots: Arc<Vec<CertificateDer<'static>>>,
}

impl X509TrustStore {
    /// Build a trust store from a list of DER-encoded CA certs. The
    /// caller has already parsed the SPIFFE bundle file and pulled
    /// out the X.509 authority cert bytes.
    ///
    /// `roots` may be empty — in that case all chain validations
    /// will fail with `ChainInvalid`. Construction itself does not
    /// fail; we surface the empty case at validation time so the
    /// trust-store bring-up stays infallible (cleaner reload path).
    pub fn from_der_roots(roots: Vec<Vec<u8>>) -> Self {
        let roots: Vec<CertificateDer<'static>> = roots
            .into_iter()
            .map(|der| CertificateDer::from(der).into_owned())
            .collect();
        Self {
            roots: Arc::new(roots),
        }
    }

    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// True when the trust store has no roots — the chain
    /// verification will reject every chain. Surfaced so callers
    /// can short-circuit federation dispatch (a federated bundle
    /// loaded with zero X.509 roots can't accept any X.509-SVID
    /// regardless of what the leaf's SAN URI claims).
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// DER bytes of the i-th trust root, or `None` when out of
    /// range. Used by the SPIRE Workload API streamer to
    /// fingerprint the loaded bundle deterministically.
    pub fn root_der(&self, idx: usize) -> Option<&[u8]> {
        self.roots.get(idx).map(|c| c.as_ref())
    }

    /// Validate a leaf-first DER chain against the configured
    /// trust roots, then extract the leaf's SPIFFE URI from
    /// SubjectAltName. Returns the SPIFFE ID + leaf SHA-256
    /// fingerprint on success.
    ///
    /// `now` lets unit tests pin the wall-clock — production
    /// callers pass `UnixTime::now()`.
    pub fn validate_chain(
        &self,
        chain: &[Vec<u8>],
        now: UnixTime,
    ) -> Result<X509SvidIdentity, X509Error> {
        let Some((leaf_bytes, intermediates_bytes)) = chain.split_first() else {
            return Err(X509Error::EmptyChain);
        };
        if self.roots.is_empty() {
            return Err(X509Error::ChainInvalid(
                "trust store has no x509 roots".into(),
            ));
        }

        let leaf_der = CertificateDer::from_slice(leaf_bytes);
        let intermediates: Vec<CertificateDer<'_>> = intermediates_bytes
            .iter()
            .map(|b| CertificateDer::from_slice(b.as_slice()))
            .collect();

        let leaf = EndEntityCert::try_from(&leaf_der)
            .map_err(|e| X509Error::ChainInvalid(format!("leaf parse: {e}")))?;

        // Anchor list — `webpki::anchor_from_trusted_cert` borrows
        // from each `CertificateDer`, so the anchors live as long
        // as the `roots` Arc.
        let anchors: Vec<TrustAnchor<'_>> = self
            .roots
            .iter()
            .map(webpki::anchor_from_trusted_cert)
            .collect::<Result<_, _>>()
            .map_err(|e| X509Error::ChainInvalid(format!("trust anchor parse: {e}")))?;

        // SPIFFE SVIDs are TLS client certs. RSA-PKCS1, RSA-PSS,
        // ECDSA-P256/P384/P521, Ed25519 cover every algorithm
        // SPIRE actually emits today; rejecting older SHA-1 /
        // weak-curve combos by omission is intentional.
        let supported_algs = &[
            webpki::aws_lc_rs::ECDSA_P256_SHA256,
            webpki::aws_lc_rs::ECDSA_P256_SHA384,
            webpki::aws_lc_rs::ECDSA_P384_SHA256,
            webpki::aws_lc_rs::ECDSA_P384_SHA384,
            webpki::aws_lc_rs::ED25519,
            webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
            webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
            webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
            webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ];

        leaf.verify_for_usage(
            supported_algs,
            &anchors,
            &intermediates,
            now,
            webpki::KeyUsage::client_auth(),
            None, // CRLs — SPIFFE doesn't use CRLs (revocation via short SVID lifetimes)
            None, // verify_path callback
        )
        .map_err(|e| X509Error::ChainInvalid(format!("{e}")))?;

        // Chain is valid. Extract SPIFFE URI from leaf's SAN.
        let (spiffe_id, multiple) = extract_spiffe_uri(leaf_bytes)?;
        if multiple {
            tracing::warn!(
                spiffe_id = %spiffe_id,
                "x509-svid: leaf cert has multiple spiffe:// URIs in SAN \
                 (SPIFFE spec allows exactly one); using first"
            );
        }

        let fingerprint = sha256_hex(leaf_bytes);
        Ok(X509SvidIdentity {
            spiffe_id,
            leaf_fingerprint_sha256: fingerprint,
        })
    }
}

#[derive(Debug)]
pub struct X509SvidIdentity {
    pub spiffe_id: String,
    pub leaf_fingerprint_sha256: String,
}

/// Peek the leaf cert's first SPIFFE URI WITHOUT validating the
/// chain. Used by federation dispatch to pick the right trust
/// store before chain validation runs.
///
/// Safe to use as a pre-validation routing hint: the URI is
/// unsigned at this point, but the subsequent `validate_chain`
/// call re-extracts it after the chain check passes. An attacker
/// who flipped the URI to point at a different federated trust
/// domain would need a chain that validates under THAT domain's
/// roots — i.e. the dispatch lands them on a trust store they
/// don't have a signing key for, and the chain fails.
pub fn peek_leaf_spiffe_uri(leaf_der: &[u8]) -> Result<String, X509Error> {
    let (uri, _multiple) = extract_spiffe_uri(leaf_der)?;
    Ok(uri)
}

/// Pull the first `spiffe://` URI out of the leaf's
/// SubjectAltName extension. Returns `(uri, multiple_seen)` where
/// `multiple_seen` lets the caller log a non-conformance warning.
fn extract_spiffe_uri(leaf_der: &[u8]) -> Result<(String, bool), X509Error> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf_der)
        .map_err(|e| X509Error::LeafParseFailed(format!("{e}")))?;
    let mut spiffe_uris: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::URI(uri) = gn
                    && uri.starts_with(SPIFFE_URI_PREFIX)
                {
                    spiffe_uris.push((*uri).to_owned());
                }
            }
        }
    }
    let mut iter = spiffe_uris.into_iter();
    let Some(first) = iter.next() else {
        return Err(X509Error::NoSpiffeUri);
    };
    let multiple = iter.next().is_some();
    Ok((first, multiple))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Test helpers shared between this module's tests and the
/// crate-root `lib.rs` end-to-end resolve() tests. Lives behind
/// `#[cfg(test)]` so the helpers don't leak into release builds.
#[cfg(test)]
pub(crate) mod tests_module {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    };
    use std::time::Duration;

    /// Build a self-signed CA. Returns the CA's DER + an `Issuer`
    /// that owns the params + key for signing leaves.
    pub(crate) fn build_ca() -> (Vec<u8>, Issuer<'static, KeyPair>) {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "Test SPIFFE CA");
            dn
        };
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().to_vec();
        (der, Issuer::new(params, key_pair))
    }

    /// Sign a leaf with the given SPIFFE URI under the given CA.
    pub(crate) fn sign_leaf(
        issuer: &Issuer<'static, KeyPair>,
        spiffe_uri: &str,
        validity: Duration,
    ) -> Vec<u8> {
        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "test-workload");
            dn
        };
        leaf_params.subject_alt_names = vec![SanType::URI(spiffe_uri.try_into().unwrap())];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        leaf_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::seconds(60);
        leaf_params.not_after =
            leaf_params.not_before + time::Duration::seconds(validity.as_secs() as i64);
        let leaf_key = KeyPair::generate().unwrap();
        leaf_params
            .signed_by(&leaf_key, issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    /// Convenience for tests that want a single CA + single leaf
    /// in one shot.
    pub(crate) fn issue_test_pair(spiffe_uri: &str) -> (Vec<u8>, Vec<u8>) {
        let (ca_der, issuer) = build_ca();
        let leaf_der = sign_leaf(&issuer, spiffe_uri, Duration::from_secs(3600));
        (ca_der, leaf_der)
    }

    pub(crate) fn issue_test_pair_with_validity(
        spiffe_uri: &str,
        validity: Duration,
    ) -> (Vec<u8>, Vec<u8>) {
        let (ca_der, issuer) = build_ca();
        let leaf_der = sign_leaf(&issuer, spiffe_uri, validity);
        (ca_der, leaf_der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType,
    };
    use std::time::{Duration, SystemTime};
    use tests_module::{build_ca, issue_test_pair, issue_test_pair_with_validity};

    fn time_now() -> UnixTime {
        UnixTime::since_unix_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
    }

    #[test]
    fn validates_well_formed_chain_and_extracts_spiffe_id() {
        let (ca_der, leaf_der) = issue_test_pair("spiffe://example.org/ns/x/sa/y");
        let store = X509TrustStore::from_der_roots(vec![ca_der]);
        let id = store.validate_chain(&[leaf_der], time_now()).unwrap();
        assert_eq!(id.spiffe_id, "spiffe://example.org/ns/x/sa/y");
        assert_eq!(id.leaf_fingerprint_sha256.len(), 64); // hex-encoded sha256
    }

    #[test]
    fn rejects_chain_signed_by_unknown_ca() {
        // Leaf from one CA; trust store holds a different CA.
        let (_real_ca, leaf) = issue_test_pair("spiffe://example.org/x");
        let (other_ca, _) = issue_test_pair("spiffe://example.org/y");
        let store = X509TrustStore::from_der_roots(vec![other_ca]);
        let err = store.validate_chain(&[leaf], time_now()).unwrap_err();
        assert!(matches!(err, X509Error::ChainInvalid(_)), "got {err:?}");
    }

    #[test]
    fn rejects_expired_leaf() {
        // Issue with a 1-second validity then sleep past it.
        let (ca, leaf) =
            issue_test_pair_with_validity("spiffe://example.org/x", Duration::from_secs(1));
        let store = X509TrustStore::from_der_roots(vec![ca]);
        // Use a wall-clock 5 minutes in the future so the leaf is
        // unambiguously expired (avoids racing the test).
        let future = UnixTime::since_unix_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                + Duration::from_secs(300),
        );
        let err = store.validate_chain(&[leaf], future).unwrap_err();
        assert!(matches!(err, X509Error::ChainInvalid(_)), "got {err:?}");
    }

    #[test]
    fn rejects_leaf_without_spiffe_uri() {
        // Issue a leaf with no URI SAN — give it a DNS SAN so
        // rcgen still accepts it.
        let (ca_der, issuer) = build_ca();
        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "no-spiffe");
            dn
        };
        leaf_params.subject_alt_names =
            vec![SanType::DnsName("workload.example.org".try_into().unwrap())];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let store = X509TrustStore::from_der_roots(vec![ca_der]);
        let err = store
            .validate_chain(&[leaf.der().to_vec()], time_now())
            .unwrap_err();
        assert!(matches!(err, X509Error::NoSpiffeUri));
    }

    #[test]
    fn empty_chain_rejected() {
        let store = X509TrustStore::from_der_roots(vec![vec![0xde]]);
        let err = store.validate_chain(&[], time_now()).unwrap_err();
        assert!(matches!(err, X509Error::EmptyChain));
    }

    #[test]
    fn empty_trust_store_rejects_chain() {
        let (_, leaf) = issue_test_pair("spiffe://example.org/x");
        let store = X509TrustStore::from_der_roots(vec![]);
        let err = store.validate_chain(&[leaf], time_now()).unwrap_err();
        assert!(matches!(err, X509Error::ChainInvalid(_)), "got {err:?}");
    }

    #[test]
    fn extracts_first_when_multiple_spiffe_uris() {
        // SPIFFE spec says exactly one; some non-conformant
        // issuers emit multiple. Plugin takes the first + warns.
        let (ca_der, issuer) = build_ca();
        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "multi-spiffe");
            dn
        };
        leaf_params.subject_alt_names = vec![
            SanType::URI("spiffe://example.org/first".try_into().unwrap()),
            SanType::URI("spiffe://example.org/second".try_into().unwrap()),
        ];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let store = X509TrustStore::from_der_roots(vec![ca_der]);
        let id = store
            .validate_chain(&[leaf_cert.der().to_vec()], time_now())
            .unwrap();
        assert_eq!(id.spiffe_id, "spiffe://example.org/first");
    }

    #[test]
    fn extracts_spiffe_when_other_san_uris_present() {
        // Real workloads sometimes carry both a SPIFFE URI and a
        // platform URI (e.g. k8s service-account URI). Make sure
        // we pick the SPIFFE one regardless of order.
        let (ca_der, issuer) = build_ca();
        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "mixed");
            dn
        };
        // Non-SPIFFE URI listed *before* the SPIFFE one.
        leaf_params.subject_alt_names = vec![
            SanType::URI("https://other.example.com/extra".try_into().unwrap()),
            SanType::URI("spiffe://example.org/real".try_into().unwrap()),
        ];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let store = X509TrustStore::from_der_roots(vec![ca_der]);
        let id = store
            .validate_chain(&[leaf_cert.der().to_vec()], time_now())
            .unwrap();
        assert_eq!(id.spiffe_id, "spiffe://example.org/real");
    }
}
