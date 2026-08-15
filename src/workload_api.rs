//! SPIRE Workload API client mode for `bundle.kind: workload_api`.
//!
//! Replaces the file-poll
//! bundle-source with a live gRPC stream against the SPIRE agent's
//! Unix socket. Two streams (X.509 + JWT bundles) drive the
//! workload identity plugin's trust store; whenever either side
//! emits an update, we recompose a [`ParsedBundle`] and atomically
//! swap it into the shared `BundleReload` so resolve() picks up
//! the new view on next request.
//!
//! The [`spiffe`] crate's `X509Source` + `JwtSource` handle the
//! reconnect/backoff logic for us — they expose a `tokio::sync::watch`
//! handle (`updated()`) that ticks every time the cached bundle
//! changes. The streamer task simply waits on the watches and
//! pushes the merged view into the bundle slot.

use std::collections::BTreeMap;
use std::sync::Arc;

use jsonwebtoken::DecodingKey;
use mcpg_bundle_reload::BundleReload;
use sha2::{Digest, Sha256};
use spiffe::bundle::BundleSource;
use spiffe::{
    JwtBundle, JwtSource, JwtSourceBuilder, TrustDomain, X509Bundle, X509Source, X509SourceBuilder,
};
use tokio::task::JoinHandle;

use crate::ParsedBundle;
use crate::x509::X509TrustStore;

/// Held for the lifetime of the plugin so the gRPC streams stay
/// connected. `Drop` shuts down the Workload API sources cleanly,
/// aborts the streamer task, and lets the SPIRE agent close its
/// stream from its end.
pub struct WorkloadApiKeepalive {
    x509: Arc<X509Source>,
    jwt: Arc<JwtSource>,
    streamer: JoinHandle<()>,
}

impl Drop for WorkloadApiKeepalive {
    fn drop(&mut self) {
        // Best-effort shutdown: aborting the streamer first stops
        // it from observing the soon-to-be-closed sources, then
        // we drop the source Arcs (the spiffe crate's supervisor
        // tasks notice their handles disappearing and tear down
        // their connections).
        self.streamer.abort();
        let _ = &self.x509;
        let _ = &self.jwt;
    }
}

/// Boot the SPIRE Workload API client + start the streaming task.
///
/// Returns a [`BundleReload`] populated from the agent's initial
/// snapshot plus a [`WorkloadApiKeepalive`] holding the streamer
/// task and the source handles.
///
/// Errors at the gRPC connect / initial-fetch layer surface as
/// fatal — the plugin's `from_config_json` panics, which is the
/// established "misconfigured identity plugin = security hole;
/// refuse to load" stance.
pub async fn start(
    socket_path: &str,
    trust_domain: &str,
) -> Result<(BundleReload<ParsedBundle>, WorkloadApiKeepalive), Error> {
    let trust_domain_obj =
        TrustDomain::new(trust_domain).map_err(|e| Error::TrustDomain(e.to_string()))?;

    let x509_source = X509SourceBuilder::new()
        .endpoint(socket_path)
        .build()
        .await
        .map_err(|e| Error::X509Source(format!("{e}")))?;
    let jwt_source = JwtSourceBuilder::new()
        .endpoint(socket_path)
        .build()
        .await
        .map_err(|e| Error::JwtSource(format!("{e}")))?;

    let x509_arc = Arc::new(x509_source);
    let jwt_arc = Arc::new(jwt_source);

    let initial = compose_parsed_bundle(&x509_arc, &jwt_arc, &trust_domain_obj)?;
    let fingerprint = fingerprint_bundle(&initial);
    let reload = mcpg_bundle_reload::static_only(initial, fingerprint);

    // Spawn the streamer. It subscribes to both `updated()` watch
    // handles and recomposes the bundle on every tick from either.
    let reload_for_task = reload.clone();
    let x509_for_task = Arc::clone(&x509_arc);
    let jwt_for_task = Arc::clone(&jwt_arc);
    let trust_domain_for_task = trust_domain_obj.clone();
    let streamer = tokio::spawn(async move {
        streamer_loop(
            reload_for_task,
            x509_for_task,
            jwt_for_task,
            trust_domain_for_task,
        )
        .await
    });

    Ok((
        reload,
        WorkloadApiKeepalive {
            x509: x509_arc,
            jwt: jwt_arc,
            streamer,
        },
    ))
}

async fn streamer_loop(
    reload: BundleReload<ParsedBundle>,
    x509: Arc<X509Source>,
    jwt: Arc<JwtSource>,
    trust_domain: TrustDomain,
) {
    let mut x509_updates = x509.updated();
    let mut jwt_updates = jwt.updated();

    loop {
        // `changed()` resolves on the next bundle update OR when
        // the supervisor cancels (source shutdown). The two
        // sources have distinct error types, so we erase them
        // into `()` and keep just the trigger label — we only
        // care which side ticked + whether the shutdown signal
        // fired, not the precise reason.
        let trigger: Result<&'static str, ()> = tokio::select! {
            r = x509_updates.changed() => r.map(|_| "x509").map_err(|_| ()),
            r = jwt_updates.changed() => r.map(|_| "jwt").map_err(|_| ()),
        };
        match trigger {
            Ok(which) => match compose_parsed_bundle(&x509, &jwt, &trust_domain) {
                Ok(parsed) => {
                    let fingerprint = fingerprint_bundle(&parsed);
                    let jwt_count = parsed.jwt_keys.len();
                    let x509_count = parsed.x509.root_count();
                    reload.replace(parsed, fingerprint);
                    tracing::info!(
                        plugin_id = crate::PLUGIN_ID,
                        trigger = %which,
                        jwt_keys = jwt_count,
                        x509_roots = x509_count,
                        "workload identity: SPIRE bundle rotated; trust store swapped"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        plugin_id = crate::PLUGIN_ID,
                        trigger = %which,
                        error = %err,
                        "workload identity: SPIRE bundle update could not be \
                         composed; keeping previous trust store live"
                    );
                }
            },
            Err(_) => {
                tracing::info!(
                    plugin_id = crate::PLUGIN_ID,
                    "workload identity: SPIRE Workload API stream closed; \
                     streamer task exiting"
                );
                return;
            }
        }
    }
}

fn compose_parsed_bundle(
    x509: &X509Source,
    jwt: &JwtSource,
    trust_domain: &TrustDomain,
) -> Result<ParsedBundle, Error> {
    let x509_roots = match x509
        .bundle_for_trust_domain(trust_domain)
        .map_err(|e| Error::X509Source(format!("bundle lookup: {e}")))?
    {
        Some(b) => x509_bundle_to_der_roots(&b),
        None => Vec::new(),
    };
    let jwt_keys = match jwt
        .bundle_for_trust_domain(trust_domain)
        .map_err(|e| Error::JwtSource(format!("bundle lookup: {e}")))?
    {
        Some(b) => jwt_bundle_to_decoding_keys(&b)?,
        None => BTreeMap::new(),
    };
    if x509_roots.is_empty() && jwt_keys.is_empty() {
        return Err(Error::EmptyBundle);
    }
    Ok(ParsedBundle {
        jwt_keys,
        x509: X509TrustStore::from_der_roots(x509_roots),
    })
}

fn x509_bundle_to_der_roots(bundle: &X509Bundle) -> Vec<Vec<u8>> {
    bundle
        .authorities()
        .iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect()
}

fn jwt_bundle_to_decoding_keys(bundle: &JwtBundle) -> Result<BTreeMap<String, DecodingKey>, Error> {
    let mut out = BTreeMap::new();
    for authority in bundle.jwt_authorities() {
        let kid = authority.key_id().to_owned();
        let jwk_json = authority.jwk_json();
        let jwk: serde_json::Value =
            serde_json::from_slice(jwk_json).map_err(|e| Error::JwkParse {
                kid: kid.clone(),
                error: e.to_string(),
            })?;
        let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        let decoded = match kty {
            "RSA" => {
                let n = jwk
                    .get("n")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::JwkParse {
                        kid: kid.clone(),
                        error: "RSA jwk missing `n`".into(),
                    })?;
                let e = jwk
                    .get("e")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::JwkParse {
                        kid: kid.clone(),
                        error: "RSA jwk missing `e`".into(),
                    })?;
                DecodingKey::from_rsa_components(n, e).map_err(|err| Error::JwkParse {
                    kid: kid.clone(),
                    error: format!("invalid RSA components: {err}"),
                })?
            }
            "EC" => {
                let x = jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::JwkParse {
                        kid: kid.clone(),
                        error: "EC jwk missing `x`".into(),
                    })?;
                let y = jwk
                    .get("y")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::JwkParse {
                        kid: kid.clone(),
                        error: "EC jwk missing `y`".into(),
                    })?;
                DecodingKey::from_ec_components(x, y).map_err(|err| Error::JwkParse {
                    kid: kid.clone(),
                    error: format!("invalid EC components: {err}"),
                })?
            }
            other => {
                return Err(Error::JwkParse {
                    kid,
                    error: format!("unsupported JWK kty `{other}` (only RSA + EC supported)"),
                });
            }
        };
        out.insert(kid, decoded);
    }
    Ok(out)
}

fn fingerprint_bundle(bundle: &ParsedBundle) -> String {
    let mut hasher = Sha256::new();
    // Hash the X.509 trust roots' raw DER (sorted for stability).
    let mut x509_ders: Vec<&[u8]> = (0..bundle.x509.root_count())
        .filter_map(|i| bundle.x509.root_der(i))
        .collect();
    x509_ders.sort();
    for der in &x509_ders {
        hasher.update(b"x509:");
        hasher.update(der);
        hasher.update(b"\x00");
    }
    // JWT keys: hash the kid set deterministically. Decoding keys
    // don't expose their bytes, so kid + kty (when we know it from
    // the source bytes) is the best fingerprint we can compute.
    // The kid space is unique per signing keypair in SPIRE so
    // kid-only is sufficient to detect rotation.
    let mut kids: Vec<&str> = bundle.jwt_keys.keys().map(String::as_str).collect();
    kids.sort();
    for kid in kids {
        hasher.update(b"jwt:");
        hasher.update(kid.as_bytes());
        hasher.update(b"\x00");
    }
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("trust domain not valid: {0}")]
    TrustDomain(String),
    #[error("SPIRE Workload API X.509 source: {0}")]
    X509Source(String),
    #[error("SPIRE Workload API JWT source: {0}")]
    JwtSource(String),
    #[error("SPIRE bundle for trust domain has no X.509 roots and no JWT keys")]
    EmptyBundle,
    #[error("JWK parse failed for kid `{kid}`: {error}")]
    JwkParse { kid: String, error: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParsedBundle;
    use crate::x509::X509TrustStore;

    fn empty_bundle() -> ParsedBundle {
        ParsedBundle {
            jwt_keys: BTreeMap::new(),
            x509: X509TrustStore::from_der_roots(vec![]),
        }
    }

    #[test]
    fn fingerprint_stable_for_identical_bundles() {
        let a = empty_bundle();
        let b = empty_bundle();
        assert_eq!(fingerprint_bundle(&a), fingerprint_bundle(&b));
    }

    #[test]
    fn fingerprint_changes_on_kid_set_difference() {
        let mut a = empty_bundle();
        let mut b = empty_bundle();
        // Insert keys with different kids; we don't actually use
        // them for verification in this test — we just want the
        // BTreeMap to differ.
        let n = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        let e = "AQAB";
        a.jwt_keys.insert(
            "kid-A".into(),
            DecodingKey::from_rsa_components(n, e).unwrap(),
        );
        b.jwt_keys.insert(
            "kid-B".into(),
            DecodingKey::from_rsa_components(n, e).unwrap(),
        );
        assert_ne!(fingerprint_bundle(&a), fingerprint_bundle(&b));
    }

    #[test]
    fn fingerprint_changes_on_x509_root_difference() {
        let a = empty_bundle();
        let b = ParsedBundle {
            jwt_keys: BTreeMap::new(),
            x509: X509TrustStore::from_der_roots(vec![vec![0x30, 0x82, 0x01]]),
        };
        assert_ne!(fingerprint_bundle(&a), fingerprint_bundle(&b));
    }
}
