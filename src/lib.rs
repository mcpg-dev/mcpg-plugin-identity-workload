//! `dev.mcpg.identity.workload` — SPIFFE workload identity plugin.
//!
//! Operator-facing summary lives in `README.md`.
//!
//! # Scope
//!
//! - **X.509-SVID** validation. Reads
//!   `metadata.tls.client_cert_chain_der` (populated when mTLS
//!   terminates at the gateway), validates the chain against the
//!   trust bundle's X.509 trust roots via `rustls-webpki`, then
//!   extracts the SPIFFE URI from the leaf cert's
//!   SubjectAltName.
//! - **JWT-SVID** validation. Reads the SVID from
//!   `Authorization: Bearer <jwt>` (or operator-named header).
//! - Trust-bundle source: operator-supplied SPIFFE Trust Domain
//!   Bundle file. Both X.509 trust roots (`use: x509-svid`) and
//!   JWT signing keys (`use: jwt-svid` / `jwt_signing_keys` /
//!   plain JWKS) parse from the same file.
//! - Trust-domain enforcement on the SPIFFE ID extracted from
//!   either format.
//! - Optional `mode: "allowlist"` of explicit SPIFFE IDs.
//! - Optional per-SPIFFE-ID metadata map.
//! - JWT-SVID `aud` claim validation. `audiences` is required:
//!   non-empty enforces "token MUST claim at least one of these
//!   audiences" via jsonwebtoken's set_audience. An empty list skips
//!   the aud check but is rejected at boot unless the operator opts
//!   in with `allow_any_audience: true`.
//! - Bundle hot-reload via the shared `mcpg-bundle-reload`
//!   helper. Atomic swap on file change covers both the JWT keys
//!   and the X.509 trust store.
//!
//! # Federation
//!
//! Operators list foreign trust domains under
//! `federated_trust_domains`, each pinned to its own bundle file.
//! Resolve-time the plugin peeks the SVID's claimed trust domain
//! (`sub` for JWT, leaf SAN URI for X.509), looks up the matching
//! bundle (local or federated), and verifies against THAT
//! bundle's keys / X.509 roots. The resolved identity carries
//! `spiffe.federation_source` + `spiffe.federation_fingerprint`
//! attributes so policy plugins + audit consumers can distinguish
//! local vs. foreign-domain SVIDs.
//!
//! Federation ships file-source bundles only; SPIRE-Workload-API
//! and HTTPS-bundle-endpoint sources per federated entry are not
//! yet supported.
//!
//! # External prerequisite
//!
//! The `x509_svid` source is only meaningful when the gateway
//! populates `RequestMetadata.tls.client_cert_chain_der`. While the
//! gateway's "direct mTLS" plumbing leaves that field empty,
//! X.509-SVID source entries drop through silently in production.
//! The plugin-side validation lands here so it's ready when the
//! gateway-side plumbing follows.

mod config;
mod workload_api;
mod x509;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mcpg_bundle_reload::{BundleReload, BundleSource, ReloadError};
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, info_span, warn};

pub use config::{
    BundleConfig, ConfigError, IdentityMetadata, JwtSvidSource, Mode, ReloadConfig,
    ResolutionConfig, SourceKind, SvidSource, WorkloadConfig,
};
pub use x509::{X509Error, X509SvidIdentity, X509TrustStore};

const PLUGIN_ID: &str = "dev.mcpg.identity.workload";

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!(
        "mcpg_identity_workload_resolutions_total",
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!("mcpg_identity_workload_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            elapsed_ms = %elapsed.as_millis(),
            "workload identity resolved"
        ),
        IdentityResolution::None => debug!(
            elapsed_ms = %elapsed.as_millis(),
            "workload identity: no SVID — fall through"
        ),
        IdentityResolution::Invalid { reason, .. } => warn!(
            reason = %reason,
            elapsed_ms = %elapsed.as_millis(),
            "workload identity: SVID validation failed"
        ),
    }
}

pub struct WorkloadIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: WorkloadConfig,
    /// Parsed trust bundle for the *local* trust domain.
    /// Hot-reloadable via the shared bundle-reload helper.
    bundle: BundleReload<ParsedBundle>,
    /// Federated foreign trust domains, indexed by trust domain
    /// string. Each carries its own bundle (file or
    /// workload_api source) reloaded independently of the local
    /// bundle. Empty when no federation is configured.
    federated: BTreeMap<String, FederatedBundle>,
    /// Bundled tokio runtime — present when either bundle reload
    /// is enabled (`File` source), the Workload API streamer is
    /// running (`WorkloadApi` source), or any federated entry
    /// uses one of those reload-driven sources.
    _runtime: Option<tokio::runtime::Runtime>,
    /// SPIRE Workload API streamer keepalives — one per
    /// `bundle.kind: workload_api` source (local + federated).
    /// Holds the X509Source + JwtSource handles plus streamer
    /// tasks; Drop shuts the gRPC streams down cleanly.
    #[allow(dead_code)]
    _workload_api: Vec<workload_api::WorkloadApiKeepalive>,
    /// Cluster client handed to the plugin at `make` time when the
    /// operator has registered a `cluster_backend`. Used today
    /// to publish a startup heartbeat on
    /// `identity.workload.started` and subscribe to the same topic
    /// so peers' startup events are visible in this node's logs
    /// (cross-node fleet observability). Future uses: cross-node
    /// trust-bundle invalidation, SPIRE-pull throttling via
    /// `acquire_lock`. Held in the `Inner` so reload paths can
    /// reach for it once that work lands.
    #[allow(dead_code)]
    cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    /// Active subscription on `identity.workload.started`. Held
    /// for the plugin's lifetime so peer startup notifications
    /// keep flowing; Drop cancels the stream.
    #[allow(dead_code)]
    cluster_subscription: Option<mcpg_plugin_sdk::Subscription<mcpg_cluster_api::PublishedMessage>>,
}

impl WorkloadIdentityPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        Self::from_config_json_with_cluster(config_json, None)
    }

    /// Factory that receives the optional cluster client from
    /// the SDK macro. Public so unit tests can construct the
    /// plugin with a synthetic client.
    pub fn from_config_json_with_cluster(
        config_json: &str,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    ) -> Self {
        let cfg = WorkloadConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "workload identity: config parse failed; refusing to register"
            );
            panic!(
                "workload identity config parse failed: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg, cluster)
    }

    fn from_validated_config(
        cfg: WorkloadConfig,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    ) -> Self {
        let (bundle, runtime, local_workload_api_keepalive) = match &cfg.bundle {
            BundleConfig::File { file_path } => {
                Self::build_file_bundle(&cfg, cluster.clone(), file_path.as_str())
            }
            BundleConfig::WorkloadApi { socket_path } => {
                Self::build_workload_api_bundle(&cfg, socket_path.as_str())
            }
        };

        // Load federated bundles. Restricted to file-source by the
        // config validator; hot-reload per federated entry is not
        // yet supported.
        let mut federated: BTreeMap<String, FederatedBundle> = BTreeMap::new();
        for fed in &cfg.federated_trust_domains {
            let fed_td = fed.trust_domain.trim().to_owned();
            let file_path = fed
                .bundle
                .file_path()
                .expect("config validator guarantees file source");
            let parsed =
                parse_bundle(&BundleSource::File(file_path.into())).unwrap_or_else(|err| {
                    panic!(
                        "workload identity: failed to load federated bundle for \
                         `{fed_td}` from {file_path}: {err}"
                    )
                });
            let fingerprint = fingerprint_file(file_path).unwrap_or_else(|err| {
                panic!(
                    "workload identity: failed to fingerprint federated bundle \
                     for `{fed_td}` at {file_path}: {err}"
                )
            });
            tracing::info!(
                plugin_id = PLUGIN_ID,
                trust_domain = %fed_td,
                file_path = %file_path,
                jwt_keys = parsed.jwt_keys.len(),
                x509_roots = parsed.x509.root_count(),
                fingerprint = %fingerprint,
                "workload identity: federated bundle loaded"
            );
            federated.insert(
                fed_td,
                FederatedBundle {
                    parsed: Arc::new(parsed),
                    fingerprint,
                },
            );
        }
        let mut workload_api_keepalive: Vec<workload_api::WorkloadApiKeepalive> = Vec::new();
        if let Some(k) = local_workload_api_keepalive {
            workload_api_keepalive.push(k);
        }

        // When a cluster_backend is registered, log the local
        // node's identity (cheap, useful for ops correlating logs
        // across nodes), publish a startup heartbeat on
        // `identity.workload.started`, and subscribe to the same
        // topic so peers' startup events are visible in this
        // node's logs. Failures are logged and ignored — cluster
        // coordination is best-effort here.
        let mut subscription = None;
        if let Some(client) = &cluster {
            let info = client.node_info();
            let local_node_id = info.node_id.clone();
            let poke_handle = bundle.poke_handle();
            let bundle_for_subscriber = bundle.clone();
            tracing::info!(
                plugin_id = PLUGIN_ID,
                cluster_node_id = %info.node_id,
                cluster_address = %info.address,
                "workload identity: cluster coordinator bound"
            );

            match client.subscribe("identity.workload.started", None, None, move |msg| {
                let from = msg.from_node.clone();
                if from == local_node_id {
                    return;
                }
                let peer_fp = serde_json::from_slice::<serde_json::Value>(&msg.payload)
                    .ok()
                    .and_then(|v| {
                        v.get("fingerprint")
                            .and_then(|f| f.as_str())
                            .map(str::to_owned)
                    });
                let local_fp = bundle_for_subscriber.fingerprint();
                let should_poke = match &peer_fp {
                    Some(peer) => peer != &local_fp,
                    None => true,
                };
                tracing::info!(
                    plugin_id = PLUGIN_ID,
                    from_node = %from,
                    topic = %msg.topic,
                    peer_fingerprint = ?peer_fp,
                    local_fingerprint = %local_fp,
                    poked = should_poke,
                    "workload identity: peer started"
                );
                if should_poke {
                    poke_handle.poke();
                }
            }) {
                Ok(s) => subscription = Some(s),
                Err(e) => tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "workload identity: subscription setup failed"
                ),
            }

            let payload = serde_json::json!({
                "plugin_id": PLUGIN_ID,
                "version": env!("CARGO_PKG_VERSION"),
                "trust_domain": cfg.trust_domain,
                "node_id": info.node_id,
                "fingerprint": bundle.fingerprint(),
            });
            let bytes = bytes::Bytes::from(serde_json::to_vec(&payload).unwrap_or_default());
            if let Err(e) = client.publish("identity.workload.started", None, bytes) {
                tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "workload identity: heartbeat publish failed"
                );
            }
        }

        tracing::info!(
            plugin_id = PLUGIN_ID,
            trust_domain = %cfg.trust_domain,
            jwt_keys_loaded = bundle.load().jwt_keys.len(),
            x509_roots_loaded = bundle.load().x509.root_count(),
            sources = cfg.sources.len(),
            mode = ?cfg.mode,
            reload_enabled = cfg.reload.enabled,
            cluster_bound = cluster.is_some(),
            bundle_kind = match &cfg.bundle {
                BundleConfig::File { .. } => "file",
                BundleConfig::WorkloadApi { .. } => "workload_api",
            },
            "workload identity: trust bundle loaded"
        );

        // Host-derived from the typed declare_plugin! capabilities; the
        // manifest no longer carries an independently-authored list.
        let required_capabilities: Vec<mcpg_plugin_protocol::capability::Capability> = Vec::new();

        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "SPIFFE Workload Identity Resolver".into(),
                    plugin_class: PluginClass::IdentityProvider,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities,
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                bundle,
                federated,
                _runtime: runtime,
                _workload_api: workload_api_keepalive,
                cluster,
                cluster_subscription: subscription,
            }),
        }
    }

    fn build_file_bundle(
        cfg: &WorkloadConfig,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
        file_path: &str,
    ) -> (
        BundleReload<ParsedBundle>,
        Option<tokio::runtime::Runtime>,
        Option<workload_api::WorkloadApiKeepalive>,
    ) {
        let source = BundleSource::File(file_path.into());
        if cfg.reload.enabled {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("workload identity: failed to build tokio runtime");
            let interval = Duration::from_secs(cfg.reload.check_interval_sec);
            // When clustered, gate each reload tick on a short-TTL
            // distributed lock (`identity.workload.refresh`).
            // `try_acquire_lock` returns `Ok(None)` on contention
            // without blocking the watcher task.
            let pre_tick: Option<mcpg_bundle_reload::PreTickHook> = cluster.as_ref().map(|c| {
                let c = c.clone();
                // Hold the refresh lock across the whole reload
                // (parse + ArcSwap), not just one poll interval, so a slow
                // parse can't let the lease expire mid-reload and let a
                // peer reload concurrently. Best-effort dedup, not a safety
                // fence (the bundle swap is idempotent; the token is only
                // logged).
                let lock_ttl = (interval * 5).max(Duration::from_secs(30));
                let arc: mcpg_bundle_reload::PreTickHook =
                    std::sync::Arc::new(move || -> Option<mcpg_bundle_reload::ReloadPermit> {
                        match c.try_acquire_lock("identity.workload.refresh", lock_ttl) {
                            Ok(Some(lease)) => {
                                tracing::debug!(
                                    plugin_id = PLUGIN_ID,
                                    fencing_token = lease.fencing_token(),
                                    "workload identity: refresh lock acquired"
                                );
                                Some(Box::new(lease) as mcpg_bundle_reload::ReloadPermit)
                            }
                            Ok(None) => {
                                tracing::debug!(
                                    plugin_id = PLUGIN_ID,
                                    "workload identity: refresh lock held by peer; skipping tick"
                                );
                                None
                            }
                            Err(e) => {
                                tracing::warn!(
                                    plugin_id = PLUGIN_ID,
                                    error = %e,
                                    "workload identity: refresh lock attempt failed; skipping tick"
                                );
                                None
                            }
                        }
                    });
                arc
            });
            let opts = match pre_tick {
                Some(h) => mcpg_bundle_reload::BundleReloadOptions::new(interval).with_pre_tick(h),
                None => mcpg_bundle_reload::BundleReloadOptions::new(interval),
            };
            let reload = rt
                .block_on(async {
                    mcpg_bundle_reload::start_with_options(source, parse_bundle, opts).await
                })
                .unwrap_or_else(|err| panic!("workload identity: failed to load bundle: {err}"));
            (reload, Some(rt), None)
        } else {
            let parsed = parse_bundle(&source)
                .unwrap_or_else(|err| panic!("workload identity: failed to load bundle: {err}"));
            let fingerprint = fingerprint_file(file_path).unwrap_or_else(|err| {
                panic!("workload identity: failed to fingerprint bundle: {err}")
            });
            let reload = mcpg_bundle_reload::static_only(parsed, fingerprint);
            (reload, None, None)
        }
    }

    fn build_workload_api_bundle(
        cfg: &WorkloadConfig,
        socket_path: &str,
    ) -> (
        BundleReload<ParsedBundle>,
        Option<tokio::runtime::Runtime>,
        Option<workload_api::WorkloadApiKeepalive>,
    ) {
        // The Workload API client uses tonic + tokio under the
        // hood; spin up a dedicated multi-thread runtime so the
        // streamer's reconnect/backoff loop runs independently of
        // any caller-supplied runtime. One worker is enough — the
        // streams are coarse-grained (one update every key
        // rotation, ~hourly).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("identity-workload-spire-api")
            .build()
            .expect("workload identity: failed to build tokio runtime");
        let (reload, keepalive) = rt
            .block_on(workload_api::start(socket_path, &cfg.trust_domain))
            .unwrap_or_else(|err| {
                panic!(
                    "workload identity: SPIRE Workload API setup failed: {err} \
                     (socket: {socket_path}, trust_domain: {})",
                    cfg.trust_domain
                )
            });
        (reload, Some(rt), Some(keepalive))
    }
}

/// Parsed view of the SPIFFE Trust Domain Bundle file. Held by
/// `Inner.bundle` and atomically replaced on reload.
#[derive(Clone)]
pub struct ParsedBundle {
    /// JWT signing keys, keyed by `kid`.
    pub jwt_keys: BTreeMap<String, DecodingKey>,
    /// X.509 trust roots. Empty when no `use: x509-svid` keys are
    /// present in the bundle (legacy JWT-only bundles, plain JWKS).
    /// Empty store rejects every X.509 chain at validation time.
    pub x509: X509TrustStore,
}

/// A federated foreign trust domain's parsed bundle. Same
/// content as a local [`ParsedBundle`] but indexed under its
/// foreign trust domain rather than `inner.config.trust_domain`
/// (the BTreeMap key in `Inner.federated` carries the domain
/// string — keeping it inline here would duplicate that key).
///
/// Static-load only — operators restart to pick up federated
/// bundle rotations. Hot-reload per federated entry is not yet
/// supported (the local bundle's `BundleReload` would compose,
/// but with one watcher per federation entry the boot graph gets
/// noisy).
#[derive(Clone)]
pub(crate) struct FederatedBundle {
    pub parsed: Arc<ParsedBundle>,
    /// Fingerprint of the bundle bytes — surfaced through
    /// `spiffe.federation_fingerprint` so audit consumers can
    /// distinguish identities resolved against different bundle
    /// versions.
    pub fingerprint: String,
}

fn parse_bundle(source: &BundleSource) -> Result<ParsedBundle, ReloadError> {
    let paths = source.list_files()?;
    let path = paths
        .first()
        .ok_or_else(|| ReloadError::Parse("bundle source produced no files".into()))?;
    let bytes = std::fs::read(path).map_err(|e| ReloadError::Io {
        path: path.display().to_string(),
        error: e.to_string(),
    })?;
    parse_spiffe_bundle(&bytes).map_err(ReloadError::Parse)
}

fn fingerprint_file(path: &str) -> Result<String, ReloadError> {
    let bytes = std::fs::read(path).map_err(|e| ReloadError::Io {
        path: path.to_owned(),
        error: e.to_string(),
    })?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    hasher.update(b"\x00");
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Parse a SPIFFE Trust Domain Bundle (or legacy JWKS) file.
///
/// Accepts three on-disk shapes, in priority order:
///
/// 1. **SPIFFE Trust Domain Bundle** — single `keys` array where
///    each entry has a `use` discriminator: `"jwt-svid"` for JWT
///    signing keys (RSA/EC with JWK fields) or `"x509-svid"` for
///    trust roots (cert in `x5c[0]` as base64-DER).
/// 2. **Legacy SPIRE bundle** — `jwt_signing_keys` array, JWT-only.
///    No X.509 trust roots in this format.
/// 3. **Plain JWKS** — `keys` array without `use`. JWT-only.
///
/// At least one of (jwt_keys, x509_roots) must be non-empty;
/// otherwise the bundle is unusable. We accept the X.509-only and
/// JWT-only cases — operators may run JWT-SVID-only or
/// X.509-SVID-only deployments.
fn parse_spiffe_bundle(bytes: &[u8]) -> Result<ParsedBundle, String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        jwt_signing_keys: Vec<RawKey>,
        #[serde(default)]
        keys: Vec<RawKey>,
    }
    #[derive(Deserialize)]
    struct RawKey {
        #[serde(default)]
        kid: Option<String>,
        #[serde(default)]
        kty: Option<String>,
        #[serde(rename = "use", default)]
        usage: Option<String>,
        #[serde(default)]
        n: Option<String>,
        #[serde(default)]
        e: Option<String>,
        #[serde(default)]
        x: Option<String>,
        #[serde(default)]
        y: Option<String>,
        #[serde(default)]
        crv: Option<String>,
        #[serde(default)]
        x5c: Vec<String>,
    }

    let raw: Raw =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid bundle JSON: {e}"))?;
    let keys_iter = raw.jwt_signing_keys.into_iter().chain(raw.keys);

    let mut jwt_keys: BTreeMap<String, DecodingKey> = BTreeMap::new();
    let mut x509_roots: Vec<Vec<u8>> = Vec::new();

    for key in keys_iter {
        // SPIFFE Trust Domain Bundle uses `use` to discriminate.
        // When absent (legacy JWKS / pre-spec SPIRE), default to
        // jwt-svid — that's what the existing format meant.
        let usage = key.usage.as_deref().unwrap_or("jwt-svid");
        match usage {
            "x509-svid" => {
                let cert_b64 = key.x5c.first().ok_or_else(|| {
                    format!(
                        "x509-svid bundle entry (kid={:?}) missing `x5c` cert",
                        key.kid
                    )
                })?;
                let der = B64
                    .decode(cert_b64.as_bytes())
                    .map_err(|e| format!("x509-svid x5c base64 decode: {e}"))?;
                x509_roots.push(der);
            }
            "jwt-svid" => {
                let kid = key.kid.ok_or("jwt-svid bundle entry missing `kid`")?;
                let kty = key
                    .kty
                    .as_deref()
                    .ok_or_else(|| format!("jwt-svid key {kid} missing `kty`"))?;
                let decoded = match kty {
                    "RSA" => {
                        let n = key
                            .n
                            .as_deref()
                            .ok_or_else(|| format!("jwt-svid RSA key {kid} missing `n`"))?;
                        let e = key
                            .e
                            .as_deref()
                            .ok_or_else(|| format!("jwt-svid RSA key {kid} missing `e`"))?;
                        DecodingKey::from_rsa_components(n, e)
                            .map_err(|err| format!("invalid RSA key {kid}: {err}"))?
                    }
                    "EC" => {
                        let x = key
                            .x
                            .as_deref()
                            .ok_or_else(|| format!("jwt-svid EC key {kid} missing `x`"))?;
                        let y = key
                            .y
                            .as_deref()
                            .ok_or_else(|| format!("jwt-svid EC key {kid} missing `y`"))?;
                        let _ = key.crv;
                        DecodingKey::from_ec_components(x, y)
                            .map_err(|err| format!("invalid EC key {kid}: {err}"))?
                    }
                    other => {
                        return Err(format!(
                            "unsupported JWK kty `{other}` for key `{kid}` \
                             (only RSA + EC supported)"
                        ));
                    }
                };
                jwt_keys.insert(kid, decoded);
            }
            other => {
                tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    usage = %other,
                    kid = ?key.kid,
                    "workload identity: bundle entry has unrecognised `use` value; ignoring"
                );
            }
        }
    }

    if jwt_keys.is_empty() && x509_roots.is_empty() {
        return Err(
            "trust bundle has no usable keys (need at least one jwt-svid or \
             x509-svid entry)"
                .into(),
        );
    }

    Ok(ParsedBundle {
        jwt_keys,
        x509: X509TrustStore::from_der_roots(x509_roots),
    })
}

fn lookup_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(n, v)| {
        if n.eq_ignore_ascii_case(name) {
            Some(v.as_str())
        } else {
            None
        }
    })
}

fn extract_token(source: &SvidSource, headers: &[(String, String)]) -> Option<String> {
    match source.kind {
        SourceKind::X509Svid => None, // X.509 path doesn't pull from headers
        SourceKind::JwtSvidBearer => {
            let raw = lookup_header(headers, "authorization")?;
            // Case-insensitive scheme match per RFC 7235.
            let rest = raw
                .strip_prefix("Bearer ")
                .or_else(|| raw.strip_prefix("bearer "))?;
            if rest.is_empty() {
                None
            } else {
                Some(rest.to_owned())
            }
        }
        SourceKind::JwtSvidHeader => {
            let header_name = source.header.as_deref()?;
            let raw = lookup_header(headers, header_name)?;
            // Header may be unprefixed OR `Bearer <jwt>` for envoy-
            // forwarded auth headers.
            let token = raw
                .strip_prefix("Bearer ")
                .or_else(|| raw.strip_prefix("bearer "))
                .unwrap_or(raw);
            if token.is_empty() {
                None
            } else {
                Some(token.to_owned())
            }
        }
    }
}

fn parse_spiffe_id(id: &str) -> Option<(String, String)> {
    // SPIFFE ID format: spiffe://<trust_domain>/<workload_path>
    let rest = id.strip_prefix("spiffe://")?;
    let (trust_domain, workload_path) = rest.split_once('/')?;
    if trust_domain.is_empty() || workload_path.is_empty() {
        return None;
    }
    Some((trust_domain.to_owned(), workload_path.to_owned()))
}

#[derive(Deserialize)]
struct SvidClaims {
    sub: String,
    #[serde(default)]
    iss: Option<String>,
}

/// Cheap pre-verification peek of a JWT's `sub` claim. Used by
/// federation dispatch to route the verification to the right
/// trust bundle BEFORE we know which key/bundle to verify against.
///
/// Safety: the returned value is unsigned at this point. It only
/// drives bundle selection — the subsequent `decode::<SvidClaims>`
/// call re-derives `sub` from the verified payload and we
/// cross-check that the verified `sub`'s trust domain matches the
/// peeked one. An attacker who flipped the unsigned `sub` to a
/// foreign trust domain would route verification at THAT domain's
/// keys; without that domain's signing key they can't produce a
/// valid signature, so verification fails.
fn peek_jwt_sub(token: &str) -> Result<String, String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let mut parts = token.split('.');
    let _header = parts.next().ok_or("JWT missing header segment")?;
    let payload_b64 = parts
        .next()
        .ok_or("JWT missing payload segment (no `.` separator)")?;
    if payload_b64.is_empty() {
        return Err("JWT payload segment is empty".into());
    }
    let payload_bytes = B64URL
        .decode(payload_b64.as_bytes())
        .map_err(|e| format!("JWT payload base64 decode: {e}"))?;
    #[derive(Deserialize)]
    struct OnlySub {
        sub: String,
    }
    let only: OnlySub = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JWT payload JSON decode: {e}"))?;
    Ok(only.sub)
}

/// Snapshot of the trust bundle for a single trust domain, plus
/// federation-provenance metadata. The local bundle has
/// `federation_fingerprint == None`; federated bundles carry the
/// fingerprint of the bundle file that was loaded for that
/// foreign domain.
struct BundleSnapshot {
    parsed: Arc<ParsedBundle>,
    federation_fingerprint: Option<String>,
}

/// Resolve which trust bundle should verify a SVID claiming the
/// given trust domain. Returns `None` when the trust domain is
/// neither the local domain nor any configured federated entry —
/// callers surface that as an explicit "unknown trust domain"
/// error so misconfigured allowlists / federations don't silently
/// fall through to the next source.
fn snapshot_bundle_for(inner: &Inner, trust_domain: &str) -> Option<BundleSnapshot> {
    if trust_domain == inner.config.trust_domain {
        return Some(BundleSnapshot {
            parsed: inner.bundle.load(),
            federation_fingerprint: None,
        });
    }
    inner.federated.get(trust_domain).map(|fed| BundleSnapshot {
        parsed: Arc::clone(&fed.parsed),
        federation_fingerprint: Some(fed.fingerprint.clone()),
    })
}

/// Result of validating a single SVID source, before allowlist /
/// metadata enforcement runs.
struct ValidatedSvid {
    spiffe_id: String,
    /// "x509" or "jwt" — drives `spiffe.svid_format`.
    format: &'static str,
    /// Issuer string for `PluginIdentity.issuer`. `Some(jwt_iss)`
    /// for JWT-SVIDs, `None` for X.509-SVIDs (the issuer DN is on
    /// the chain itself; not surfaced as a SPIFFE issuer).
    issuer: Option<String>,
    /// Format-specific attributes merged into the final
    /// `PluginIdentity.attributes` (e.g. `spiffe.cert_fingerprint`
    /// for X.509 or `spiffe.jwt_kid` for JWT). Federation-resolved
    /// SVIDs additionally carry `spiffe.federation_source` (the
    /// foreign trust domain) and `spiffe.federation_fingerprint`
    /// (the foreign bundle's hash).
    extras: Vec<(&'static str, String)>,
}

/// Build the JWT-SVID validation policy.
///
/// Split out so the binding it enforces is unit-testable without a signing
/// key fixture. When `audiences` is non-empty the JWT MUST carry an `aud`
/// that intersects it — `set_audience` alone only checks an `aud` that is
/// already present, so a token omitting the claim would otherwise skip the
/// binding entirely. An empty `audiences` is an explicit opt-out: config
/// validation only permits it under `allow_any_audience: true`.
fn build_svid_validation(alg: Algorithm, audiences: &[String]) -> Validation {
    let mut validation = Validation::new(alg);
    // `exp` is always required; a JWT-SVID without one never expires.
    let mut required = vec!["exp".to_owned()];
    if audiences.is_empty() {
        validation.validate_aud = false;
    } else {
        validation.set_audience(audiences);
        required.push("aud".to_owned());
    }
    validation.set_required_spec_claims(&required);
    // A JWT-SVID that is not yet valid must be refused, not accepted early.
    validation.validate_nbf = true;
    validation
}

fn verify_jwt_svid(inner: &Inner, token: &str) -> Result<ValidatedSvid, String> {
    // 1. Peek `sub` to decide which trust bundle to verify against.
    //    Federation requires us to select the bundle BEFORE we have
    //    a verified key; the signature check below is the actual
    //    trust gate. See `peek_jwt_sub`'s safety note.
    let peeked_sub = peek_jwt_sub(token)?;
    let (peek_td, _peek_path) = parse_spiffe_id(&peeked_sub)
        .ok_or_else(|| format!("`sub` claim is not a SPIFFE ID: `{peeked_sub}`"))?;

    let snapshot = snapshot_bundle_for(inner, &peek_td).ok_or_else(|| {
        format!(
            "trust domain `{peek_td}` is not the local domain (`{}`) and is not in \
             federated_trust_domains",
            inner.config.trust_domain
        )
    })?;

    let header = decode_header(token).map_err(|e| format!("invalid JWT header: {e}"))?;
    let kid = header
        .kid
        .ok_or("JWT header missing `kid` — cannot select trust bundle key")?;
    let key = snapshot
        .parsed
        .jwt_keys
        .get(&kid)
        .ok_or_else(|| format!("trust bundle for `{peek_td}` has no key for kid `{kid}`"))?;

    let alg = match header.alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => header.alg,
        Algorithm::ES256 | Algorithm::ES384 => header.alg,
        // SPIFFE spec disallows `none` and HS* — same here.
        other => return Err(format!("unsupported JWT-SVID algorithm: {other:?}")),
    };
    let validation = build_svid_validation(alg, &inner.config.audiences);

    let token_data = decode::<SvidClaims>(token, key, &validation)
        .map_err(|e| format!("JWT verification failed: {e}"))?;

    let spiffe_id = token_data.claims.sub;
    let (verified_td, _verified_path) = parse_spiffe_id(&spiffe_id)
        .ok_or_else(|| format!("`sub` claim is not a SPIFFE ID: `{spiffe_id}`"))?;
    // Defence-in-depth: peek vs. verified `sub` MUST agree. Same
    // bytes, same parser — divergence indicates token tampering
    // between the peek and the signature check, which shouldn't
    // be reachable but cheap to assert.
    if verified_td != peek_td {
        return Err(format!(
            "JWT `sub` mismatch after verification: peek=`{peek_td}` \
             verified=`{verified_td}`"
        ));
    }

    let mut extras: Vec<(&'static str, String)> = vec![("spiffe.jwt_kid", kid)];
    if let Some(fp) = snapshot.federation_fingerprint {
        extras.push(("spiffe.federation_source", peek_td));
        extras.push(("spiffe.federation_fingerprint", fp));
    }

    Ok(ValidatedSvid {
        spiffe_id,
        format: "jwt",
        issuer: token_data.claims.iss,
        extras,
    })
}

fn verify_x509_svid(
    inner: &Inner,
    tls: &mcpg_plugin_protocol::types::TlsInfo,
) -> Result<ValidatedSvid, String> {
    if !tls.client_cert_present || tls.client_cert_chain_der.is_empty() {
        // Caller already filtered to "we have an X.509 source AND
        // metadata.tls.is_some()", but the cert chain itself can
        // still be empty (handshake failed earlier, or the gateway
        // observed TLS without a client cert). Treat as
        // "source produces nothing" so the chain falls through to
        // the next source rather than erroring on absence.
        return Err("x509-svid: no client cert present".into());
    }

    // 1. Peek the leaf's SPIFFE URI to decide which trust store
    //    to validate against. See `x509::peek_leaf_spiffe_uri`'s
    //    safety note — the actual chain check below re-extracts
    //    + cross-checks the URI from the validated leaf.
    let leaf_der = tls
        .client_cert_chain_der
        .first()
        .ok_or("x509-svid: no client cert present")?;
    let peeked_uri = x509::peek_leaf_spiffe_uri(leaf_der).map_err(|e| format!("x509-svid: {e}"))?;
    let (peek_td, _peek_path) = parse_spiffe_id(&peeked_uri)
        .ok_or_else(|| format!("x509-svid leaf SAN URI is not a SPIFFE ID: `{peeked_uri}`"))?;

    let snapshot = snapshot_bundle_for(inner, &peek_td).ok_or_else(|| {
        format!(
            "x509-svid: trust domain `{peek_td}` is not the local domain (`{}`) \
             and is not in federated_trust_domains",
            inner.config.trust_domain
        )
    })?;

    let now = rustls_pki_types::UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|e| format!("x509-svid: system clock pre-epoch: {e}"))?,
    );
    let svid = snapshot
        .parsed
        .x509
        .validate_chain(&tls.client_cert_chain_der, now)
        .map_err(|e| format!("x509-svid: {e}"))?;

    let (verified_td, _verified_path) = parse_spiffe_id(&svid.spiffe_id)
        .ok_or_else(|| format!("x509-svid SAN URI is not a SPIFFE ID: `{}`", svid.spiffe_id))?;
    // Defence-in-depth: same bytes, same parser — divergence here
    // would indicate a parser bug, not an attack vector.
    if verified_td != peek_td {
        return Err(format!(
            "x509-svid: SAN URI mismatch after chain validation: \
             peek=`{peek_td}` verified=`{verified_td}`"
        ));
    }

    let mut extras: Vec<(&'static str, String)> =
        vec![("spiffe.cert_fingerprint", svid.leaf_fingerprint_sha256)];
    if let Some(fp) = snapshot.federation_fingerprint {
        extras.push(("spiffe.federation_source", peek_td));
        extras.push(("spiffe.federation_fingerprint", fp));
    }

    Ok(ValidatedSvid {
        spiffe_id: svid.spiffe_id,
        format: "x509",
        issuer: None,
        extras,
    })
}

/// Outcome of a single source attempt before the chain runs the
/// allowlist + metadata stages.
enum SourceOutcome {
    /// Source produced no input (e.g. header missing, no client
    /// cert) — keep walking.
    NotPresent,
    /// Source produced input, validation succeeded.
    Resolved(ValidatedSvid),
    /// Source produced input, validation failed — keep walking but
    /// remember the reason for the final `Invalid`.
    Invalid(String),
}

fn try_source(
    inner: &Inner,
    source: &SvidSource,
    headers: &[(String, String)],
    metadata: &mcpg_plugin_protocol::types::RequestMetadata,
) -> SourceOutcome {
    match source.kind {
        SourceKind::X509Svid => match metadata.tls.as_ref() {
            None => SourceOutcome::NotPresent,
            Some(tls) if !tls.client_cert_present => SourceOutcome::NotPresent,
            Some(tls) => match verify_x509_svid(inner, tls) {
                Ok(v) => SourceOutcome::Resolved(v),
                Err(reason) => SourceOutcome::Invalid(reason),
            },
        },
        SourceKind::JwtSvidBearer | SourceKind::JwtSvidHeader => {
            let Some(token) = extract_token(source, headers) else {
                return SourceOutcome::NotPresent;
            };
            match verify_jwt_svid(inner, &token) {
                Ok(v) => SourceOutcome::Resolved(v),
                Err(reason) => SourceOutcome::Invalid(reason),
            }
        }
    }
}

fn build_resolution(
    inner: &Inner,
    source: &SvidSource,
    validated: ValidatedSvid,
) -> IdentityResolution {
    let ValidatedSvid {
        spiffe_id,
        format,
        issuer,
        extras,
    } = validated;

    if matches!(inner.config.mode, Mode::Allowlist)
        && !inner
            .config
            .allowlist
            .iter()
            .any(|allowed| allowed == &spiffe_id)
    {
        return IdentityResolution::Invalid {
            reason: format!("SPIFFE ID not in allowlist: `{spiffe_id}`"),
            response_headers: Vec::new(),
        };
    }

    let metadata = inner.config.identities.get(&spiffe_id).cloned();
    let mut attributes: BTreeMap<String, String> = metadata
        .as_ref()
        .map(|m| m.attributes.clone())
        .unwrap_or_default();
    // Always-populated attributes. `spiffe.id` matches the value
    // also set as `subject_id` — duplicated for downstream policy
    // plugins that filter by attribute keys without reaching for
    // the top-level field.
    attributes.insert("spiffe.id".into(), spiffe_id.clone());
    attributes.insert("spiffe.svid_format".into(), format.into());
    attributes.insert("spiffe.svid_source".into(), source.kind.tag().into());
    if let Some((td, path)) = parse_spiffe_id(&spiffe_id) {
        attributes.insert("spiffe.trust_domain".into(), td);
        attributes.insert("spiffe.path".into(), path);
    }
    // Backwards-compat: also emit `spiffe.source` (without the
    // `_svid` suffix) so existing policy rules don't break.
    attributes.insert("spiffe.source".into(), source.kind.tag().into());
    for (k, v) in extras {
        attributes.insert(k.into(), v);
    }

    IdentityResolution::Resolved {
        identity: PluginIdentity {
            kind: inner.config.resolution.trust_level.clone(),
            trust_level: inner.config.resolution.trust_level.clone(),
            subject_id: Some(spiffe_id),
            auth_provider: Some(inner.config.resolution.auth_provider_label.clone()),
            issuer,
            roles: metadata
                .as_ref()
                .map(|m| m.roles.clone())
                .unwrap_or_default(),
            groups: metadata
                .as_ref()
                .map(|m| m.groups.clone())
                .unwrap_or_default(),
            scopes: metadata
                .as_ref()
                .map(|m| m.scopes.clone())
                .unwrap_or_default(),
            attributes,
        },
    }
}

fn resolve(
    inner: &Inner,
    headers: &[(String, String)],
    metadata: &mcpg_plugin_protocol::types::RequestMetadata,
) -> IdentityResolution {
    let mut last_invalid: Option<String> = None;
    for source in &inner.config.sources {
        match try_source(inner, source, headers, metadata) {
            SourceOutcome::Resolved(v) => return build_resolution(inner, source, v),
            SourceOutcome::Invalid(reason) => last_invalid = Some(reason),
            SourceOutcome::NotPresent => continue,
        }
    }
    if let Some(reason) = last_invalid {
        IdentityResolution::Invalid {
            reason: format!("SPIFFE: {reason}"),
            response_headers: Vec::new(),
        }
    } else {
        IdentityResolution::None
    }
}

#[async_trait]
impl IdentityProviderPlugin for WorkloadIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        // Plugin-scoped span so traces from workload identity attribute
        // back to dev.mcpg.identity.workload.
        let _span = info_span!("identity_workload_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve(&self.inner, headers, metadata);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

impl SyncIdentityResolver for WorkloadIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_workload_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve(&self.inner, headers, metadata);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {
    plugin_id: "dev.mcpg.identity.workload",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    // TransportListen covers `cap.host.client_cert_acceptor`
    // (the X.509-SVID source consumes the gateway's mTLS handshake
    // metadata); NetworkOutbound covers `cap.host.unix_socket_client`
    // (Workload API client over /run/spire/sockets/agent.sock).
    capabilities: &[
        mcpg_plugin_protocol::capability::Capability::TransportListen,
        mcpg_plugin_protocol::capability::Capability::NetworkOutbound,
    ],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: WorkloadIdentityPlugin,
            // Receives a `HostHandle` from the macro. The plugin
            // derives the active cluster client via `host.cluster()`
            // to emit a startup heartbeat on
            // `identity.workload.started` and stash the client for
            // future cross-node coordination work.
            factory: |cfg: &str, host: ::mcpg_plugin_sdk::HostHandle| -> WorkloadIdentityPlugin {
                WorkloadIdentityPlugin::from_config_json_with_cluster(cfg, host.cluster())
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: integration tests that actually sign + verify a JWT
    // would need a stable RSA test key pair fixture (or runtime
    // key generation via aws-lc-rs). Both add weight that's
    // disproportionate for unit testing — those paths are
    // exercised by gateway-level integration tests against a
    // real SPIRE bundle. Unit tests below cover the
    // pre-verification logic (header extraction, SPIFFE ID
    // parsing, trust-domain check, config validation).

    /// `set_audience` only validates an `aud` that is present, so a
    /// signature-valid JWT-SVID carrying no `aud` at all would otherwise
    /// satisfy a configured audience binding by simply omitting the claim.
    #[test]
    fn configured_audiences_require_the_aud_claim() {
        let audiences = vec!["mcpg".to_owned()];
        let v = build_svid_validation(Algorithm::RS256, &audiences);
        assert!(
            v.required_spec_claims.contains("aud"),
            "aud must be required, not merely checked when present"
        );
        assert!(v.required_spec_claims.contains("exp"));
        assert!(v.validate_aud);
        assert!(v.validate_nbf, "a not-yet-valid SVID must be refused");
    }

    /// An empty `audiences` is the operator's explicit opt-out and must not
    /// start demanding a claim they chose not to bind.
    #[test]
    fn empty_audiences_opt_out_of_the_aud_binding() {
        let v = build_svid_validation(Algorithm::RS256, &[]);
        assert!(!v.validate_aud);
        assert!(!v.required_spec_claims.contains("aud"));
        assert!(v.required_spec_claims.contains("exp"));
    }

    #[test]
    fn parse_spiffe_id_well_formed() {
        let (td, path) = parse_spiffe_id("spiffe://example.org/workloads/orders").unwrap();
        assert_eq!(td, "example.org");
        assert_eq!(path, "workloads/orders");
    }

    #[test]
    fn parse_spiffe_id_rejects_non_spiffe_scheme() {
        assert!(parse_spiffe_id("https://example.org/x").is_none());
        assert!(parse_spiffe_id("spiffe://").is_none());
        assert!(parse_spiffe_id("spiffe://example.org").is_none());
        assert!(parse_spiffe_id("spiffe:///workload").is_none());
    }

    #[test]
    fn lookup_header_is_case_insensitive() {
        let h = vec![("Authorization".into(), "Bearer x".into())];
        assert_eq!(lookup_header(&h, "authorization"), Some("Bearer x"));
        assert_eq!(lookup_header(&h, "AUTHORIZATION"), Some("Bearer x"));
        assert!(lookup_header(&h, "x-other").is_none());
    }

    #[test]
    fn extract_token_bearer_strips_scheme() {
        let source = JwtSvidSource {
            kind: SourceKind::JwtSvidBearer,
            header: None,
        };
        let h = vec![("Authorization".into(), "Bearer eyJxxx".into())];
        assert_eq!(extract_token(&source, &h), Some("eyJxxx".into()));
    }

    #[test]
    fn extract_token_bearer_returns_none_for_other_scheme() {
        let source = JwtSvidSource {
            kind: SourceKind::JwtSvidBearer,
            header: None,
        };
        let h = vec![("Authorization".into(), "Basic eyJxxx".into())];
        assert!(extract_token(&source, &h).is_none());
    }

    #[test]
    fn extract_token_header_works_with_or_without_bearer_prefix() {
        let source = JwtSvidSource {
            kind: SourceKind::JwtSvidHeader,
            header: Some("X-Forwarded-Authorization".into()),
        };
        let h1 = vec![("X-Forwarded-Authorization".into(), "Bearer eyJxxx".into())];
        assert_eq!(extract_token(&source, &h1), Some("eyJxxx".into()));
        let h2 = vec![("X-Forwarded-Authorization".into(), "eyJxxx".into())];
        assert_eq!(extract_token(&source, &h2), Some("eyJxxx".into()));
    }

    #[test]
    fn extract_token_header_returns_none_when_absent() {
        let source = JwtSvidSource {
            kind: SourceKind::JwtSvidHeader,
            header: Some("X-Forwarded-Authorization".into()),
        };
        let h = vec![("Authorization".into(), "Bearer x".into())];
        assert!(extract_token(&source, &h).is_none());
    }

    // ---------------------------------------------------------------
    // Bundle parser tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_bundle_legacy_jwt_signing_keys_only() {
        // The JWT-only SPIRE format. Should still parse cleanly
        // (operators with bundles already on disk don't have to
        // re-export to pick up x509 support).
        let bundle = serde_json::json!({
            "jwt_signing_keys": [{
                "kid": "k1",
                "kty": "EC",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            }]
        });
        let parsed = parse_spiffe_bundle(bundle.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.jwt_keys.len(), 1);
        assert_eq!(parsed.x509.root_count(), 0);
    }

    #[test]
    fn parse_bundle_with_x509_root() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let (ca_der, _leaf) = crate::x509::tests_module::issue_test_pair("spiffe://example.org/x");
        let bundle = serde_json::json!({
            "keys": [
                {
                    "use": "x509-svid",
                    "x5c": [B64.encode(&ca_der)],
                },
                {
                    "use": "jwt-svid",
                    "kid": "k1",
                    "kty": "EC",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                },
            ]
        });
        let parsed = parse_spiffe_bundle(bundle.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.jwt_keys.len(), 1);
        assert_eq!(parsed.x509.root_count(), 1);
    }

    #[test]
    fn parse_bundle_x509_only_is_accepted() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let (ca_der, _) = crate::x509::tests_module::issue_test_pair("spiffe://example.org/x");
        let bundle = serde_json::json!({
            "keys": [{
                "use": "x509-svid",
                "x5c": [B64.encode(&ca_der)],
            }]
        });
        let parsed = parse_spiffe_bundle(bundle.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.jwt_keys.len(), 0);
        assert_eq!(parsed.x509.root_count(), 1);
    }

    #[test]
    fn parse_bundle_rejects_empty() {
        let bundle = serde_json::json!({ "keys": [] });
        let err = parse_spiffe_bundle(bundle.to_string().as_bytes())
            .err()
            .expect("empty bundle must fail to parse");
        assert!(
            err.contains("no usable keys"),
            "expected empty-bundle error, got: {err}"
        );
    }

    #[test]
    fn parse_bundle_rejects_x509_without_x5c() {
        let bundle = serde_json::json!({
            "keys": [{ "use": "x509-svid", "kid": "ca1" }]
        });
        let err = parse_spiffe_bundle(bundle.to_string().as_bytes())
            .err()
            .expect("x509 entry without x5c must fail");
        assert!(err.contains("x509"));
    }

    // ---------------------------------------------------------------
    // End-to-end resolve() tests for the X.509-SVID path
    // ---------------------------------------------------------------

    fn write_bundle_with_x509(tmpdir: &tempfile::TempDir, ca_der: &[u8]) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let bundle = serde_json::json!({
            "keys": [
                {
                    "use": "x509-svid",
                    "x5c": [B64.encode(ca_der)],
                },
                // Include a JWT key too so JWT-only sources also
                // work in mixed-source tests.
                {
                    "use": "jwt-svid",
                    "kid": "k1",
                    "kty": "EC",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                },
            ]
        });
        let path = tmpdir.path().join("bundle.json");
        std::fs::write(&path, bundle.to_string()).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn build_plugin(
        tmpdir: &tempfile::TempDir,
        ca_der: &[u8],
        sources_json: serde_json::Value,
    ) -> WorkloadIdentityPlugin {
        let bundle_path = write_bundle_with_x509(tmpdir, ca_der);
        let cfg = serde_json::json!({
            "trust_domain": "example.org",
            "bundle": { "kind": "file", "file_path": bundle_path },
            "sources": sources_json,
            "allow_any_audience": true,
        });
        WorkloadIdentityPlugin::from_config_json(&cfg.to_string())
    }

    fn tls_info_with_chain(chain: Vec<Vec<u8>>) -> mcpg_plugin_protocol::types::TlsInfo {
        mcpg_plugin_protocol::types::TlsInfo {
            client_cert_present: true,
            client_cert_chain_der: chain,
            ..Default::default()
        }
    }

    #[test]
    fn resolve_x509_svid_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let (ca_der, issuer) = crate::x509::tests_module::build_ca();
        let leaf_der = crate::x509::tests_module::sign_leaf(
            &issuer,
            "spiffe://example.org/ns/payments/sa/orders",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin(&tmp, &ca_der, serde_json::json!([{ "kind": "x509_svid" }]));

        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf_der])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(
                    identity.subject_id.as_deref(),
                    Some("spiffe://example.org/ns/payments/sa/orders")
                );
                assert_eq!(
                    identity
                        .attributes
                        .get("spiffe.svid_format")
                        .map(String::as_str),
                    Some("x509")
                );
                assert_eq!(
                    identity
                        .attributes
                        .get("spiffe.svid_source")
                        .map(String::as_str),
                    Some("x509_svid")
                );
                assert_eq!(
                    identity
                        .attributes
                        .get("spiffe.trust_domain")
                        .map(String::as_str),
                    Some("example.org")
                );
                assert_eq!(
                    identity.attributes.get("spiffe.path").map(String::as_str),
                    Some("ns/payments/sa/orders")
                );
                assert!(identity.attributes.contains_key("spiffe.cert_fingerprint"));
                assert!(identity.issuer.is_none());
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_x509_svid_wrong_trust_domain() {
        // Leaf claims a trust domain that's neither local nor
        // federated — the dispatch helper rejects before chain
        // validation ever runs (no bundle to verify against).
        let tmp = tempfile::tempdir().unwrap();
        let (ca_der, issuer) = crate::x509::tests_module::build_ca();
        let leaf_der = crate::x509::tests_module::sign_leaf(
            &issuer,
            "spiffe://other.example/x",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin(&tmp, &ca_der, serde_json::json!([{ "kind": "x509_svid" }]));

        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf_der])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Invalid { reason, .. } => {
                assert!(
                    reason.contains("other.example") && reason.contains("example.org"),
                    "expected dispatch error naming both trust domains, got: {reason}",
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn resolve_x509_svid_no_tls_falls_through() {
        // No TlsInfo on the request => X.509 source skipped silently.
        // With no other sources configured, this is `None`, not
        // `Invalid`.
        let tmp = tempfile::tempdir().unwrap();
        let (ca_der, _) = crate::x509::tests_module::build_ca();
        let plugin = build_plugin(&tmp, &ca_der, serde_json::json!([{ "kind": "x509_svid" }]));
        let outcome = resolve(
            &plugin.inner,
            &[],
            &mcpg_plugin_protocol::types::RequestMetadata::default(),
        );
        assert!(
            matches!(outcome, IdentityResolution::None),
            "got {outcome:?}"
        );
    }

    #[test]
    fn resolve_x509_svid_no_client_cert_falls_through_to_jwt() {
        // Hybrid deployment: x509 first then jwt. mTLS terminated
        // upstream so client_cert_present == false; JWT bearer
        // header is the actual SVID. Plugin must skip x509 (not
        // record an Invalid) and reach the JWT source. Without a
        // verified JWT token here we just assert "JWT-source
        // logic ran" by checking the outcome isn't an X.509 error.
        let tmp = tempfile::tempdir().unwrap();
        let (ca_der, _) = crate::x509::tests_module::build_ca();
        let plugin = build_plugin(
            &tmp,
            &ca_der,
            serde_json::json!([
                { "kind": "x509_svid" },
                { "kind": "jwt_svid_bearer" },
            ]),
        );
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(mcpg_plugin_protocol::types::TlsInfo::default()),
            ..Default::default()
        };
        // No Authorization header → JWT source also returns None
        // → final outcome is None (clean fallthrough, not Invalid
        // — proves x509 didn't poison the chain).
        let outcome = resolve(&plugin.inner, &[], &metadata);
        assert!(
            matches!(outcome, IdentityResolution::None),
            "got {outcome:?}"
        );
    }

    #[test]
    fn resolve_x509_svid_chain_invalid_records_reason() {
        // Bundle has CA-A, request has leaf signed by CA-B.
        // Should surface as Invalid with the chain-validation
        // reason — proving the fall-through-on-NotPresent path
        // doesn't swallow real validation failures.
        let tmp = tempfile::tempdir().unwrap();
        let (good_ca, _) = crate::x509::tests_module::build_ca();
        let (_, bad_issuer) = crate::x509::tests_module::build_ca();
        let bad_leaf = crate::x509::tests_module::sign_leaf(
            &bad_issuer,
            "spiffe://example.org/x",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin(&tmp, &good_ca, serde_json::json!([{ "kind": "x509_svid" }]));
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![bad_leaf])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Invalid { reason, .. } => {
                assert!(reason.contains("x509-svid"), "got: {reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn manifest_declares_no_legacy_capabilities() {
        // Capabilities moved to `PluginRegistration.capabilities`
        // (typed). The runtime manifest's `Vec<String>` is
        // display-only and empty;
        // the cdylib's typed declarations are the authoritative
        // source. The plugin's `declare_plugin!` invocation declares
        // the typed `TransportListen` (X.509-SVID source via
        // client-cert acceptor) + `NetworkOutbound` (Workload API
        // Unix socket) capabilities at compile time.
        let tmp = tempfile::tempdir().unwrap();
        let (ca_der, _) = crate::x509::tests_module::build_ca();
        let plugin = build_plugin(
            &tmp,
            &ca_der,
            serde_json::json!([{ "kind": "jwt_svid_bearer" }]),
        );
        let caps = &plugin.inner.manifest.required_capabilities;
        assert!(
            caps.is_empty(),
            "manifest caps are display-only and empty: {caps:?}"
        );
    }

    #[test]
    fn allowlist_blocks_unauthorised_x509_svid() {
        let tmp = tempfile::tempdir().unwrap();
        let (ca_der, issuer) = crate::x509::tests_module::build_ca();
        let leaf_der = crate::x509::tests_module::sign_leaf(
            &issuer,
            "spiffe://example.org/not/in/list",
            std::time::Duration::from_secs(3600),
        );
        let bundle_path = write_bundle_with_x509(&tmp, &ca_der);
        let cfg = serde_json::json!({
            "trust_domain": "example.org",
            "bundle": { "kind": "file", "file_path": bundle_path },
            "sources": [{ "kind": "x509_svid" }],
            "mode": "allowlist",
            "allowlist": ["spiffe://example.org/different/path"],
            "allow_any_audience": true,
        });
        let plugin = WorkloadIdentityPlugin::from_config_json(&cfg.to_string());

        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf_der])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Invalid { reason, .. } => {
                assert!(reason.contains("not in allowlist"), "got: {reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // peek_jwt_sub helper (pre-verification routing peek)
    // ---------------------------------------------------------------

    fn make_unsigned_jwt(payload: &str) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let header = B64URL.encode(br#"{"alg":"ES256","kid":"k1"}"#);
        let payload_b64 = B64URL.encode(payload.as_bytes());
        let signature = B64URL.encode(b"fake-signature");
        format!("{header}.{payload_b64}.{signature}")
    }

    #[test]
    fn peek_jwt_sub_extracts_sub_from_unsigned_payload() {
        let token =
            make_unsigned_jwt(r#"{"sub":"spiffe://example.org/x","iss":"spiffe://example.org"}"#);
        assert_eq!(peek_jwt_sub(&token).unwrap(), "spiffe://example.org/x");
    }

    #[test]
    fn peek_jwt_sub_rejects_token_without_payload_segment() {
        let err = peek_jwt_sub("only_header").unwrap_err();
        assert!(err.contains("payload"), "got: {err}");
    }

    #[test]
    fn peek_jwt_sub_rejects_empty_payload_segment() {
        let err = peek_jwt_sub("aaa..bbb").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn peek_jwt_sub_rejects_invalid_base64() {
        // `!` is not in the URL-safe base64 alphabet.
        let err = peek_jwt_sub("aaaa.!!!.zzz").unwrap_err();
        assert!(err.contains("base64"), "got: {err}");
    }

    #[test]
    fn peek_jwt_sub_rejects_payload_without_sub() {
        let token = make_unsigned_jwt(r#"{"iss":"x"}"#);
        let err = peek_jwt_sub(&token).unwrap_err();
        assert!(err.contains("JSON"), "got: {err}");
    }

    // ---------------------------------------------------------------
    // Federation: end-to-end resolve() over X.509-SVID. Asserts the
    // dispatch flow picks the right trust store, populates the
    // `spiffe.federation_*` attributes, and rejects unknown trust
    // domains. JWT federation rides on the same dispatch helpers
    // (snapshot_bundle_for) — the JWT path is exercised at gateway
    // integration level, consistent with the rest of this file's
    // unit-vs-integration split.
    // ---------------------------------------------------------------

    fn write_x509_only_bundle(tmpdir: &tempfile::TempDir, name: &str, ca_der: &[u8]) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let bundle = serde_json::json!({
            "keys": [{ "use": "x509-svid", "x5c": [B64.encode(ca_der)] }]
        });
        let path = tmpdir.path().join(name);
        std::fs::write(&path, bundle.to_string()).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn build_plugin_with_federation(
        tmpdir: &tempfile::TempDir,
        local_ca_der: &[u8],
        federated: &[(&str, &[u8])],
        extra: serde_json::Value,
    ) -> WorkloadIdentityPlugin {
        let local_path = write_bundle_with_x509(tmpdir, local_ca_der);
        let federated_cfg: Vec<serde_json::Value> = federated
            .iter()
            .enumerate()
            .map(|(i, (td, ca))| {
                let path = write_x509_only_bundle(tmpdir, &format!("bundle_fed_{i}.json"), ca);
                serde_json::json!({
                    "trust_domain": td,
                    "bundle": { "kind": "file", "file_path": path },
                })
            })
            .collect();
        let mut cfg = serde_json::json!({
            "trust_domain": "example.org",
            "bundle": { "kind": "file", "file_path": local_path },
            "sources": [{ "kind": "x509_svid" }],
            "federated_trust_domains": federated_cfg,
            "allow_any_audience": true,
        });
        if let serde_json::Value::Object(m) = extra {
            for (k, v) in m {
                cfg[k] = v;
            }
        }
        WorkloadIdentityPlugin::from_config_json(&cfg.to_string())
    }

    #[test]
    fn resolve_x509_svid_federated_happy_path() {
        // Local CA issues `example.org` SVIDs. Federated CA issues
        // `payments.example` SVIDs. A leaf signed by the federated
        // CA with a `payments.example` URI must dispatch to the
        // federated bundle, validate, and surface the federation
        // attributes.
        let tmp = tempfile::tempdir().unwrap();
        let (local_ca, _local_issuer) = crate::x509::tests_module::build_ca();
        let (fed_ca, fed_issuer) = crate::x509::tests_module::build_ca();
        let leaf = crate::x509::tests_module::sign_leaf(
            &fed_issuer,
            "spiffe://payments.example/svc/orders",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin_with_federation(
            &tmp,
            &local_ca,
            &[("payments.example", &fed_ca)],
            serde_json::json!({}),
        );
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(
                    identity.subject_id.as_deref(),
                    Some("spiffe://payments.example/svc/orders"),
                );
                assert_eq!(
                    identity
                        .attributes
                        .get("spiffe.trust_domain")
                        .map(String::as_str),
                    Some("payments.example"),
                );
                assert_eq!(
                    identity
                        .attributes
                        .get("spiffe.federation_source")
                        .map(String::as_str),
                    Some("payments.example"),
                    "federated SVIDs MUST carry `spiffe.federation_source`",
                );
                let fp = identity
                    .attributes
                    .get("spiffe.federation_fingerprint")
                    .expect("federated SVIDs MUST carry `spiffe.federation_fingerprint`");
                assert_eq!(fp.len(), 64, "fingerprint should be 64-char sha256 hex");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_x509_svid_local_path_omits_federation_attrs() {
        // Negative control: local-domain SVID resolves without
        // emitting federation attributes (they only appear for
        // foreign-domain dispatches).
        let tmp = tempfile::tempdir().unwrap();
        let (local_ca, local_issuer) = crate::x509::tests_module::build_ca();
        let (fed_ca, _) = crate::x509::tests_module::build_ca();
        let leaf = crate::x509::tests_module::sign_leaf(
            &local_issuer,
            "spiffe://example.org/svc/orders",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin_with_federation(
            &tmp,
            &local_ca,
            &[("payments.example", &fed_ca)],
            serde_json::json!({}),
        );
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Resolved { identity } => {
                assert!(
                    !identity.attributes.contains_key("spiffe.federation_source"),
                    "local-domain SVIDs MUST NOT carry federation_source",
                );
                assert!(
                    !identity
                        .attributes
                        .contains_key("spiffe.federation_fingerprint"),
                    "local-domain SVIDs MUST NOT carry federation_fingerprint",
                );
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_x509_svid_unknown_trust_domain_invalid() {
        // Leaf claims `unknown.example` — not local, not federated.
        // Dispatch must reject before chain validation runs (no
        // bundle to verify against).
        let tmp = tempfile::tempdir().unwrap();
        let (local_ca, _) = crate::x509::tests_module::build_ca();
        let (other_ca, other_issuer) = crate::x509::tests_module::build_ca();
        let leaf = crate::x509::tests_module::sign_leaf(
            &other_issuer,
            "spiffe://unknown.example/svc",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin_with_federation(
            &tmp,
            &local_ca,
            &[("payments.example", &other_ca)],
            serde_json::json!({}),
        );
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Invalid { reason, .. } => {
                assert!(
                    reason.contains("unknown.example"),
                    "expected unknown-domain in error, got: {reason}",
                );
                assert!(
                    reason.contains("federated_trust_domains"),
                    "error should hint at the federation config: {reason}",
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn resolve_x509_svid_federated_leaf_signed_by_local_ca_rejected() {
        // Cross-trust-domain attack: leaf claims `payments.example`
        // (so dispatch picks the federated bundle) but is actually
        // signed by the local CA. The federated bundle's roots
        // don't include the local CA → chain validation MUST fail.
        let tmp = tempfile::tempdir().unwrap();
        let (local_ca, local_issuer) = crate::x509::tests_module::build_ca();
        let (fed_ca, _) = crate::x509::tests_module::build_ca();
        let attacker_leaf = crate::x509::tests_module::sign_leaf(
            &local_issuer,
            "spiffe://payments.example/x",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin_with_federation(
            &tmp,
            &local_ca,
            &[("payments.example", &fed_ca)],
            serde_json::json!({}),
        );
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![attacker_leaf])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Invalid { reason, .. } => {
                assert!(
                    reason.contains("x509-svid"),
                    "expected chain-validation reason, got: {reason}",
                );
            }
            other => panic!("expected Invalid (chain-failure), got {other:?}"),
        }
    }

    #[test]
    fn resolve_x509_svid_federated_allowlist_accepts_foreign_id() {
        // Allowlist names a `payments.example` SPIFFE ID. The
        // config validator allows the entry because the domain is
        // configured under federation; resolve-time the foreign
        // SVID matches the allowlist and succeeds.
        let tmp = tempfile::tempdir().unwrap();
        let (local_ca, _) = crate::x509::tests_module::build_ca();
        let (fed_ca, fed_issuer) = crate::x509::tests_module::build_ca();
        let leaf = crate::x509::tests_module::sign_leaf(
            &fed_issuer,
            "spiffe://payments.example/svc/orders",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin_with_federation(
            &tmp,
            &local_ca,
            &[("payments.example", &fed_ca)],
            serde_json::json!({
                "mode": "allowlist",
                "allowlist": ["spiffe://payments.example/svc/orders"],
            }),
        );
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        assert!(
            matches!(outcome, IdentityResolution::Resolved { .. }),
            "got {outcome:?}",
        );
    }

    #[test]
    fn resolve_x509_svid_federated_allowlist_blocks_unlisted_foreign_id() {
        // Federation widens the *valid* set of trust domains; it
        // does NOT widen the allowlist. A foreign-domain SVID not
        // in the allowlist is still rejected after dispatch.
        let tmp = tempfile::tempdir().unwrap();
        let (local_ca, _) = crate::x509::tests_module::build_ca();
        let (fed_ca, fed_issuer) = crate::x509::tests_module::build_ca();
        let leaf = crate::x509::tests_module::sign_leaf(
            &fed_issuer,
            "spiffe://payments.example/not-in-list",
            std::time::Duration::from_secs(3600),
        );
        let plugin = build_plugin_with_federation(
            &tmp,
            &local_ca,
            &[("payments.example", &fed_ca)],
            serde_json::json!({
                "mode": "allowlist",
                "allowlist": ["spiffe://payments.example/svc/orders"],
            }),
        );
        let metadata = mcpg_plugin_protocol::types::RequestMetadata {
            tls: Some(tls_info_with_chain(vec![leaf])),
            ..Default::default()
        };
        let outcome = resolve(&plugin.inner, &[], &metadata);
        match outcome {
            IdentityResolution::Invalid { reason, .. } => {
                assert!(reason.contains("not in allowlist"), "got: {reason}",);
            }
            other => panic!("expected Invalid (allowlist), got {other:?}"),
        }
    }
}
