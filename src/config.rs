//! Operator-supplied configuration schema for `dev.mcpg.identity.workload`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    /// Local SPIFFE trust domain — the authority component of
    /// SVIDs the gateway issues / consumes natively. Foreign
    /// trust domains are configured under
    /// `federated_trust_domains` (v0.5+).
    pub trust_domain: String,

    /// Trust bundle source for the *local* trust domain.
    pub bundle: BundleConfig,

    /// Federated trust domains the plugin also accepts SVIDs
    /// from (v0.5). Each entry pins a foreign trust domain to
    /// its own bundle source — at resolve time the plugin
    /// extracts the SVID's trust domain, looks it up here (or
    /// matches `trust_domain` for the local case), and verifies
    /// against that bundle.
    ///
    /// Per-domain authorisation: a federated SVID still walks
    /// the global `mode: allowlist` + `identities` map; the
    /// allowlist's domain check is relaxed to allow any
    /// configured federated domain. Per-domain authorisation
    /// rules (e.g. "team-payments may invoke READ but not
    /// WRITE") compose at the policy layer, not at the
    /// identity-plugin layer.
    ///
    /// Empty (the default) preserves v0.4 behaviour: only the
    /// local `trust_domain` is accepted.
    #[serde(default)]
    pub federated_trust_domains: Vec<FederatedDomain>,

    /// SVID source list. Walked in priority order.
    pub sources: Vec<JwtSvidSource>,

    /// Operating mode.
    #[serde(default)]
    pub mode: Mode,

    /// Required when `mode: allowlist`. Each entry must be a
    /// SPIFFE ID under the configured trust domain.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Per-SPIFFE-ID metadata.
    #[serde(default)]
    pub identities: BTreeMap<String, IdentityMetadata>,

    /// Audiences accepted in the JWT-SVID `aud` claim. When
    /// non-empty, the validator REQUIRES the token's `aud` to
    /// contain at least one of these strings (jsonwebtoken's
    /// default semantics for `set_audience`).
    ///
    /// Operators MUST set this to the gateway's stable audience
    /// identifier (typically a URL or service name). SPIFFE clients
    /// in production mint per-audience JWT-SVIDs via the SPIRE
    /// Workload API; an unconfigured audience turns the resolver
    /// into an "any SPIFFE ID under our trust domain" surface and
    /// accepts a JWT-SVID minted for a *different* relying party
    /// under the same trust domain (token confusion / cross-service
    /// replay). Leaving this empty is therefore a hard config error
    /// unless `allow_any_audience: true` is set explicitly, mirroring
    /// the OIDC plugin.
    #[serde(default)]
    pub audiences: Vec<String>,

    /// Escape hatch for the rare deployment whose SPIRE issues
    /// audience-less JWT-SVIDs: opt out of `aud` validation. Default
    /// `false` — an empty `audiences` with this unset is rejected at
    /// boot rather than silently skipping the check.
    #[serde(default)]
    pub allow_any_audience: bool,

    #[serde(default)]
    pub resolution: ResolutionConfig,

    /// Optional bundle hot-reload watcher. Default disabled
    /// (operator restarts to pick up SPIRE bundle rotations).
    /// SPIRE rotates ~hourly in production; enable this to track
    /// rotations without restarting.
    #[serde(default)]
    pub reload: ReloadConfig,
}

/// A federated foreign trust domain. The plugin accepts SVIDs
/// whose authority component matches `trust_domain`, validating
/// against the configured `bundle`.
///
/// Bundle source mode is the same shape as the local bundle
/// (`file` for SPIFFE Trust Domain Bundle JSON on disk,
/// `workload_api` for live gRPC stream from a SPIRE agent that
/// holds federated bundles). HTTPS bundle-endpoint fetch
/// (the SPIFFE federation transport spec) is a v0.6 deferral.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedDomain {
    /// Foreign trust domain — e.g. `payments.example.org`.
    pub trust_domain: String,
    /// Bundle source for this foreign domain.
    pub bundle: BundleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReloadConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_check_interval_sec")]
    pub check_interval_sec: u64,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_sec: default_check_interval_sec(),
        }
    }
}

fn default_check_interval_sec() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleConfig {
    /// Operator-managed bundle file. Plugin polls mtime + sha256
    /// for hot-reload on change.
    File { file_path: String },
    /// SPIRE Workload API client. Plugin connects to the agent's
    /// Unix socket via gRPC, fetches the trust bundle stream, and
    /// hot-swaps locally on every push from the agent. Requires the
    /// `network_outbound` capability — operators must
    /// explicitly authorise the gateway to make Unix-socket
    /// connections.
    WorkloadApi {
        /// Workload API endpoint string. Accepts `unix:` /
        /// `unix://` prefixes for Unix-socket addresses or `tcp:`
        /// for in-network agents (uncommon — most SPIRE deploys
        /// expose the agent over a Unix socket only). Examples:
        ///
        /// - `unix:/run/spire/sockets/agent.sock` (RFC 6335 form,
        ///   single colon)
        /// - `unix:///run/spire/sockets/agent.sock` (URI form,
        ///   triple slash)
        socket_path: String,
    },
}

impl BundleConfig {
    /// File path for the `File` variant; `None` for other
    /// variants. Used by the file-watcher reload path; the
    /// Workload API path drives reloads off its gRPC stream
    /// directly and ignores this.
    pub fn file_path(&self) -> Option<&str> {
        match self {
            Self::File { file_path } => Some(file_path),
            Self::WorkloadApi { .. } => None,
        }
    }

    pub fn workload_api_socket(&self) -> Option<&str> {
        match self {
            Self::WorkloadApi { socket_path } => Some(socket_path),
            Self::File { .. } => None,
        }
    }
}

/// Single SVID source. Renamed from `JwtSvidSource` once the
/// `X509Svid` variant landed — the same struct now covers both
/// JWT and X.509 sources via the `kind` discriminant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvidSource {
    pub kind: SourceKind,
    /// Required for `JwtSvidHeader`; ignored otherwise.
    #[serde(default)]
    pub header: Option<String>,
}

/// Backwards-compatible alias for the old name. Kept so external
/// consumers (none in-tree, but the struct is `pub use`'d from
/// the crate root) don't break on rename.
pub type JwtSvidSource = SvidSource;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Validate an X.509-SVID presented during the TLS handshake.
    /// Reads `metadata.tls.client_cert_chain_der` (populated by
    /// the gateway when mTLS terminates at the gateway), validates
    /// the chain against the trust bundle's X.509 trust roots, and
    /// extracts the SPIFFE URI from the leaf cert's
    /// SubjectAltName.
    ///
    /// Requires the gateway-side `transport_listen` capability
    /// (the plugin's manifest declares it dynamically when at
    /// least one source is `X509Svid`).
    X509Svid,
    /// Read JWT-SVID from `Authorization: Bearer <jwt>`.
    JwtSvidBearer,
    /// Read JWT-SVID from a custom header (e.g. envoy's
    /// `X-Forwarded-Authorization`).
    JwtSvidHeader,
}

impl SourceKind {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::X509Svid => "x509_svid",
            Self::JwtSvidBearer => "jwt_svid_bearer",
            Self::JwtSvidHeader => "jwt_svid_header",
        }
    }

    /// True for sources that consume the TLS handshake's peer
    /// cert chain. Drives the dynamic capability declaration
    /// (`transport_listen`).
    pub fn needs_tls_metadata(&self) -> bool {
        matches!(self, Self::X509Svid)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Any verified SVID with the matching trust domain.
    #[default]
    Trust,
    /// Only allowlisted SPIFFE IDs.
    Allowlist,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMetadata {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

fn default_trust_level() -> String {
    "verified".into()
}

fn default_auth_provider_label() -> String {
    "spiffe-workload".into()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid identity.workload config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("identity.workload: trust_domain is empty")]
    EmptyTrustDomain,
    #[error("identity.workload: sources must be non-empty")]
    EmptySources,
    #[error("identity.workload: source[{index}] (jwt_svid_header) requires a non-empty `header`")]
    HeaderSourceMissingHeaderField { index: usize },
    #[error(
        "identity.workload: duplicate source kind `{kind}` — each non-header source \
         kind may appear at most once (header sources are distinct by `header`)"
    )]
    DuplicateSourceKind { kind: &'static str },
    #[error(
        "identity.workload: duplicate jwt_svid_header source for header `{header}` \
         (case-insensitive); each header may be configured at most once"
    )]
    DuplicateHeaderSource { header: String },
    #[error("identity.workload: mode=allowlist requires non-empty `allowlist` list")]
    EmptyAllowlist,
    #[error(
        "identity.workload: allowlist entry `{entry}` is not a SPIFFE ID under \
         trust domain `{trust_domain}`"
    )]
    AllowlistEntryWrongDomain { entry: String, trust_domain: String },
    #[error(
        "identity.workload: invalid trust_level `{value}` \
         (allowed: verified | header_asserted)"
    )]
    InvalidTrustLevel { value: String },
    #[error(
        "identity.workload: audiences[{index}] is empty or whitespace; \
         remove the entry or set it to a real audience identifier"
    )]
    EmptyAudienceEntry { index: usize },
    #[error(
        "identity.workload: audiences is empty — refusing to skip JWT-SVID `aud` \
         validation (a JWT-SVID minted for another relying party under the same \
         trust domain would be accepted). Set `audiences`, or for SPIRE setups \
         that issue audience-less SVIDs opt in explicitly with \
         `allow_any_audience: true`"
    )]
    EmptyAudiencesRequireOptIn,
    #[error("identity.workload: bundle.file_path must not be empty")]
    EmptyBundleFilePath,
    #[error(
        "identity.workload: bundle.socket_path must not be empty when bundle.kind \
         is `workload_api`"
    )]
    EmptyWorkloadApiSocketPath,
    #[error(
        "identity.workload: bundle.socket_path `{socket_path}` is not a recognised \
         endpoint — supported forms are `unix:/path/to/sock` (or `unix:///path`) \
         and `tcp:host:port`"
    )]
    InvalidWorkloadApiSocketPath { socket_path: String },
    #[error("identity.workload: federated_trust_domains entry has an empty trust_domain")]
    EmptyFederatedTrustDomain,
    #[error(
        "identity.workload: federated_trust_domains contains duplicate entry \
         `{trust_domain}` (also matches the local trust_domain when listed there)"
    )]
    DuplicateFederatedTrustDomain { trust_domain: String },
    #[error(
        "identity.workload: federated_trust_domains[`{trust_domain}`].bundle is \
         invalid: {detail}"
    )]
    FederatedBundleInvalid {
        trust_domain: String,
        detail: String,
    },
}

/// Shared bundle-config validator used by both the local and
/// federated paths. Returns the same `ConfigError` variants the
/// federation path then re-wraps so error messages name *which*
/// bundle is misconfigured.
fn validate_bundle_config(bundle: &BundleConfig) -> Result<(), ConfigError> {
    match bundle {
        BundleConfig::File { file_path } => {
            if file_path.trim().is_empty() {
                return Err(ConfigError::EmptyBundleFilePath);
            }
        }
        BundleConfig::WorkloadApi { socket_path } => {
            let trimmed = socket_path.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::EmptyWorkloadApiSocketPath);
            }
            let lower = trimmed.to_ascii_lowercase();
            let recognised = lower.starts_with("unix:") || lower.starts_with("tcp:");
            if !recognised {
                return Err(ConfigError::InvalidWorkloadApiSocketPath {
                    socket_path: socket_path.clone(),
                });
            }
        }
    }
    Ok(())
}

impl WorkloadConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.trust_domain.trim().is_empty() {
            return Err(ConfigError::EmptyTrustDomain);
        }
        validate_bundle_config(&self.bundle)?;
        // Federation: each entry's trust domain must be non-empty,
        // distinct from the local + every other federated domain
        // (no duplicates). Bundle source per entry walks the same
        // validator the local bundle uses.
        let mut seen_domains: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        seen_domains.insert(self.trust_domain.trim().to_owned());
        for fed in &self.federated_trust_domains {
            let fed_td = fed.trust_domain.trim().to_owned();
            if fed_td.is_empty() {
                return Err(ConfigError::EmptyFederatedTrustDomain);
            }
            if !seen_domains.insert(fed_td.clone()) {
                return Err(ConfigError::DuplicateFederatedTrustDomain {
                    trust_domain: fed_td,
                });
            }
            // v0.5 federation supports `bundle.kind: file` only.
            // Workload-API and HTTPS-bundle-endpoint sources for
            // federated bundles are tracked as v0.6 follow-ups
            // (one extra stream per federated entry isn't free
            // and the operator-config + reload story for them
            // wants more design).
            if !matches!(fed.bundle, BundleConfig::File { .. }) {
                return Err(ConfigError::FederatedBundleInvalid {
                    trust_domain: fed_td.clone(),
                    detail: "v0.5 federation supports `bundle.kind: file` only \
                             (workload_api / https endpoint per federated \
                             domain are v0.6)"
                        .into(),
                });
            }
            validate_bundle_config(&fed.bundle).map_err(|e| match e {
                ConfigError::EmptyBundleFilePath => ConfigError::FederatedBundleInvalid {
                    trust_domain: fed_td.clone(),
                    detail: "bundle.file_path is empty".into(),
                },
                other => other,
            })?;
        }
        if self.sources.is_empty() {
            return Err(ConfigError::EmptySources);
        }
        // Same source kind twice is meaningless
        // (there's no per-source state to vary it) — reject at
        // boot rather than silently coalescing. Header sources
        // *with different headers* are still distinct entries
        // because their `header` field differentiates them.
        let mut seen_plain_kinds = std::collections::BTreeSet::new();
        let mut seen_headers = std::collections::BTreeSet::new();
        for (index, source) in self.sources.iter().enumerate() {
            match source.kind {
                SourceKind::JwtSvidHeader => {
                    let h = source.header.as_deref().unwrap_or("");
                    if h.trim().is_empty() {
                        return Err(ConfigError::HeaderSourceMissingHeaderField { index });
                    }
                    let normalised = h.trim().to_ascii_lowercase();
                    if !seen_headers.insert(normalised.clone()) {
                        return Err(ConfigError::DuplicateHeaderSource { header: normalised });
                    }
                }
                kind => {
                    if !seen_plain_kinds.insert(kind) {
                        return Err(ConfigError::DuplicateSourceKind { kind: kind.tag() });
                    }
                }
            }
        }
        match self.resolution.trust_level.as_str() {
            "verified" | "header_asserted" => {}
            other => {
                return Err(ConfigError::InvalidTrustLevel {
                    value: other.into(),
                });
            }
        }
        if matches!(self.mode, Mode::Allowlist) {
            if self.allowlist.is_empty() {
                return Err(ConfigError::EmptyAllowlist);
            }
            // v0.5: allowlist entries may belong to the local
            // trust domain OR any configured federated domain.
            // The check enforces "the entry's authority must
            // match SOME accepted domain" — typo-catching
            // without locking allowlists to the local domain
            // only.
            let mut accepted_prefixes: Vec<String> =
                Vec::with_capacity(1 + self.federated_trust_domains.len());
            accepted_prefixes.push(format!("spiffe://{}/", self.trust_domain));
            for fed in &self.federated_trust_domains {
                accepted_prefixes.push(format!("spiffe://{}/", fed.trust_domain.trim()));
            }
            for entry in &self.allowlist {
                let matched = accepted_prefixes.iter().any(|p| entry.starts_with(p));
                if !matched {
                    return Err(ConfigError::AllowlistEntryWrongDomain {
                        entry: entry.clone(),
                        trust_domain: self.trust_domain.clone(),
                    });
                }
            }
        }
        for (index, aud) in self.audiences.iter().enumerate() {
            if aud.trim().is_empty() {
                return Err(ConfigError::EmptyAudienceEntry { index });
            }
        }
        // Empty audiences disables `aud` validation, which accepts a
        // JWT-SVID minted for any relying party under the trust domain.
        // Require an explicit opt-out, mirroring the OIDC plugin.
        if self.audiences.is_empty() && !self.allow_any_audience {
            return Err(ConfigError::EmptyAudiencesRequireOptIn);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> serde_json::Value {
        // `allow_any_audience` keeps these fixtures (which don't exercise
        // audience binding) parseable now that an empty `audiences` is a
        // hard error without the explicit opt-in.
        json!({
            "trust_domain": "example.org",
            "bundle": { "kind": "file", "file_path": "/tmp/x" },
            "sources": [{ "kind": "jwt_svid_bearer" }],
            "allow_any_audience": true
        })
    }

    #[test]
    fn parses_minimal() {
        WorkloadConfig::parse(&minimal().to_string()).unwrap();
    }

    #[test]
    fn rejects_empty_trust_domain() {
        let mut cfg = minimal();
        cfg["trust_domain"] = json!("");
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::EmptyTrustDomain);
    }

    #[test]
    fn rejects_empty_sources() {
        let mut cfg = minimal();
        cfg["sources"] = json!([]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::EmptySources);
    }

    #[test]
    fn header_source_requires_header() {
        let mut cfg = minimal();
        cfg["sources"] = json!([{ "kind": "jwt_svid_header" }]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::HeaderSourceMissingHeaderField { .. });
    }

    #[test]
    fn allowlist_mode_requires_entries() {
        let mut cfg = minimal();
        cfg["mode"] = json!("allowlist");
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::EmptyAllowlist);
    }

    #[test]
    fn allowlist_entries_must_match_trust_domain() {
        let mut cfg = minimal();
        cfg["mode"] = json!("allowlist");
        cfg["allowlist"] = json!(["spiffe://other-domain.org/x"]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::AllowlistEntryWrongDomain { .. });
    }

    #[test]
    fn empty_audiences_requires_explicit_opt_in() {
        // Without `allow_any_audience`, an empty `audiences` is rejected
        // at parse — refusing to silently skip `aud` validation.
        let mut cfg = minimal();
        cfg.as_object_mut().unwrap().remove("allow_any_audience");
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::EmptyAudiencesRequireOptIn);

        // With the explicit opt-in, an empty `audiences` parses and
        // disables the `aud` check.
        let parsed = WorkloadConfig::parse(&minimal().to_string()).unwrap();
        assert!(parsed.audiences.is_empty());
        assert!(parsed.allow_any_audience);
    }

    #[test]
    fn audiences_accepts_well_formed() {
        let mut cfg = minimal();
        cfg["audiences"] = json!(["mcpg-gateway", "https://gw.acme.example/"]);
        let parsed = WorkloadConfig::parse(&cfg.to_string()).unwrap();
        assert_eq!(parsed.audiences.len(), 2);
        assert_eq!(parsed.audiences[0], "mcpg-gateway");
    }

    #[test]
    fn audiences_rejects_empty_entry() {
        let mut cfg = minimal();
        cfg["audiences"] = json!(["mcpg-gateway", ""]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::EmptyAudienceEntry { index: 1 });
    }

    #[test]
    fn audiences_rejects_whitespace_entry() {
        let mut cfg = minimal();
        cfg["audiences"] = json!(["mcpg-gateway", "   "]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        matches!(err, ConfigError::EmptyAudienceEntry { index: 1 });
    }

    #[test]
    fn x509_source_kind_parses() {
        let mut cfg = minimal();
        cfg["sources"] = json!([{ "kind": "x509_svid" }]);
        let parsed = WorkloadConfig::parse(&cfg.to_string()).unwrap();
        assert_eq!(parsed.sources.len(), 1);
        assert!(matches!(parsed.sources[0].kind, SourceKind::X509Svid));
        assert!(parsed.sources[0].kind.needs_tls_metadata());
    }

    #[test]
    fn duplicate_x509_source_rejected() {
        let mut cfg = minimal();
        cfg["sources"] = json!([
            { "kind": "x509_svid" },
            { "kind": "x509_svid" },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::DuplicateSourceKind { kind } => assert_eq!(kind, "x509_svid"),
            other => panic!("expected DuplicateSourceKind, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_jwt_bearer_source_rejected() {
        let mut cfg = minimal();
        cfg["sources"] = json!([
            { "kind": "jwt_svid_bearer" },
            { "kind": "jwt_svid_bearer" },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::DuplicateSourceKind { kind } => {
                assert_eq!(kind, "jwt_svid_bearer");
            }
            other => panic!("expected DuplicateSourceKind, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_jwt_header_with_same_header_rejected() {
        let mut cfg = minimal();
        cfg["sources"] = json!([
            { "kind": "jwt_svid_header", "header": "X-Forwarded-Authorization" },
            { "kind": "jwt_svid_header", "header": "x-forwarded-authorization" },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::DuplicateHeaderSource { header } => {
                // Comparison is case-insensitive — both entries
                // collapse to the lowercased canonical form.
                assert_eq!(header, "x-forwarded-authorization");
            }
            other => panic!("expected DuplicateHeaderSource, got {other:?}"),
        }
    }

    #[test]
    fn distinct_jwt_headers_allowed() {
        let mut cfg = minimal();
        cfg["sources"] = json!([
            { "kind": "jwt_svid_header", "header": "X-Forwarded-Authorization" },
            { "kind": "jwt_svid_header", "header": "X-SVID-JWT" },
        ]);
        let parsed = WorkloadConfig::parse(&cfg.to_string()).unwrap();
        assert_eq!(parsed.sources.len(), 2);
    }

    #[test]
    fn mixed_x509_and_jwt_sources_allowed() {
        let mut cfg = minimal();
        cfg["sources"] = json!([
            { "kind": "x509_svid" },
            { "kind": "jwt_svid_bearer" },
            { "kind": "jwt_svid_header", "header": "X-Forwarded-Authorization" },
        ]);
        let parsed = WorkloadConfig::parse(&cfg.to_string()).unwrap();
        assert_eq!(parsed.sources.len(), 3);
    }

    #[test]
    fn workload_api_bundle_kind_parses() {
        let mut cfg = minimal();
        cfg["bundle"] = json!({
            "kind": "workload_api",
            "socket_path": "unix:/run/spire/sockets/agent.sock",
        });
        let parsed = WorkloadConfig::parse(&cfg.to_string()).unwrap();
        assert!(matches!(parsed.bundle, BundleConfig::WorkloadApi { .. }));
        assert_eq!(
            parsed.bundle.workload_api_socket(),
            Some("unix:/run/spire/sockets/agent.sock")
        );
        assert_eq!(parsed.bundle.file_path(), None);
    }

    #[test]
    fn workload_api_socket_path_uri_form_accepted() {
        let mut cfg = minimal();
        cfg["bundle"] = json!({
            "kind": "workload_api",
            "socket_path": "unix:///var/run/spire/agent.sock",
        });
        WorkloadConfig::parse(&cfg.to_string()).unwrap();
    }

    #[test]
    fn workload_api_socket_path_tcp_form_accepted() {
        let mut cfg = minimal();
        cfg["bundle"] = json!({
            "kind": "workload_api",
            "socket_path": "tcp:127.0.0.1:8081",
        });
        WorkloadConfig::parse(&cfg.to_string()).unwrap();
    }

    #[test]
    fn workload_api_socket_path_must_not_be_empty() {
        let mut cfg = minimal();
        cfg["bundle"] = json!({
            "kind": "workload_api",
            "socket_path": "  ",
        });
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyWorkloadApiSocketPath));
    }

    #[test]
    fn workload_api_socket_path_must_be_recognised_endpoint() {
        let mut cfg = minimal();
        cfg["bundle"] = json!({
            "kind": "workload_api",
            "socket_path": "/run/spire/sockets/agent.sock",
        });
        // Bare path (no `unix:` prefix) is rejected.
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::InvalidWorkloadApiSocketPath { socket_path } => {
                assert_eq!(socket_path, "/run/spire/sockets/agent.sock");
            }
            other => panic!("expected InvalidWorkloadApiSocketPath, got {other:?}"),
        }
    }

    #[test]
    fn file_bundle_requires_non_empty_file_path() {
        let mut cfg = minimal();
        cfg["bundle"] = json!({ "kind": "file", "file_path": "  " });
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyBundleFilePath));
    }

    // ---------------------------------------------------------------
    // Federation config validation
    // ---------------------------------------------------------------

    #[test]
    fn federated_trust_domains_default_empty() {
        let cfg = WorkloadConfig::parse(&minimal().to_string()).unwrap();
        assert!(cfg.federated_trust_domains.is_empty());
    }

    #[test]
    fn federated_trust_domains_well_formed_parse() {
        let mut cfg = minimal();
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "payments.example", "bundle": { "kind": "file", "file_path": "/tmp/payments-bundle.json" } },
            { "trust_domain": "fraud.example", "bundle": { "kind": "file", "file_path": "/tmp/fraud-bundle.json" } },
        ]);
        let parsed = WorkloadConfig::parse(&cfg.to_string()).unwrap();
        assert_eq!(parsed.federated_trust_domains.len(), 2);
        assert_eq!(
            parsed.federated_trust_domains[0].trust_domain,
            "payments.example"
        );
    }

    #[test]
    fn federated_trust_domains_reject_empty_domain() {
        let mut cfg = minimal();
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "  ", "bundle": { "kind": "file", "file_path": "/tmp/x" } },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyFederatedTrustDomain));
    }

    #[test]
    fn federated_trust_domains_reject_duplicate_among_themselves() {
        let mut cfg = minimal();
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "payments.example", "bundle": { "kind": "file", "file_path": "/tmp/a" } },
            { "trust_domain": "payments.example", "bundle": { "kind": "file", "file_path": "/tmp/b" } },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::DuplicateFederatedTrustDomain { trust_domain } => {
                assert_eq!(trust_domain, "payments.example");
            }
            other => panic!("expected DuplicateFederatedTrustDomain, got {other:?}"),
        }
    }

    #[test]
    fn federated_trust_domains_reject_duplicate_of_local_domain() {
        // Listing the local trust domain in the federation config
        // is meaningless (the local bundle already covers it) and
        // would force the validator to pick "which bundle wins?".
        // Reject at boot so the operator notices.
        let mut cfg = minimal();
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "example.org", "bundle": { "kind": "file", "file_path": "/tmp/dup" } },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::DuplicateFederatedTrustDomain { trust_domain } => {
                assert_eq!(trust_domain, "example.org");
            }
            other => panic!("expected DuplicateFederatedTrustDomain, got {other:?}"),
        }
    }

    #[test]
    fn federated_trust_domains_reject_workload_api_source_in_v0_5() {
        // v0.5 supports `bundle.kind: file` only for federated
        // entries — workload_api per federated entry is a v0.6
        // follow-up. Make sure the validator rejects with a
        // version-specific error.
        let mut cfg = minimal();
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "payments.example", "bundle": { "kind": "workload_api", "socket_path": "unix:/tmp/sock" } },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::FederatedBundleInvalid {
                trust_domain,
                detail,
            } => {
                assert_eq!(trust_domain, "payments.example");
                assert!(detail.contains("v0.5"), "got detail: {detail}");
            }
            other => panic!("expected FederatedBundleInvalid, got {other:?}"),
        }
    }

    #[test]
    fn federated_trust_domains_reject_empty_file_path() {
        let mut cfg = minimal();
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "payments.example", "bundle": { "kind": "file", "file_path": " " } },
        ]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::FederatedBundleInvalid {
                trust_domain,
                detail,
            } => {
                assert_eq!(trust_domain, "payments.example");
                assert!(detail.contains("file_path"), "got detail: {detail}");
            }
            other => panic!("expected FederatedBundleInvalid, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_accepts_entries_under_federated_trust_domains() {
        // Federation widens the *valid SVID set* — operators can
        // now allowlist SPIFFE IDs that belong to a federated
        // domain, not just the local one. The validator must
        // accept those entries (resolve-time still checks the
        // signature against the federated bundle).
        let mut cfg = minimal();
        cfg["mode"] = json!("allowlist");
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "payments.example", "bundle": { "kind": "file", "file_path": "/tmp/p" } },
        ]);
        cfg["allowlist"] = json!([
            "spiffe://example.org/local/x",
            "spiffe://payments.example/svc/orders",
        ]);
        WorkloadConfig::parse(&cfg.to_string()).unwrap();
    }

    #[test]
    fn allowlist_rejects_entry_under_unconfigured_domain_even_with_federation() {
        let mut cfg = minimal();
        cfg["mode"] = json!("allowlist");
        cfg["federated_trust_domains"] = json!([
            { "trust_domain": "payments.example", "bundle": { "kind": "file", "file_path": "/tmp/p" } },
        ]);
        // `unknown.example` is neither local nor federated — must
        // still fail allowlist validation.
        cfg["allowlist"] = json!(["spiffe://unknown.example/x"]);
        let err = WorkloadConfig::parse(&cfg.to_string()).unwrap_err();
        match err {
            ConfigError::AllowlistEntryWrongDomain { entry, .. } => {
                assert_eq!(entry, "spiffe://unknown.example/x");
            }
            other => panic!("expected AllowlistEntryWrongDomain, got {other:?}"),
        }
    }
}
