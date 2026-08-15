# SPIFFE Workload Identity Resolver — `dev.mcpg.identity.workload`

> class `identity_provider` · `native` · package `mcpg-plugin-identity-workload` · artifact `libmcpg_plugin_identity_workload.so`

Resolves caller identity from SPIFFE Verifiable Identity Documents (SVIDs) —
both X.509-SVID (via the gateway's mTLS handshake) and JWT-SVID (via headers) —
against an operator-supplied SPIFFE trust bundle. Reach for it for
zero-trust workload identity in a SPIRE-managed mesh.

## What it does
- Walks `sources` in priority order: `x509_svid` (validates the TLS peer-cert
  chain against the bundle's X.509 roots, reads the SPIFFE URI from the leaf
  SAN), `jwt_svid_bearer` (JWT-SVID from `Authorization: Bearer`), and
  `jwt_svid_header` (JWT-SVID from a custom header).
- Enforces the configured `trust_domain` on the SVID's authority; v0.5 adds
  `federated_trust_domains`. `mode: allowlist` restricts to listed SPIFFE IDs.
- Optional `audiences` allowlist for the JWT-SVID `aud` claim.
- Bundle sources: `file` (poll + hot-reload on change) or `workload_api` (live
  gRPC stream from the SPIRE agent's Unix socket, auto-swaps on rotation).
- Stamps `spiffe.*` attributes + per-SPIFFE-ID metadata onto the resolved
  identity. Requires capabilities `transport_listen` + `network_outbound`
  (consumed only when the matching source/bundle kind is used).

## Configuration
Part of the identity chain, loaded via the top-level `plugins:` list:

```yaml
plugins:
  - id: dev.mcpg.identity.workload
    class: identity_provider
    source: { path: ./plugins/libmcpg_plugin_identity_workload.so }
    config:
      trust_domain: example.org
      bundle:
        kind: file                     # "file" | "workload_api"
        file_path: /etc/mcpg/spiffe-bundle.json
        # kind: workload_api → socket_path: unix:/run/spire/sockets/agent.sock
      sources:
        - { kind: x509_svid }
        - { kind: jwt_svid_bearer }
        - { kind: jwt_svid_header, header: X-Forwarded-Authorization }
      audiences: ["https://gateway.example.org"]
      mode: trust                      # "trust" | "allowlist"
      # allowlist: ["spiffe://example.org/ns/payments/sa/orders"]
      identities:
        "spiffe://example.org/ns/payments/sa/orders":
          roles: ["service"]
          scopes: ["orders.*"]
      resolution:
        trust_level: verified          # "verified" | "header_asserted"
        auth_provider_label: spiffe-workload
      reload:
        enabled: true
        check_interval_sec: 60
```

| Field | Type | Default | Description |
|---|---|---|---|
| `trust_domain` | string | — | Local SPIFFE trust domain. Required. |
| `bundle` | object | — | `file { file_path }` or `workload_api { socket_path }`. |
| `federated_trust_domains` | object[] | `[]` | Foreign domains `{ trust_domain, bundle }` (file-only in v0.5). |
| `sources` | source[] | — | SVID sources in priority order; non-empty, no dup kinds. |
| `mode` | enum | `trust` | `trust` (any valid SVID) or `allowlist`. |
| `allowlist` | string[] | `[]` | Required when `mode: allowlist`; SPIFFE IDs under an accepted domain. |
| `audiences` | string[] | `[]` | JWT-SVID `aud` allowlist; empty skips aud check. |
| `identities` | map | `{}` | Per-SPIFFE-ID roles/groups/scopes/attributes. |
| `resolution.trust_level` | string | `"verified"` | Trust level (`verified` / `header_asserted`). |
| `resolution.auth_provider_label` | string | `"spiffe-workload"` | `auth_provider` on the resolved identity. |
| `reload.enabled` | bool | `false` | Poll the file bundle and hot-swap (file mode). |
| `reload.check_interval_sec` | u64 | `60` | Poll interval when reload enabled. |

Source kinds: `x509_svid`, `jwt_svid_bearer`, `jwt_svid_header { header }`.
Unknown config fields are rejected; invalid config fails the plugin to load.

## Build
```bash
cargo build -p mcpg-plugin-identity-workload --features cdylib-export --release   # → target/release/libmcpg_plugin_identity_workload.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
