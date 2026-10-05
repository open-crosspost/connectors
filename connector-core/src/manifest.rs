//! The connector manifest: what goes in it, and how it rides inside the
//! wasm.
//!
//! The manifest is embedded in a wasm custom section named
//! `outlayer.manifest`, so it is covered by the wasm's SHA256, which the
//! contract records for the version and the worker checks before executing.
//! Nobody — not the platform, not the author after publishing — can change
//! what a published version is allowed to reach without changing its hash,
//! and changing its hash means publishing a new version the user has to
//! move to. A `manifest.json` at the repository root is NOT read; the
//! custom section is the only source, and `build.sh` fails the build when
//! the section is missing so the omission is caught at the author's desk.
//!
//! `capabilities.network` is the outbound allowlist the TEE worker
//! enforces: exact hostnames, case-insensitive, no implicit subdomain
//! wildcard. `example.com` does not permit `evil.example.com`. A connector
//! without the section reaches nothing.

use serde::{Deserialize, Serialize};

/// Embed the manifest at `path` (relative to the crate whose source expands
/// the macro) into the wasm. The `#[used]` keeps the linker from dropping a
/// static nothing references — without it the module would publish with no
/// allowlist and, being a connector, be refused all outbound network.
#[macro_export]
macro_rules! embed_manifest {
    ($path:literal) => {
        #[cfg(target_family = "wasm")]
        #[used]
        #[link_section = "outlayer.manifest"]
        static OUTLAYER_MANIFEST: [u8; include_bytes!($path).len()] = *include_bytes!($path);
    };
}

/// The manifest, as the worker reads it out of the custom section. Kept
/// whole enough to parse a `manifest.json` at build time (`build.sh`
/// validates the words it uses); unknown members are refused by the
/// platform itself, so this struct denies them too.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub connector_id: String,
    #[serde(default)]
    pub display: Option<Display>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    #[serde(default)]
    pub author_secrets: Option<AuthorSecrets>,
    #[serde(default)]
    pub limits: Vec<Limit>,
    #[serde(default)]
    pub encryption_keys: Vec<EncryptionKey>,
    #[serde(default)]
    pub tasks: Option<bool>,
    #[serde(default)]
    pub describe: Option<Describe>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Display {
    pub name: String,
    pub author: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Capabilities {
    /// Exact hostnames; case-insensitive, no implicit subdomain wildcard.
    #[serde(default)]
    pub network: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AuthorSecrets {
    pub profile: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Limit {
    pub operation: String,
    pub window: String,
    pub max_count: u32,
    #[serde(default = "default_applies")]
    pub applies: String,
}

fn default_applies() -> String {
    "everyone".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EncryptionKey {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Describe {
    pub summary: String,
    #[serde(default)]
    pub operations: serde_json::Map<String, serde_json::Value>,
}

/// The windows and applies-sets the coordinator knows. A word it does not
/// know is read at its STRICTEST, which binds more callers than the author
/// meant and is noticed only when somebody is refused — so the vocabulary is
/// validated at build time.
pub const WINDOWS: &[&str] = &["day", "week", "month"];
pub const APPLIES: &[&str] = &["everyone", "unpaid", "covered"];

/// Is `host` allowed by the allowlist? Exact match, case-insensitive: no
/// subdomain is ever implied, a port is part of nothing here (hosts carry
/// none), and `["any"]` is not a word.
pub fn host_allowed(host: &str, allowlist: &[String]) -> bool {
    let host = host.trim().to_ascii_lowercase();
    allowlist.iter().any(|allowed| allowed.trim().eq_ignore_ascii_case(&host))
}

/// Everything wrong with the manifest's words, for `build.sh` to refuse the
/// build on. `operations_served` are the names the code dispatches on — the
/// manifest, the code and the README must agree, because an operation the
/// code serves but the manifest omits is undeclared surface, and one the
/// manifest declares and the code does not serve answers every caller with
/// a refusal that reads like a platform fault.
pub fn validate(manifest: &Manifest, operations_served: &[&str]) -> Vec<String> {
    let mut bad = Vec::new();
    if manifest.connector_id.trim().is_empty() {
        bad.push("connector_id is missing".into());
    }
    let served: std::collections::BTreeSet<&str> = operations_served.iter().copied().collect();
    let declared: std::collections::BTreeSet<&str> = manifest.operations.iter().map(String::as_str).collect();
    if declared != served {
        bad.push(format!(
            "operations {declared:?} do not match the dispatched set {served:?}"
        ));
    }
    if let Some(network) = &manifest.capabilities {
        if network.network.is_empty() {
            bad.push("capabilities.network is empty: a connector reaches nothing".into());
        }
        for host in &network.network {
            let host = host.trim();
            if host.contains('*') || host.starts_with('.') {
                bad.push(format!("network host {host:?}: exact hostnames only, no wildcards"));
            }
        }
    } else {
        bad.push("capabilities.network is missing".into());
    }
    match &manifest.author_secrets {
        Some(a) if !a.profile.trim().is_empty() => {}
        _ => bad.push("author_secrets.profile is missing".into()),
    }
    for limit in &manifest.limits {
        if !WINDOWS.contains(&limit.window.as_str()) {
            bad.push(format!("limit window {:?} (allowed: {WINDOWS:?})", limit.window));
        }
        if !APPLIES.contains(&limit.applies.as_str()) {
            bad.push(format!("limit applies {:?} (allowed: {APPLIES:?})", limit.applies));
        }
        let base = limit.operation.split(':').next().unwrap_or_default();
        if !declared.contains(base) {
            bad.push(format!("limit on unknown operation {:?}", limit.operation));
        }
    }
    if manifest.tasks == Some(true) {
        // A connector that leaves tasks imports the tasks host interface;
        // the build's wasm-tools check confirms the import. Nothing to say
        // about the words here.
    }
    bad
}

/// Parse and validate a manifest the way `build.sh` does, from raw bytes.
pub fn parse_and_validate(bytes: &[u8], operations_served: &[&str]) -> Result<Manifest, String> {
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|e| format!("manifest.json does not parse: {e}"))?;
    let bad = validate(&manifest, operations_served);
    if bad.is_empty() {
        Ok(manifest)
    } else {
        Err(bad.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{
        "connector_id": "test",
        "display": {"name": "Test", "author": "tester.testnet"},
        "operations": ["ping", "do"],
        "capabilities": {"network": ["api.test.com"]},
        "author_secrets": {"profile": "author"},
        "limits": [{"operation": "do", "window": "day", "max_count": 500}]
    }"#;

    fn manifest(json: &str) -> Manifest {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_well_formed_manifest_parses_and_validates() {
        let m = manifest(MINIMAL);
        assert_eq!(m.connector_id, "test");
        assert_eq!(m.limits[0].applies, "everyone", "applies defaults to everyone");
        assert!(validate(&m, &["ping", "do"]).is_empty(), "{:?}", validate(&m, &["ping", "do"]));
        assert!(parse_and_validate(MINIMAL.as_bytes(), &["ping", "do"]).is_ok());
    }

    #[test]
    fn the_operations_must_be_exactly_what_the_code_serves() {
        let m = manifest(MINIMAL);
        let bad = validate(&m, &["ping"]);
        assert!(bad.iter().any(|b| b.contains("do") && b.contains("ping")), "{bad:?}");
        let bad = validate(&m, &["ping", "do", "extra"]);
        assert!(!bad.is_empty(), "a served operation the manifest omits is undeclared surface: {bad:?}");
    }

    #[test]
    fn an_unknown_limit_word_is_a_build_error_not_a_stricter_read() {
        let m = manifest(MINIMAL);
        let mut worse = m.clone();
        worse.limits[0].window = "fortnight".into();
        assert!(validate(&worse, &["ping", "do"])[0].contains("fortnight"));
        worse.limits[0].window = "day".into();
        worse.limits[0].applies = "nobody".into();
        assert!(validate(&worse, &["ping", "do"])[0].contains("applies"));
        worse.limits[0].applies = "everyone".into();
        worse.limits[0].operation = "never".into();
        assert!(validate(&worse, &["ping", "do"])[0].contains("unknown operation"));
    }

    /// The allowlist is exact hostnames. `example.com` does not permit
    /// `evil.example.com`; case and stray spaces do not matter; a port is
    /// never part of a manifest host.
    #[test]
    fn the_allowlist_is_exact_hostnames_and_nothing_else() {
        let allow = vec!["api.twitter.com".to_string(), "API.X.COM".to_string()];
        assert!(host_allowed("api.twitter.com", &allow));
        assert!(host_allowed("  API.X.COM ", &allow));
        for refused in ["evil.example.com", "x.com", "api.twitter.com.evil.com", "", "sub.api.twitter.com"] {
            assert!(!host_allowed(refused, &allow), "`{refused}` must not pass");
        }
    }

    #[test]
    fn a_manifest_word_the_platform_does_not_know_is_refused_here_too() {
        assert!(serde_json::from_str::<Manifest>(r#"{"connector_id":"x","surprise":1}"#).is_err());
    }

    #[test]
    fn a_manifest_without_the_allowlist_or_the_author_profile_is_incomplete() {
        let m = manifest(r#"{"connector_id":"x","operations":[]}"#);
        let bad = validate(&m, &[]);
        assert!(bad.iter().any(|b| b.contains("network")), "{bad:?}");
        assert!(bad.iter().any(|b| b.contains("author_secrets")), "{bad:?}");
    }
}
