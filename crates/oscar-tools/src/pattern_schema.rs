//! Shared JSON schemas and result helpers for pattern-search tools.

use oscar_core::{DiscoveryResult, MatchMode};
use serde_json::{json, Value};

/// Standard properties for pattern search tools (merge into tool input_schema).
pub fn pattern_properties() -> Value {
    json!({
        "pattern": {
            "type": "string",
            "description": "Search pattern: partial name, glob (* ?), IP, IP fragment (10.0.4), or CIDR (10.0.0.0/16). Also accepted as `query`."
        },
        "query": {
            "type": "string",
            "description": "Alias for pattern"
        },
        "mode": {
            "type": "string",
            "enum": ["partial", "prefix", "suffix", "exact", "glob", "ip_or_cidr"],
            "description": "Match mode. Default: inferred (glob if *?, ip_or_cidr if IP/CIDR, else partial)."
        },
        "profile_id": { "type": "string", "description": "Limit to one oscar cloud profile" },
        "region": { "type": "string" },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 500,
            "default": 50,
            "description": "Max hits to return (ranked by score)"
        }
    })
}

pub fn discovery_tool_result(result: DiscoveryResult) -> oscar_tools_result::Ready {
    let summary = if result.hit_count == 0 {
        format!(
            "No matches for pattern `{}` ({}) in {} — tell the user you could not find it (include profile/account if known). \
             If inventory may be empty/stale, suggest inventory.sync then re-search, or verify profile keys target the right account.",
            result.pattern, result.mode, result.query_scope
        )
    } else {
        let top: Vec<String> = result
            .hits
            .iter()
            .take(5)
            .map(|h| format!("{}:{}[{}]", h.kind, h.name, h.matched_field))
            .collect();
        format!(
            "{} hit(s) for `{}` in {} — top: {}",
            result.hit_count,
            result.pattern,
            result.query_scope,
            top.join("; ")
        )
    };
    oscar_tools_result::Ready {
        summary,
        data: serde_json::to_value(&result).unwrap_or(json!({})),
        partial: result.partial,
    }
}

mod oscar_tools_result {
    use serde_json::Value;
    pub struct Ready {
        pub summary: String,
        pub data: Value,
        pub partial: bool,
    }
}

pub use oscar_tools_result::Ready as DiscoveryReady;

pub fn to_tool_result(ready: DiscoveryReady) -> crate::ToolResult {
    let mut r = crate::ToolResult::success(ready.summary, ready.data);
    if ready.partial {
        r.diagnostics.push(oscar_core::Diagnostic {
            code: Some("partial_inventory".into()),
            message: "Inventory incomplete — some accounts/APIs not scanned".into(),
            severity: oscar_core::DiagnosticSeverity::Warning,
        });
    }
    r
}

/// Short description snippet for discovery tools.
pub fn discovery_blurb(resource: &str) -> String {
    format!(
        "High-accuracy pattern discovery for {resource}. Default match is partial (substring); also supports prefix, suffix, exact, glob (*?), and IP/CIDR. Prefer short name fragments over exact FQDNs — returns ranked hits with resource ids for the agent."
    )
}

pub fn default_mode_label(mode: MatchMode) -> &'static str {
    match mode {
        MatchMode::Partial => "partial",
        MatchMode::Prefix => "prefix",
        MatchMode::Suffix => "suffix",
        MatchMode::Exact => "exact",
        MatchMode::Glob => "glob",
        MatchMode::IpOrCidr => "ip_or_cidr",
    }
}
