//! Secret redaction — guarantee model/agent transcript never retains raw credentials.

use regex::Regex;
use std::sync::OnceLock;

/// Patterns that must never appear in agent-visible text.
fn secret_patterns() -> &'static [Regex] {
    static PATS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)(aws_secret_access_key|secret_access_key|session_token|api[_-]?key|password|client_secret)\s*[=:]\s*\S+").unwrap(),
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            Regex::new(r"\bASIA[0-9A-Z]{16}\b").unwrap(),
            Regex::new(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            Regex::new(r"(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*").unwrap(),
            Regex::new(r#"(?i)("?(?:secret|token|password|apiKey|api_key|accessKey|private_key)"?\s*:\s*")([^"]{8,})(")"#).unwrap(),
            Regex::new(r"(?i)(AWS_SESSION_TOKEN|X-Amz-Security-Token)=([A-Za-z0-9/+=]{20,})").unwrap(),
        ]
    })
}

/// Redact secrets from free text for model/TUI non-secure panes.
pub fn redact_text(input: &str) -> String {
    let mut out = input.to_string();
    for re in secret_patterns() {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                if caps.len() >= 4 {
                    format!("{}***REDACTED***{}", &caps[1], &caps[3])
                } else if caps.len() >= 3 {
                    format!("{}***REDACTED***", &caps[1])
                } else {
                    "***REDACTED***".to_string()
                }
            })
            .into_owned();
    }
    out
}

/// Recursively redact string values in JSON for model-facing tool results.
pub fn redact_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let lk = k.to_ascii_lowercase();
                if lk.contains("secret")
                    || lk.contains("password")
                    || lk.contains("token")
                    || lk.contains("credential")
                    || lk == "key"
                    || lk.ends_with("_key")
                    || lk.contains("private")
                    || lk.contains("authorization")
                {
                    if v.is_string() || v.is_number() {
                        out.insert(k.clone(), serde_json::json!("***REDACTED***"));
                    } else {
                        out.insert(k.clone(), redact_json(v));
                    }
                } else {
                    out.insert(k.clone(), redact_json(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_json).collect())
        }
        serde_json::Value::String(s) => serde_json::Value::String(redact_text(s)),
        other => other.clone(),
    }
}

/// True if text still appears to contain a high-confidence secret (post-redact check).
pub fn looks_like_secret_leak(text: &str) -> bool {
    secret_patterns().iter().any(|re| re.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_akia_and_secret_key_line() {
        let raw = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY AKIAIOSFODNN7EXAMPLE";
        let r = redact_text(raw);
        assert!(!r.contains("wJalrXUtnFEMI"));
        assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(r.contains("REDACTED") || r.contains("***"));
    }

    #[test]
    fn redacts_json_secret_fields() {
        let v = serde_json::json!({
            "ok": true,
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "secretAccessKey": "supersecretvalue12345",
            "nested": { "password": "hunter2hunter2" }
        });
        let r = redact_json(&v);
        assert_eq!(r["secretAccessKey"], "***REDACTED***");
        assert_eq!(r["nested"]["password"], "***REDACTED***");
        let s = r.to_string();
        assert!(!s.contains("supersecretvalue12345"));
    }
}
