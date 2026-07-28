//! Shared AWS credential resolution + CLI JSON for live tools.

use oscar_core::Cloud;
use oscar_identity::{
    auth_request_from_error, resolve_aws_process_creds, BinaryInventory, Profile,
};
use oscar_tools::sync::run_json_command_with_env;

pub async fn aws_json(
    profile: &Profile,
    args: &[&str],
) -> Result<serde_json::Value, oscar_tools::ToolResult> {
    let binaries = BinaryInventory::detect();
    if !binaries.has_aws() {
        return Err(oscar_tools::ToolResult::needs_auth(
            oscar_identity::auth_aws_missing_binary(profile),
        ));
    }
    let creds = resolve_aws_process_creds(profile, &binaries).map_err(|a| {
        oscar_tools::ToolResult::needs_auth(a)
    })?;
    let env: Vec<(String, String)> = creds.env.into_iter().collect();
    match run_json_command_with_env("aws", args, &env).await {
        Ok(v) => Ok(v),
        Err(e) => {
            let text = e.to_string();
            if let Some(auth) = auth_request_from_error(Cloud::Aws, Some(&profile.id), &text) {
                Err(oscar_tools::ToolResult::needs_auth(auth))
            } else {
                Err(oscar_tools::ToolResult::error(text))
            }
        }
    }
}

/// Non-JSON AWS CLI (some IAM ops return empty / text).
pub async fn aws_cli(
    profile: &Profile,
    args: &[&str],
) -> Result<String, oscar_tools::ToolResult> {
    let binaries = BinaryInventory::detect();
    if !binaries.has_aws() {
        return Err(oscar_tools::ToolResult::needs_auth(
            oscar_identity::auth_aws_missing_binary(profile),
        ));
    }
    let creds = resolve_aws_process_creds(profile, &binaries)
        .map_err(oscar_tools::ToolResult::needs_auth)?;
    let mut cmd = tokio::process::Command::new("aws");
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in &creds.env {
        cmd.env(k, v);
    }
    if creds.env.contains_key("AWS_ACCESS_KEY_ID") {
        cmd.env_remove("AWS_PROFILE");
        cmd.env_remove("AWS_DEFAULT_PROFILE");
    }
    let output = cmd.output().await.map_err(|e| {
        oscar_tools::ToolResult::error(format!("failed to spawn aws: {e}"))
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        let text = format!("{} {}", stderr.trim(), stdout.trim());
        if let Some(auth) = auth_request_from_error(Cloud::Aws, Some(&profile.id), &text) {
            return Err(oscar_tools::ToolResult::needs_auth(auth));
        }
        return Err(oscar_tools::ToolResult::error(text));
    }
    Ok(stdout)
}

pub fn first_aws_profile<'a>(
    profiles: &'a oscar_identity::ProfileStore,
    profile_id: Option<&str>,
) -> Result<&'a Profile, oscar_tools::ToolResult> {
    first_aws_profile_pref(profiles, profile_id, None)
}

pub fn first_aws_profile_pref<'a>(
    profiles: &'a oscar_identity::ProfileStore,
    profile_id: Option<&str>,
    preferred_profile_id: Option<&str>,
) -> Result<&'a Profile, oscar_tools::ToolResult> {
    if let Some(id) = profile_id {
        return profiles.get(id).ok_or_else(|| {
            oscar_tools::ToolResult::needs_auth(
                oscar_tools::auth_for(Cloud::Aws, format!("Unknown profile `{id}`")).profile(id),
            )
        });
    }
    if let Some(id) = preferred_profile_id {
        if let Some(p) = profiles.get(id) {
            if p.cloud == Cloud::Aws {
                return Ok(p);
            }
        }
    }
    let aws: Vec<_> = profiles
        .list()
        .iter()
        .filter(|p| p.cloud == Cloud::Aws)
        .collect();
    match aws.as_slice() {
        [] => Err(oscar_tools::ToolResult::needs_auth(oscar_tools::auth_for(
            Cloud::Aws,
            "No AWS profile configured — call system.access.prepare with cloud=aws (+ account/label), or `oscar profiles add`",
        ))),
        [only] => Ok(*only),
        many => {
            let ids: Vec<_> = many.iter().map(|p| p.id.as_str()).collect();
            Err(oscar_tools::ToolResult::error(format!(
                "Multiple AWS profiles {} — refuse silent default. \
                 If the user named an account/label, system.access.review then system.access.prepare (if missing) / system.access.select, \
                 then re-call with profile_id. Do not use another profile as a substitute.",
                ids.join(", ")
            )))
        }
    }
}

/// Resolve AWS profile for live tools; falls back to ambient binary session shell.
pub fn resolve_aws_profile(
    profiles: &oscar_identity::ProfileStore,
    profile_id: Option<&str>,
) -> Result<Profile, oscar_tools::ToolResult> {
    resolve_aws_profile_pref(profiles, profile_id, None)
}

pub fn resolve_aws_profile_pref(
    profiles: &oscar_identity::ProfileStore,
    profile_id: Option<&str>,
    preferred_profile_id: Option<&str>,
) -> Result<Profile, oscar_tools::ToolResult> {
    match first_aws_profile_pref(profiles, profile_id, preferred_profile_id) {
        Ok(p) => Ok(p.clone()),
        Err(e) if profile_id.is_some() => Err(e),
        Err(e) => {
            // Only ambient-fallback when there are *zero* AWS profiles configured.
            // Multi-profile ambiguity / auth errors must surface to the agent.
            let aws_n = profiles
                .list()
                .iter()
                .filter(|p| p.cloud == Cloud::Aws)
                .count();
            if aws_n == 0 {
                Ok(Profile::new(Cloud::Aws, "ambient", "ambient"))
            } else {
                Err(e)
            }
        }
    }
}

/// Prefer session pivot profile when tools omit `profile_id`.
pub fn resolve_aws_profile_ctx(
    ctx: &oscar_tools::ToolContext,
    profile_id: Option<&str>,
) -> Result<Profile, oscar_tools::ToolResult> {
    resolve_aws_profile_pref(
        &ctx.profiles,
        profile_id,
        ctx.preferred_profile_id.as_deref(),
    )
}

pub fn first_aws_profile_ctx<'a>(
    ctx: &'a oscar_tools::ToolContext,
    profile_id: Option<&str>,
) -> Result<&'a Profile, oscar_tools::ToolResult> {
    first_aws_profile_pref(
        &ctx.profiles,
        profile_id,
        ctx.preferred_profile_id.as_deref(),
    )
}

pub fn arg_str<'a>(args: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

pub fn require_str(args: &serde_json::Value, key: &str) -> Result<String, oscar_tools::ToolResult> {
    arg_str(args, key)
        .map(|s| s.to_string())
        .ok_or_else(|| oscar_tools::ToolResult::error(format!("missing required argument `{key}`")))
}

