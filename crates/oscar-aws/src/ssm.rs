//! AWS Systems Manager (SSM) Run Command — agent-friendly remote exec.
//!
//! The agent passes a **plain** shell command string. Oscar base64-encodes it and
//! runs it on the instance via `AWS-RunShellScript` so quoting, newlines, and
//! special characters never break the SSM API payload.

use crate::aws_runtime::{arg_str, aws_json, require_str, resolve_aws_profile_ctx};
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, ToolDomain};
use oscar_tools::{Tool, ToolContext, ToolMeta, ToolResult};
use serde_json::{json, Value};
use std::time::Duration;

pub fn register_ssm(registry: &mut oscar_tools::ToolRegistry) {
    registry.register(std::sync::Arc::new(AwsSsmExec));
    registry.register(std::sync::Arc::new(AwsSsmInstancesList));
}

/// Standard base64 (no_std-friendly, no extra crate).
fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Wrap agent command so SSM receives a single safe shell line.
///
/// Remote side: `echo <b64> | base64 -d | bash -s` (Linux) or PowerShell equivalent.
fn encode_remote_command(command: &str, shell: &str) -> String {
    let b64 = encode_base64(command.as_bytes());
    match shell {
        "powershell" | "pwsh" | "windows" => {
            // PowerShell: decode base64 UTF-8 and invoke
            format!(
                "$b='{b64}'; $bytes=[Convert]::FromBase64String($b); \
                 $cmd=[Text.Encoding]::UTF8.GetString($bytes); \
                 Invoke-Expression $cmd"
            )
        }
        _ => {
            // Linux/macOS SSM agent — base64 -d is standard (GNU/BusyBox)
            format!("echo '{b64}' | base64 -d | /bin/bash -s")
        }
    }
}

fn collect_instance_ids(args: &Value) -> Result<Vec<String>, ToolResult> {
    let mut ids = Vec::new();
    if let Some(one) = arg_str(args, "instance_id") {
        let t = one.trim();
        if !t.is_empty() {
            ids.push(t.to_string());
        }
    }
    if let Some(arr) = args.get("instance_ids").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                let t = s.trim();
                if !t.is_empty() {
                    ids.push(t.to_string());
                }
            }
        }
    }
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err(ToolResult::error(
            "instance_id or instance_ids required (e.g. i-0abc…). Use aws.ssm.instances.list to discover managed instances.",
        ));
    }
    for id in &ids {
        if !id.starts_with("i-") && !id.starts_with("mi-") {
            return Err(ToolResult::error(format!(
                "invalid instance id `{id}` — expected EC2 instance id (i-…) or managed instance (mi-…)"
            )));
        }
    }
    Ok(ids)
}

struct AwsSsmExec;
struct AwsSsmInstancesList;

#[async_trait]
impl Tool for AwsSsmExec {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.ssm.exec".into(),
            name: "Run command on EC2 via SSM".into(),
            description: "Send a shell command to one or more EC2 instances with SSM Run Command \
(AWS-RunShellScript). Pass **plain `command` text only** — oscar base64-encodes and wraps it so \
quotes, pipes, newlines, and special chars need no extra escaping. Polls until done and returns \
stdout/stderr/exit status. Requires SSM agent online + IAM. Write-gated (use readwrite mode). \
Discover targets with aws.ssm.instances.list.".into(),
            domain: ToolDomain::Infra,
            clouds: vec![Cloud::Aws],
            capability: Capability::Write,
            tags: vec![
                "ssm".into(),
                "exec".into(),
                "run".into(),
                "command".into(),
                "shell".into(),
                "node".into(),
                "ec2".into(),
                "instance".into(),
                "remote".into(),
                "troubleshoot".into(),
                "send-command".into(),
                "systems-manager".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Exact shell script/command to run on the instance (no SSM encoding — pass as you would type it)"
                    },
                    "instance_id": {
                        "type": "string",
                        "description": "Single target EC2 instance id (i-…)"
                    },
                    "instance_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Multiple instance ids"
                    },
                    "region": {
                        "type": "string",
                        "description": "AWS region (default: profile region or us-east-1)"
                    },
                    "profile_id": {
                        "type": "string",
                        "description": "Oscar AWS profile (short-lived STS / keys)"
                    },
                    "timeout_sec": {
                        "type": "integer",
                        "default": 60,
                        "description": "Max seconds to wait for command completion (5–600)"
                    },
                    "shell": {
                        "type": "string",
                        "enum": ["bash", "powershell"],
                        "default": "bash",
                        "description": "Remote shell: bash (Linux) or powershell (Windows)"
                    },
                    "comment": {
                        "type": "string",
                        "description": "Optional SSM comment (audit)"
                    },
                    "working_directory": {
                        "type": "string",
                        "description": "Optional remote cwd (AWS-RunShellScript workingDirectory)"
                    }
                },
                "required": ["command"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let command = match require_str(&args, "command") {
            Ok(c) => c,
            Err(e) => return e,
        };
        if command.trim().is_empty() {
            return ToolResult::error("command must not be empty");
        }
        let ids = match collect_instance_ids(&args) {
            Ok(i) => i,
            Err(e) => return e,
        };
        let region = arg_str(&args, "region")
            .map(|s| s.to_string())
            .or_else(|| profile.default_region.clone())
            .unwrap_or_else(|| "us-east-1".into());
        let timeout_sec = args
            .get("timeout_sec")
            .and_then(|v| v.as_u64())
            .unwrap_or(60)
            .clamp(5, 600);
        let shell = arg_str(&args, "shell").unwrap_or("bash");
        let document = if matches!(shell, "powershell" | "pwsh" | "windows") {
            "AWS-RunPowerShellScript"
        } else {
            "AWS-RunShellScript"
        };
        let remote = encode_remote_command(&command, shell);
        let comment = arg_str(&args, "comment").unwrap_or("oscar aws.ssm.exec");

        // Build Parameters JSON object for CLI
        let mut params = json!({ "commands": [remote] });
        if let Some(wd) = arg_str(&args, "working_directory") {
            if let Some(obj) = params.as_object_mut() {
                obj.insert("workingDirectory".into(), json!([wd]));
            }
        }

        let mut send_args: Vec<String> = vec![
            "ssm".into(),
            "send-command".into(),
            "--region".into(),
            region.clone(),
            "--document-name".into(),
            document.into(),
            "--comment".into(),
            comment.into(),
            "--timeout-seconds".into(),
            timeout_sec.to_string(),
            "--output".into(),
            "json".into(),
        ];
        for id in &ids {
            send_args.push("--instance-ids".into());
            send_args.push(id.clone());
        }
        send_args.push("--parameters".into());
        send_args.push(params.to_string());

        let refs: Vec<&str> = send_args.iter().map(|s| s.as_str()).collect();
        let sent = match aws_json(&profile, &refs).await {
            Ok(v) => v,
            Err(e) => return e,
        };

        let command_id = sent
            .pointer("/Command/CommandId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if command_id.is_empty() {
            return ToolResult::error(format!(
                "ssm send-command returned no CommandId: {}",
                sent
            ));
        }

        // Poll each instance
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_sec + 15);
        let mut results = Vec::new();
        for id in &ids {
            let inv = poll_invocation(&profile, &region, &command_id, id, deadline).await;
            results.push(inv);
        }

        let all_ok = results.iter().all(|r| {
            r.get("status")
                .and_then(|s| s.as_str())
                .is_some_and(|s| s == "Success")
        });
        let summary = if results.len() == 1 {
            let r = &results[0];
            let st = r.get("status").and_then(|s| s.as_str()).unwrap_or("?");
            let code = r.get("response_code").and_then(|c| c.as_i64()).unwrap_or(-1);
            format!(
                "SSM {st} on {} (exit {code}, command_id={command_id})",
                ids[0]
            )
        } else {
            format!(
                "SSM command_id={command_id} on {} instance(s) — ok={}",
                ids.len(),
                all_ok
            )
        };

        let mut data = json!({
            "cloud": "aws",
            "profile_id": profile.id,
            "region": region,
            "command_id": command_id,
            "document": document,
            "instance_ids": ids,
            "encoding": "base64_wrap",
            "command_preview": truncate_chars(&command, 200),
            "results": results,
            "ok": all_ok,
        });
        // Convenience: single-instance stdout at top level
        if results.len() == 1 {
            if let Some(obj) = data.as_object_mut() {
                obj.insert(
                    "stdout".into(),
                    results[0]
                        .get("stdout")
                        .cloned()
                        .unwrap_or(json!("")),
                );
                obj.insert(
                    "stderr".into(),
                    results[0]
                        .get("stderr")
                        .cloned()
                        .unwrap_or(json!("")),
                );
                obj.insert(
                    "status".into(),
                    results[0]
                        .get("status")
                        .cloned()
                        .unwrap_or(json!("Unknown")),
                );
                obj.insert(
                    "response_code".into(),
                    results[0]
                        .get("response_code")
                        .cloned()
                        .unwrap_or(json!(-1)),
                );
            }
        }

        if all_ok {
            ToolResult::success(summary, data)
        } else {
            let mut r = ToolResult::error(summary);
            r.data = data;
            r
        }
    }
}

async fn poll_invocation(
    profile: &oscar_identity::Profile,
    region: &str,
    command_id: &str,
    instance_id: &str,
    deadline: tokio::time::Instant,
) -> Value {
    loop {
        let inv = aws_json(
            profile,
            &[
                "ssm",
                "get-command-invocation",
                "--region",
                region,
                "--command-id",
                command_id,
                "--instance-id",
                instance_id,
                "--output",
                "json",
            ],
        )
        .await;

        match inv {
            Ok(v) => {
                let status = v
                    .get("Status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown")
                    .to_string();
                if matches!(
                    status.as_str(),
                    "Success" | "Failed" | "Cancelled" | "TimedOut" | "Cancelling"
                ) || tokio::time::Instant::now() >= deadline
                {
                    let stdout = v
                        .get("StandardOutputContent")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let stderr = v
                        .get("StandardErrorContent")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let code = v
                        .get("ResponseCode")
                        .and_then(|c| c.as_i64())
                        .unwrap_or(-1);
                    let truncated = stdout.len() >= 24000 || stderr.len() >= 24000;
                    return json!({
                        "instance_id": instance_id,
                        "status": status,
                        "response_code": code,
                        "stdout": stdout,
                        "stderr": stderr,
                        "stdout_truncated": truncated,
                        "status_details": v.get("StatusDetails"),
                        "plugin_name": v.get("PluginName"),
                    });
                }
            }
            Err(e) => {
                // InvocationNotFound — still propagating
                let msg = e.summary.clone();
                if msg.contains("InvocationDoesNotExist")
                    || msg.contains("not found")
                    || msg.contains("does not exist")
                {
                    if tokio::time::Instant::now() >= deadline {
                        return json!({
                            "instance_id": instance_id,
                            "status": "Timeout",
                            "response_code": -1,
                            "stdout": "",
                            "stderr": msg,
                        });
                    }
                } else {
                    return json!({
                        "instance_id": instance_id,
                        "status": "Error",
                        "response_code": -1,
                        "stdout": "",
                        "stderr": msg,
                    });
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        if tokio::time::Instant::now() >= deadline {
            return json!({
                "instance_id": instance_id,
                "status": "Timeout",
                "response_code": -1,
                "stdout": "",
                "stderr": "timed out waiting for SSM get-command-invocation",
            });
        }
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

#[async_trait]
impl Tool for AwsSsmInstancesList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.ssm.instances.list".into(),
            name: "List SSM-managed EC2 instances".into(),
            description: "List EC2 instances visible to Systems Manager (PingStatus, platform, IP, name). \
Use before aws.ssm.exec to pick instance_id. Filters optional: online_only, name_contains, platform.".into(),
            domain: ToolDomain::Infra,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "ssm".into(),
                "ec2".into(),
                "instance".into(),
                "list".into(),
                "node".into(),
                "managed".into(),
                "inventory".into(),
                "discover".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "region": { "type": "string" },
                    "profile_id": { "type": "string" },
                    "online_only": { "type": "boolean", "default": true },
                    "name_contains": { "type": "string", "description": "Substring match on ComputerName / Name tag" },
                    "max_results": { "type": "integer", "default": 50 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let region = arg_str(&args, "region")
            .map(|s| s.to_string())
            .or_else(|| profile.default_region.clone())
            .unwrap_or_else(|| "us-east-1".into());
        let online_only = args
            .get("online_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let name_filter = arg_str(&args, "name_contains")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        let max = args
            .get("max_results")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .clamp(1, 200) as usize;

        let mut cli_args = vec![
            "ssm",
            "describe-instance-information",
            "--region",
            region.as_str(),
            "--output",
            "json",
            "--max-results",
            "50",
        ];
        // filters as JSON if online
        let filters_owned: Option<String> = if online_only {
            Some(r#"[{"Key":"PingStatus","Values":["Online"]}]"#.to_string())
        } else {
            None
        };
        if let Some(ref f) = filters_owned {
            cli_args.push("--filters");
            cli_args.push(f.as_str());
        }

        let raw = match aws_json(&profile, &cli_args).await {
            Ok(v) => v,
            Err(e) => return e,
        };

        let mut instances = Vec::new();
        if let Some(arr) = raw
            .get("InstanceInformationList")
            .and_then(|a| a.as_array())
        {
            for it in arr {
                let id = it
                    .get("InstanceId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = it
                    .get("ComputerName")
                    .or_else(|| it.get("Name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let platform = it
                    .get("PlatformType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ping = it
                    .get("PingStatus")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ip = it
                    .get("IPAddress")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !name_filter.is_empty() {
                    let hay = format!("{name} {id} {ip}").to_ascii_lowercase();
                    if !hay.contains(&name_filter) {
                        continue;
                    }
                }
                instances.push(json!({
                    "instance_id": id,
                    "computer_name": name,
                    "platform": platform,
                    "ping_status": ping,
                    "ip_address": ip,
                    "agent_version": it.get("AgentVersion"),
                    "resource_type": it.get("ResourceType"),
                }));
                if instances.len() >= max {
                    break;
                }
            }
        }

        ToolResult::success(
            format!(
                "{} SSM-managed instance(s) in {region} (profile `{}`)",
                instances.len(),
                profile.id
            ),
            json!({
                "cloud": "aws",
                "profile_id": profile.id,
                "region": region,
                "count": instances.len(),
                "instances": instances,
                "next": "aws.ssm.exec instance_id=i-… command=\"your shell command\"",
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_hello() {
        assert_eq!(encode_base64(b"hello"), "aGVsbG8=");
        assert_eq!(encode_base64(b"hi"), "aGk=");
        assert_eq!(encode_base64(b"f"), "Zg==");
    }

    #[test]
    fn remote_wrap_contains_b64() {
        let r = encode_remote_command("echo hello | wc -l", "bash");
        assert!(r.contains("base64 -d"));
        assert!(r.contains("bash -s"));
        // payload is base64 of the command
        assert!(r.contains(&encode_base64(b"echo hello | wc -l")));
    }

    #[test]
    fn collect_ids() {
        let v = json!({"instance_id": "i-abc123"});
        assert_eq!(collect_instance_ids(&v).unwrap(), vec!["i-abc123"]);
        let v = json!({"instance_ids": ["i-a", "i-b"]});
        assert_eq!(collect_instance_ids(&v).unwrap().len(), 2);
    }
}
