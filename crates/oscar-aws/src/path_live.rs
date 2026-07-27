//! Live AWS path / access analyzer tools via EC2 Network Insights APIs.

use crate::aws_runtime::{aws_json, first_aws_profile};
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PathBlocker, PathHop, PathStatus, PathTraceResult, ToolDomain};
use oscar_tools::{Tool, ToolContext, ToolMeta, ToolResult};
use serde_json::json;
use tokio::time::{sleep, Duration};

pub struct AwsNetworkPathAnalyze;
pub struct AwsNetworkAccessAnalyze;

#[async_trait]
impl Tool for AwsNetworkPathAnalyze {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.path.analyze".into(),
            name: "AWS VPC Reachability Analyzer".into(),
            description: "Live VPC Reachability Analyzer: create path + analysis between source/destination (IP or resource id), poll until complete, return unified PathTraceResult.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "path".into(),
                "reachability".into(),
                "vpc".into(),
                "live".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "Source IP or resource id (eni-/i-/vgw-…)" },
                    "destination": { "type": "string", "description": "Destination IP or resource id" },
                    "protocol": { "type": "string", "default": "tcp" },
                    "destination_port": { "type": "integer" },
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "poll_seconds": { "type": "integer", "default": 45 }
                },
                "required": ["source", "destination"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let dest = args.get("destination").and_then(|v| v.as_str()).unwrap_or("");
        if source.is_empty() || dest.is_empty() {
            return ToolResult::error("source and destination are required");
        }
        let profile = match first_aws_profile(
            &ctx.profiles,
            args.get("profile_id").and_then(|v| v.as_str()),
        ) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let region = args
            .get("region")
            .and_then(|v| v.as_str())
            .or(profile.default_region.as_deref())
            .unwrap_or("us-east-1");
        let protocol = args
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp");
        let port = args
            .get("destination_port")
            .and_then(|v| v.as_u64())
            .map(|p| p.to_string());
        let poll_secs = args
            .get("poll_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(45)
            .min(180);

        // IP vs resource id heuristic
        let mut create_owned: Vec<String> = vec![
            "ec2".into(),
            "create-network-insights-path".into(),
            "--region".into(),
            region.into(),
            "--protocol".into(),
            protocol.into(),
            "--output".into(),
            "json".into(),
        ];
        if looks_like_ip(source) {
            create_owned.push("--source-ip".into());
            create_owned.push(source.into());
        } else {
            create_owned.push("--source".into());
            create_owned.push(source.into());
        }
        if looks_like_ip(dest) {
            create_owned.push("--destination-ip".into());
            create_owned.push(dest.into());
        } else {
            create_owned.push("--destination".into());
            create_owned.push(dest.into());
        }
        if let Some(p) = &port {
            create_owned.push("--destination-port".into());
            create_owned.push(p.clone());
        }
        let create_refs: Vec<&str> = create_owned.iter().map(|s| s.as_str()).collect();

        let created = match aws_json(profile, &create_refs).await {
            Ok(v) => v,
            Err(e) => return e,
        };
        let path_id = created
            .pointer("/NetworkInsightsPath/NetworkInsightsPathId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if path_id.is_empty() {
            return ToolResult::error(format!("create-network-insights-path unexpected: {created}"));
        }

        let start = match aws_json(
            profile,
            &[
                "ec2",
                "start-network-insights-analysis",
                "--region",
                region,
                "--network-insights-path-id",
                &path_id,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => v,
            Err(e) => return e,
        };
        let analysis_id = start
            .pointer("/NetworkInsightsAnalysis/NetworkInsightsAnalysisId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if analysis_id.is_empty() {
            return ToolResult::error(format!("start analysis unexpected: {start}"));
        }

        let mut last = start;
        let deadline = std::time::Instant::now() + Duration::from_secs(poll_secs);
        loop {
            let desc = match aws_json(
                profile,
                &[
                    "ec2",
                    "describe-network-insights-analyses",
                    "--region",
                    region,
                    "--network-insights-analysis-ids",
                    &analysis_id,
                    "--output",
                    "json",
                ],
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return e,
            };
            last = desc.clone();
            let status = desc
                .pointer("/NetworkInsightsAnalyses/0/Status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if status.eq_ignore_ascii_case("succeeded")
                || status.eq_ignore_ascii_case("failed")
            {
                break;
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            if ctx.cancel.is_cancelled() {
                return ToolResult::error("path analysis cancelled");
            }
            sleep(Duration::from_secs(3)).await;
        }

        let analysis = last
            .pointer("/NetworkInsightsAnalyses/0")
            .cloned()
            .unwrap_or(last);
        let status_str = analysis
            .get("Status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let network_path_found = analysis
            .get("NetworkPathFound")
            .and_then(|v| v.as_bool());
        let path_status = match (status_str, network_path_found) {
            ("succeeded", Some(true)) => PathStatus::Reachable,
            ("succeeded", Some(false)) => PathStatus::Unreachable,
            ("failed", _) => PathStatus::Unknown,
            _ => PathStatus::Partial,
        };

        let mut hops = Vec::new();
        if let Some(components) = analysis
            .get("ForwardPathComponents")
            .and_then(|v| v.as_array())
        {
            for (i, c) in components.iter().enumerate() {
                let resource = c
                    .pointer("/Component/Id")
                    .or_else(|| c.pointer("/Component/Arn"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("component")
                    .to_string();
                let detail = c
                    .get("OutboundHeader")
                    .or_else(|| c.get("InboundHeader"))
                    .map(|v| v.to_string());
                hops.push(PathHop {
                    order: i as u32,
                    resource,
                    detail,
                });
            }
        }

        let mut blockers = Vec::new();
        if let Some(explanations) = analysis
            .get("Explanations")
            .and_then(|v| v.as_array())
        {
            for e in explanations {
                let msg = e
                    .get("ExplanationCode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("blocked")
                    .to_string();
                let resource = e
                    .pointer("/Acl/Id")
                    .or_else(|| e.pointer("/SecurityGroup/Id"))
                    .or_else(|| e.pointer("/NetworkAcl/Id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                blockers.push(PathBlocker {
                    kind: e
                        .get("ExplanationCode")
                        .and_then(|v| v.as_str())
                        .unwrap_or("explanation")
                        .to_string(),
                    resource,
                    message: msg,
                });
            }
        }

        let summary = format!(
            "Reachability Analyzer {source} → {dest}: status={status_str} path_found={:?} hops={} blockers={}",
            network_path_found,
            hops.len(),
            blockers.len()
        );
        let trace = PathTraceResult {
            cloud: Cloud::Aws,
            status: path_status,
            hops,
            blockers,
            raw_ref: Some(analysis_id.clone()),
            summary: summary.clone(),
        };
        ToolResult::success(
            summary,
            json!({
                "format": "PathTraceResult",
                "path_id": path_id,
                "analysis_id": analysis_id,
                "region": region,
                "result": trace,
                "native": analysis,
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsNetworkAccessAnalyze {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.access.analyze".into(),
            name: "AWS Network Access Analyzer".into(),
            description: "Live Network Access Analyzer: list access scopes and optionally start/describe an analysis for a scope_id.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "access".into(),
                "analyzer".into(),
                "live".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scope_id": { "type": "string", "description": "Network Insights Access Scope id; if omitted, list scopes" },
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "poll_seconds": { "type": "integer", "default": 45 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile(
            &ctx.profiles,
            args.get("profile_id").and_then(|v| v.as_str()),
        ) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let region = args
            .get("region")
            .and_then(|v| v.as_str())
            .or(profile.default_region.as_deref())
            .unwrap_or("us-east-1");
        let scope_id = args.get("scope_id").and_then(|v| v.as_str());

        if scope_id.is_none() {
            let listed = match aws_json(
                profile,
                &[
                    "ec2",
                    "describe-network-insights-access-scopes",
                    "--region",
                    region,
                    "--output",
                    "json",
                ],
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return e,
            };
            let scopes = listed
                .get("NetworkInsightsAccessScopes")
                .cloned()
                .unwrap_or(json!([]));
            let n = scopes.as_array().map(|a| a.len()).unwrap_or(0);
            return ToolResult::success(
                format!("{n} Network Access Analyzer scope(s) in {region}"),
                json!({
                    "format": "NetworkAccessScopes",
                    "region": region,
                    "scopes": scopes,
                    "hint": "Pass scope_id to start an analysis"
                }),
            );
        }

        let scope_id = scope_id.unwrap();
        let started = match aws_json(
            profile,
            &[
                "ec2",
                "start-network-insights-access-scope-analysis",
                "--region",
                region,
                "--network-insights-access-scope-id",
                scope_id,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => v,
            Err(e) => return e,
        };
        let analysis_id = started
            .pointer("/NetworkInsightsAccessScopeAnalysis/NetworkInsightsAccessScopeAnalysisId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if analysis_id.is_empty() {
            return ToolResult::error(format!("start scope analysis unexpected: {started}"));
        }

        let poll_secs = args
            .get("poll_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(45)
            .min(180);
        let deadline = std::time::Instant::now() + Duration::from_secs(poll_secs);
        let mut last = started;
        loop {
            let desc = match aws_json(
                profile,
                &[
                    "ec2",
                    "describe-network-insights-access-scope-analyses",
                    "--region",
                    region,
                    "--network-insights-access-scope-analysis-ids",
                    &analysis_id,
                    "--output",
                    "json",
                ],
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return e,
            };
            last = desc.clone();
            let status = desc
                .pointer("/NetworkInsightsAccessScopeAnalyses/0/Status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if status.eq_ignore_ascii_case("succeeded")
                || status.eq_ignore_ascii_case("failed")
            {
                break;
            }
            if std::time::Instant::now() > deadline || ctx.cancel.is_cancelled() {
                break;
            }
            sleep(Duration::from_secs(3)).await;
        }

        ToolResult::success(
            format!("Network Access Analyzer analysis {analysis_id} complete (scope {scope_id})"),
            json!({
                "format": "NetworkAccessScopeAnalysis",
                "scope_id": scope_id,
                "analysis_id": analysis_id,
                "region": region,
                "result": last,
            }),
        )
    }
}

fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}
