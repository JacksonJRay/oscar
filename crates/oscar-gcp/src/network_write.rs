//! GCP network write tools. **Capability::Write** — blocked in readonly mode.

use async_trait::async_trait;
use oscar_core::{Capability, Cloud, ToolDomain};
use oscar_tools::sync::{gcloud_project_args, run_json_command, which_ok};
use oscar_tools::{auth_for, Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult};
use serde_json::json;
use std::sync::Arc;

pub fn register_network_write(registry: &mut ToolRegistry) {
    registry.register(Arc::new(GcpNetworkVpcCreate));
    registry.register(Arc::new(GcpNetworkVpcDelete));
    registry.register(Arc::new(GcpNetworkSubnetCreate));
    registry.register(Arc::new(GcpNetworkSubnetDelete));
    registry.register(Arc::new(GcpNetworkFirewallCreate));
    registry.register(Arc::new(GcpNetworkFirewallDelete));
    registry.register(Arc::new(GcpNetworkRouteCreate));
    registry.register(Arc::new(GcpNetworkRouteDelete));
    registry.register(Arc::new(GcpNetworkPeeringCreate));
    registry.register(Arc::new(GcpNetworkPeeringDelete));
}

fn write_meta(id: &str, name: &str, desc: &str, tags: &[&str], schema: serde_json::Value) -> ToolMeta {
    let mut t: Vec<String> = tags.iter().map(|s| (*s).into()).collect();
    t.push("write".into());
    ToolMeta {
        id: id.into(),
        name: name.into(),
        description: format!("{desc} **Requires session mode readwrite** (blocked in readonly)."),
        domain: ToolDomain::Network,
        clouds: vec![Cloud::Gcp],
        capability: Capability::Write,
        tags: t,
        input_schema: schema,
        output_schema: None,
    }
}

fn profile_gcp<'a>(
    ctx: &'a ToolContext,
    profile_id: Option<&str>,
) -> Result<&'a oscar_identity::Profile, ToolResult> {
    let profiles = ctx.profiles_for(Cloud::Gcp, profile_id);
    profiles.first().copied().ok_or_else(|| {
        ToolResult::needs_auth(auth_for(Cloud::Gcp, "GCP profile required (account_ref=project id)"))
    })
}

async fn ensure_gcloud() -> Result<(), ToolResult> {
    if which_ok("gcloud").await {
        Ok(())
    } else {
        Err(ToolResult::error("gcloud not on PATH"))
    }
}

struct GcpNetworkVpcCreate;
struct GcpNetworkVpcDelete;
struct GcpNetworkSubnetCreate;
struct GcpNetworkSubnetDelete;
struct GcpNetworkFirewallCreate;
struct GcpNetworkFirewallDelete;
struct GcpNetworkRouteCreate;
struct GcpNetworkRouteDelete;
struct GcpNetworkPeeringCreate;
struct GcpNetworkPeeringDelete;

#[async_trait]
impl Tool for GcpNetworkVpcCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.vpc.create",
                "Create VPC network",
                "Create a GCP VPC network (gcloud compute networks create).",
                &["vpc", "network", "create"],
                json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "subnet_mode":{"type":"string","default":"custom","description":"custom|auto"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return ToolResult::error("name required");
        }
        let mode = args
            .get("subnet_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("custom");
        let mut cmd = vec![
            "compute".into(),
            "networks".into(),
            "create".into(),
            name.into(),
            format!("--subnet-mode={mode}"),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created GCP network {name}"),
                json!({"action":"create","resource":"vpc","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkVpcDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.vpc.delete",
                "Delete VPC network",
                "Delete a GCP VPC network (gcloud compute networks delete).",
                &["vpc", "network", "delete"],
                json!({
                    "type":"object",
                    "properties":{"name":{"type":"string"},"profile_id":{"type":"string"}},
                    "required":["name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return ToolResult::error("name required");
        }
        let mut cmd = vec![
            "compute".into(),
            "networks".into(),
            "delete".into(),
            name.into(),
            "--quiet".into(),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Deleted GCP network {name}"),
                json!({"action":"delete","resource":"vpc","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkSubnetCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.subnet.create",
                "Create subnet",
                "Create a GCP subnet (gcloud compute networks subnets create).",
                &["subnet", "create", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "network":{"type":"string"},
                        "region":{"type":"string"},
                        "range":{"type":"string","description":"CIDR e.g. 10.0.1.0/24"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["name","network","region","range"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let network = args.get("network").and_then(|v| v.as_str()).unwrap_or("");
        let region = args.get("region").and_then(|v| v.as_str()).unwrap_or("");
        let range = args.get("range").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || network.is_empty() || region.is_empty() || range.is_empty() {
            return ToolResult::error("name, network, region, range required");
        }
        let mut cmd = vec![
            "compute".into(),
            "networks".into(),
            "subnets".into(),
            "create".into(),
            name.into(),
            format!("--network={network}"),
            format!("--region={region}"),
            format!("--range={range}"),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created subnet {name} ({range})"),
                json!({"action":"create","resource":"subnet","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkSubnetDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.subnet.delete",
                "Delete subnet",
                "Delete a GCP subnet (gcloud compute networks subnets delete).",
                &["subnet", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "region":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["name","region"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let region = args.get("region").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || region.is_empty() {
            return ToolResult::error("name and region required");
        }
        let mut cmd = vec![
            "compute".into(),
            "networks".into(),
            "subnets".into(),
            "delete".into(),
            name.into(),
            format!("--region={region}"),
            "--quiet".into(),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Deleted subnet {name}"),
                json!({"action":"delete","resource":"subnet","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkFirewallCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.firewall.create",
                "Create firewall rule",
                "Create a GCP VPC firewall rule (gcloud compute firewall-rules create). Prefer least-privilege ranges.",
                &["firewall", "create", "network", "security-group"],
                json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "network":{"type":"string","default":"default"},
                        "direction":{"type":"string","default":"INGRESS"},
                        "action":{"type":"string","default":"ALLOW"},
                        "rules":{"type":"string","description":"e.g. tcp:22 or tcp:80,443","default":"tcp:22"},
                        "source_ranges":{"type":"string","default":"0.0.0.0/0"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return ToolResult::error("name required");
        }
        let network = args.get("network").and_then(|v| v.as_str()).unwrap_or("default");
        let direction = args.get("direction").and_then(|v| v.as_str()).unwrap_or("INGRESS");
        let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("ALLOW");
        let rules = args.get("rules").and_then(|v| v.as_str()).unwrap_or("tcp:22");
        let src = args
            .get("source_ranges")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0/0");
        let mut cmd = vec![
            "compute".into(),
            "firewall-rules".into(),
            "create".into(),
            name.into(),
            format!("--network={network}"),
            format!("--direction={direction}"),
            format!("--action={action}"),
            format!("--rules={rules}"),
            format!("--source-ranges={src}"),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created firewall rule {name}"),
                json!({"action":"create","resource":"firewall","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkFirewallDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.firewall.delete",
                "Delete firewall rule",
                "Delete a GCP firewall rule (gcloud compute firewall-rules delete).",
                &["firewall", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{"name":{"type":"string"},"profile_id":{"type":"string"}},
                    "required":["name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return ToolResult::error("name required");
        }
        let mut cmd = vec![
            "compute".into(),
            "firewall-rules".into(),
            "delete".into(),
            name.into(),
            "--quiet".into(),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Deleted firewall rule {name}"),
                json!({"action":"delete","resource":"firewall","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkRouteCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.route.create",
                "Create custom route",
                "Create a GCP custom route (gcloud compute routes create).",
                &["route", "create", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "network":{"type":"string"},
                        "destination_range":{"type":"string"},
                        "next_hop_gateway":{"type":"string","description":"e.g. default-internet-gateway"},
                        "next_hop_ip":{"type":"string"},
                        "priority":{"type":"integer","default":1000},
                        "profile_id":{"type":"string"}
                    },
                    "required":["name","network","destination_range"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let network = args.get("network").and_then(|v| v.as_str()).unwrap_or("");
        let dest = args
            .get("destination_range")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if name.is_empty() || network.is_empty() || dest.is_empty() {
            return ToolResult::error("name, network, destination_range required");
        }
        let mut cmd = vec![
            "compute".into(),
            "routes".into(),
            "create".into(),
            name.into(),
            format!("--network={network}"),
            format!("--destination-range={dest}"),
            "--format=json".into(),
        ];
        if let Some(gw) = args.get("next_hop_gateway").and_then(|v| v.as_str()) {
            cmd.push(format!("--next-hop-gateway={gw}"));
        } else if let Some(ip) = args.get("next_hop_ip").and_then(|v| v.as_str()) {
            cmd.push(format!("--next-hop-address={ip}"));
        } else {
            return ToolResult::error("next_hop_gateway or next_hop_ip required");
        }
        if let Some(pr) = args.get("priority").and_then(|v| v.as_u64()) {
            cmd.push(format!("--priority={pr}"));
        }
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created route {name} → {dest}"),
                json!({"action":"create","resource":"route","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkRouteDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.route.delete",
                "Delete custom route",
                "Delete a GCP custom route (gcloud compute routes delete).",
                &["route", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{"name":{"type":"string"},"profile_id":{"type":"string"}},
                    "required":["name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return ToolResult::error("name required");
        }
        let mut cmd = vec![
            "compute".into(),
            "routes".into(),
            "delete".into(),
            name.into(),
            "--quiet".into(),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Deleted route {name}"),
                json!({"action":"delete","resource":"route","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkPeeringCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.peering.create",
                "Create VPC peering",
                "Create GCP VPC network peering (gcloud compute networks peerings create).",
                &["peering", "create", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "network":{"type":"string"},
                        "peer_network":{"type":"string","description":"Full URL or projects/P/global/networks/N"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["name","network","peer_network"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let network = args.get("network").and_then(|v| v.as_str()).unwrap_or("");
        let peer = args.get("peer_network").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || network.is_empty() || peer.is_empty() {
            return ToolResult::error("name, network, peer_network required");
        }
        let mut cmd = vec![
            "compute".into(),
            "networks".into(),
            "peerings".into(),
            "create".into(),
            name.into(),
            format!("--network={network}"),
            format!("--peer-network={peer}"),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created peering {name} on {network}"),
                json!({"action":"create","resource":"peering","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpNetworkPeeringDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "gcp.network.peering.delete",
                "Delete VPC peering",
                "Delete GCP VPC network peering (gcloud compute networks peerings delete).",
                &["peering", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "network":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["name","network"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_gcloud().await {
            return e;
        }
        let p = match profile_gcp(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let network = args.get("network").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || network.is_empty() {
            return ToolResult::error("name and network required");
        }
        let mut cmd = vec![
            "compute".into(),
            "networks".into(),
            "peerings".into(),
            "delete".into(),
            name.into(),
            format!("--network={network}"),
            "--quiet".into(),
            "--format=json".into(),
        ];
        cmd.extend(gcloud_project_args(p));
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Deleted peering {name}"),
                json!({"action":"delete","resource":"peering","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&p.id), e.to_string()),
        }
    }
}
