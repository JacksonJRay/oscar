//! Azure network write tools. **Capability::Write** — blocked in readonly mode.

use async_trait::async_trait;
use oscar_core::{Capability, Cloud, ToolDomain};
use oscar_tools::sync::{run_json_command, which_ok};
use oscar_tools::{auth_for, Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult};
use serde_json::json;
use std::sync::Arc;

pub fn register_network_write(registry: &mut ToolRegistry) {
    registry.register(Arc::new(AzureNetworkVnetCreate));
    registry.register(Arc::new(AzureNetworkVnetDelete));
    registry.register(Arc::new(AzureNetworkSubnetCreate));
    registry.register(Arc::new(AzureNetworkSubnetDelete));
    registry.register(Arc::new(AzureNetworkNsgCreate));
    registry.register(Arc::new(AzureNetworkNsgDelete));
    registry.register(Arc::new(AzureNetworkRouteTableCreate));
    registry.register(Arc::new(AzureNetworkRouteTableDelete));
    registry.register(Arc::new(AzureNetworkRouteCreate));
    registry.register(Arc::new(AzureNetworkRouteDelete));
    registry.register(Arc::new(AzureNetworkPeeringCreate));
    registry.register(Arc::new(AzureNetworkPeeringDelete));
}

fn write_meta(id: &str, name: &str, desc: &str, tags: &[&str], schema: serde_json::Value) -> ToolMeta {
    let mut t: Vec<String> = tags.iter().map(|s| (*s).into()).collect();
    t.push("write".into());
    ToolMeta {
        id: id.into(),
        name: name.into(),
        description: format!("{desc} **Requires session mode readwrite** (blocked in readonly)."),
        domain: ToolDomain::Network,
        clouds: vec![Cloud::Azure],
        capability: Capability::Write,
        tags: t,
        input_schema: schema,
        output_schema: None,
    }
}

fn profile_az<'a>(
    ctx: &'a ToolContext,
    profile_id: Option<&str>,
) -> Result<&'a oscar_identity::Profile, ToolResult> {
    let profiles = ctx.profiles_for(Cloud::Azure, profile_id);
    profiles.first().copied().ok_or_else(|| {
        ToolResult::needs_auth(auth_for(Cloud::Azure, "Azure profile required"))
    })
}

async fn ensure_az() -> Result<(), ToolResult> {
    if which_ok("az").await {
        Ok(())
    } else {
        Err(ToolResult::error("az CLI not on PATH"))
    }
}

fn req(args: &serde_json::Value, k: &str) -> Result<String, ToolResult> {
    args.get(k)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| ToolResult::error(format!("{k} is required")))
}

struct AzureNetworkVnetCreate;
struct AzureNetworkVnetDelete;
struct AzureNetworkSubnetCreate;
struct AzureNetworkSubnetDelete;
struct AzureNetworkNsgCreate;
struct AzureNetworkNsgDelete;
struct AzureNetworkRouteTableCreate;
struct AzureNetworkRouteTableDelete;
struct AzureNetworkRouteCreate;
struct AzureNetworkRouteDelete;
struct AzureNetworkPeeringCreate;
struct AzureNetworkPeeringDelete;

#[async_trait]
impl Tool for AzureNetworkVnetCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.vnet.create",
                "Create VNet",
                "Create an Azure virtual network (az network vnet create).",
                &["vnet", "create", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "name":{"type":"string"},
                        "address_prefixes":{"type":"string","default":"10.0.0.0/16"},
                        "location":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let prefixes = args
            .get("address_prefixes")
            .and_then(|v| v.as_str())
            .unwrap_or("10.0.0.0/16");
        let mut cmd = vec![
            "network".into(),
            "vnet".into(),
            "create".into(),
            "-g".into(),
            rg.clone(),
            "-n".into(),
            name.clone(),
            "--address-prefixes".into(),
            prefixes.into(),
            "-o".into(),
            "json".into(),
        ];
        if let Some(loc) = args.get("location").and_then(|v| v.as_str()) {
            cmd.push("-l".into());
            cmd.push(loc.into());
        }
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("az", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created VNet {name} in {rg}"),
                json!({"action":"create","resource":"vnet","name":name,"resource_group":rg,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkVnetDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.vnet.delete",
                "Delete VNet",
                "Delete an Azure virtual network (az network vnet delete).",
                &["vnet", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "name":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cmd = [
            "network", "vnet", "delete", "-g", &rg, "-n", &name, "--yes", "-o", "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Deleted VNet {name}"),
                json!({"action":"delete","resource":"vnet","name":name,"raw":v}),
            ),
            Err(e) => {
                let t = e.to_string();
                if t.is_empty() || t.contains("None") {
                    ToolResult::success(
                        format!("Deleted VNet {name}"),
                        json!({"action":"delete","resource":"vnet","name":name}),
                    )
                } else {
                    ToolResult::from_error_text(Cloud::Azure, Some(&p.id), t)
                }
            }
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkSubnetCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.subnet.create",
                "Create subnet",
                "Create an Azure subnet (az network vnet subnet create).",
                &["subnet", "create", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "vnet_name":{"type":"string"},
                        "name":{"type":"string"},
                        "address_prefix":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","vnet_name","name","address_prefix"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let vnet = match req(&args, "vnet_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let prefix = match req(&args, "address_prefix") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cmd = [
            "network",
            "vnet",
            "subnet",
            "create",
            "-g",
            &rg,
            "--vnet-name",
            &vnet,
            "-n",
            &name,
            "--address-prefixes",
            &prefix,
            "-o",
            "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Created subnet {name} ({prefix})"),
                json!({"action":"create","resource":"subnet","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkSubnetDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.subnet.delete",
                "Delete subnet",
                "Delete an Azure subnet (az network vnet subnet delete).",
                &["subnet", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "vnet_name":{"type":"string"},
                        "name":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","vnet_name","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let vnet = match req(&args, "vnet_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cmd = [
            "network",
            "vnet",
            "subnet",
            "delete",
            "-g",
            &rg,
            "--vnet-name",
            &vnet,
            "-n",
            &name,
            "-o",
            "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Deleted subnet {name}"),
                json!({"action":"delete","resource":"subnet","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkNsgCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.nsg.create",
                "Create NSG",
                "Create an Azure network security group (az network nsg create).",
                &["nsg", "create", "network", "firewall"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "name":{"type":"string"},
                        "location":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut cmd = vec![
            "network".into(),
            "nsg".into(),
            "create".into(),
            "-g".into(),
            rg.clone(),
            "-n".into(),
            name.clone(),
            "-o".into(),
            "json".into(),
        ];
        if let Some(loc) = args.get("location").and_then(|v| v.as_str()) {
            cmd.push("-l".into());
            cmd.push(loc.into());
        }
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("az", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created NSG {name}"),
                json!({"action":"create","resource":"nsg","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkNsgDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.nsg.delete",
                "Delete NSG",
                "Delete an Azure NSG (az network nsg delete).",
                &["nsg", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "name":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cmd = ["network", "nsg", "delete", "-g", &rg, "-n", &name, "-o", "json"];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Deleted NSG {name}"),
                json!({"action":"delete","resource":"nsg","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkRouteTableCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.route_table.create",
                "Create route table",
                "Create an Azure route table (az network route-table create).",
                &["route-table", "create", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "name":{"type":"string"},
                        "location":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut cmd = vec![
            "network".into(),
            "route-table".into(),
            "create".into(),
            "-g".into(),
            rg,
            "-n".into(),
            name.clone(),
            "-o".into(),
            "json".into(),
        ];
        if let Some(loc) = args.get("location").and_then(|v| v.as_str()) {
            cmd.push("-l".into());
            cmd.push(loc.into());
        }
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("az", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created route table {name}"),
                json!({"action":"create","resource":"route_table","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkRouteTableDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.route_table.delete",
                "Delete route table",
                "Delete an Azure route table (az network route-table delete).",
                &["route-table", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "name":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cmd = [
            "network",
            "route-table",
            "delete",
            "-g",
            &rg,
            "-n",
            &name,
            "-o",
            "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Deleted route table {name}"),
                json!({"action":"delete","resource":"route_table","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkRouteCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.route.create",
                "Create UDR route",
                "Create a route in an Azure route table (az network route-table route create).",
                &["route", "create", "network", "udr"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "route_table_name":{"type":"string"},
                        "name":{"type":"string"},
                        "address_prefix":{"type":"string"},
                        "next_hop_type":{"type":"string","description":"VirtualAppliance|VnetLocal|Internet|None","default":"VirtualAppliance"},
                        "next_hop_ip_address":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","route_table_name","name","address_prefix"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let rtb = match req(&args, "route_table_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let prefix = match req(&args, "address_prefix") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let hop = args
            .get("next_hop_type")
            .and_then(|v| v.as_str())
            .unwrap_or("VirtualAppliance");
        let mut cmd = vec![
            "network".into(),
            "route-table".into(),
            "route".into(),
            "create".into(),
            "-g".into(),
            rg,
            "--route-table-name".into(),
            rtb,
            "-n".into(),
            name.clone(),
            "--address-prefix".into(),
            prefix.clone(),
            "--next-hop-type".into(),
            hop.into(),
            "-o".into(),
            "json".into(),
        ];
        if let Some(ip) = args.get("next_hop_ip_address").and_then(|v| v.as_str()) {
            cmd.push("--next-hop-ip-address".into());
            cmd.push(ip.into());
        }
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("az", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created route {name} ({prefix})"),
                json!({"action":"create","resource":"route","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkRouteDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.route.delete",
                "Delete UDR route",
                "Delete a route from an Azure route table (az network route-table route delete).",
                &["route", "delete", "network", "udr"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "route_table_name":{"type":"string"},
                        "name":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","route_table_name","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let rtb = match req(&args, "route_table_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cmd = [
            "network",
            "route-table",
            "route",
            "delete",
            "-g",
            &rg,
            "--route-table-name",
            &rtb,
            "-n",
            &name,
            "-o",
            "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Deleted route {name}"),
                json!({"action":"delete","resource":"route","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkPeeringCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.peering.create",
                "Create VNet peering",
                "Create Azure VNet peering (az network vnet peering create). Often need reciprocal peering.",
                &["peering", "create", "network", "vnet"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "vnet_name":{"type":"string"},
                        "name":{"type":"string"},
                        "remote_vnet_id":{"type":"string","description":"Full resource id of remote VNet"},
                        "allow_vnet_access":{"type":"boolean","default":true},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","vnet_name","name","remote_vnet_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let vnet = match req(&args, "vnet_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let remote = match req(&args, "remote_vnet_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let allow = args
            .get("allow_vnet_access")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let cmd = [
            "network",
            "vnet",
            "peering",
            "create",
            "-g",
            &rg,
            "--vnet-name",
            &vnet,
            "-n",
            &name,
            "--remote-vnet",
            &remote,
            "--allow-vnet-access",
            if allow { "true" } else { "false" },
            "-o",
            "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Created VNet peering {name} (reciprocal may still be needed)"),
                json!({"action":"create","resource":"peering","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkPeeringDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            write_meta(
                "azure.network.peering.delete",
                "Delete VNet peering",
                "Delete Azure VNet peering (az network vnet peering delete).",
                &["peering", "delete", "network"],
                json!({
                    "type":"object",
                    "properties":{
                        "resource_group":{"type":"string"},
                        "vnet_name":{"type":"string"},
                        "name":{"type":"string"},
                        "profile_id":{"type":"string"}
                    },
                    "required":["resource_group","vnet_name","name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Err(e) = ensure_az().await {
            return e;
        }
        let p = match profile_az(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rg = match req(&args, "resource_group") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let vnet = match req(&args, "vnet_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match req(&args, "name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cmd = [
            "network",
            "vnet",
            "peering",
            "delete",
            "-g",
            &rg,
            "--vnet-name",
            &vnet,
            "-n",
            &name,
            "-o",
            "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Deleted VNet peering {name}"),
                json!({"action":"delete","resource":"peering","name":name,"raw":v}),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&p.id), e.to_string()),
        }
    }
}
