//! AWS network write tools (create/delete). **Capability::Write** — blocked in readonly mode.

use crate::aws_runtime::{arg_str, aws_json, first_aws_profile_ctx, require_str};
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, ToolDomain};
use oscar_tools::{Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult};
use serde_json::json;
use std::sync::Arc;

pub fn register_network_write(registry: &mut ToolRegistry) {
    registry.register(Arc::new(AwsNetworkVpcCreate));
    registry.register(Arc::new(AwsNetworkVpcDelete));
    registry.register(Arc::new(AwsNetworkSubnetCreate));
    registry.register(Arc::new(AwsNetworkSubnetDelete));
    registry.register(Arc::new(AwsNetworkSgCreate));
    registry.register(Arc::new(AwsNetworkSgDelete));
    registry.register(Arc::new(AwsNetworkSgIngressAuthorize));
    registry.register(Arc::new(AwsNetworkSgIngressRevoke));
    registry.register(Arc::new(AwsNetworkRouteCreate));
    registry.register(Arc::new(AwsNetworkRouteDelete));
    registry.register(Arc::new(AwsNetworkPeeringCreate));
    registry.register(Arc::new(AwsNetworkPeeringAccept));
    registry.register(Arc::new(AwsNetworkPeeringDelete));
    registry.register(Arc::new(AwsNetworkEndpointCreate));
    registry.register(Arc::new(AwsNetworkEndpointDelete));
    registry.register(Arc::new(AwsNetworkTagCreate));
}

fn region_of(args: &serde_json::Value, profile: &oscar_identity::Profile) -> String {
    arg_str(args, "region")
        .map(|s| s.to_string())
        .or_else(|| profile.default_region.clone())
        .unwrap_or_else(|| "us-east-1".into())
}

fn write_meta(
    id: &str,
    name: &str,
    description: &str,
    tags: &[&str],
    schema: serde_json::Value,
) -> ToolMeta {
    let mut t: Vec<String> = tags.iter().map(|s| (*s).to_string()).collect();
    if !t.iter().any(|x| x == "write") {
        t.push("write".into());
    }
    ToolMeta {
        id: id.into(),
        name: name.into(),
        description: format!(
            "{description} **Requires session mode readwrite** (blocked in readonly)."
        ),
        domain: ToolDomain::Network,
        clouds: vec![Cloud::Aws],
        capability: Capability::Write,
        tags: t,
        input_schema: schema,
        output_schema: None,
    }
}

struct AwsNetworkVpcCreate;
struct AwsNetworkVpcDelete;
struct AwsNetworkSubnetCreate;
struct AwsNetworkSubnetDelete;
struct AwsNetworkSgCreate;
struct AwsNetworkSgDelete;
struct AwsNetworkSgIngressAuthorize;
struct AwsNetworkSgIngressRevoke;
struct AwsNetworkRouteCreate;
struct AwsNetworkRouteDelete;
struct AwsNetworkPeeringCreate;
struct AwsNetworkPeeringAccept;
struct AwsNetworkPeeringDelete;
struct AwsNetworkEndpointCreate;
struct AwsNetworkEndpointDelete;
struct AwsNetworkTagCreate;

#[async_trait]
impl Tool for AwsNetworkVpcCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.vpc.create",
                "Create VPC",
                "Create an AWS VPC (ec2 create-vpc).",
                &["vpc", "create", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "cidr_block": { "type": "string", "description": "e.g. 10.0.0.0/16" },
                        "name": { "type": "string", "description": "Name tag" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["cidr_block"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let cidr = match require_str(&args, "cidr_block") {
            Ok(c) => c,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        let cmd = [
            "ec2",
            "create-vpc",
            "--cidr-block",
            &cidr,
            "--region",
            &region,
            "--output",
            "json",
        ];
        match aws_json(profile, &cmd).await {
            Ok(v) => {
                let vpc_id = v
                    .pointer("/Vpc/VpcId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Some(name) = arg_str(&args, "name") {
                    if !vpc_id.is_empty() {
                        let tag = format!("ResourceType=vpc,Tags=[{{Key=Name,Value={name}}}]");
                        let _ = aws_json(
                            profile,
                            &[
                                "ec2",
                                "create-tags",
                                "--resources",
                                &vpc_id,
                                "--tags",
                                &format!("Key=Name,Value={name}"),
                                "--region",
                                &region,
                                "--output",
                                "json",
                            ],
                        )
                        .await;
                        let _ = tag;
                    }
                }
                ToolResult::success(
                    format!("Created VPC {vpc_id} ({cidr})"),
                    json!({"action":"create","resource":"vpc","vpc_id":vpc_id,"cidr_block":cidr,"raw":v}),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkVpcDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.vpc.delete",
                "Delete VPC",
                "Delete an empty AWS VPC (ec2 delete-vpc). Fails if dependencies remain.",
                &["vpc", "delete", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let vpc_id = match require_str(&args, "vpc_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "delete-vpc",
                "--vpc-id",
                &vpc_id,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("Deleted VPC {vpc_id}"),
                json!({"action":"delete","resource":"vpc","vpc_id":vpc_id,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkSubnetCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.subnet.create",
                "Create subnet",
                "Create an AWS subnet in a VPC (ec2 create-subnet).",
                &["subnet", "create", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_id": { "type": "string" },
                        "cidr_block": { "type": "string" },
                        "availability_zone": { "type": "string" },
                        "name": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_id", "cidr_block"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let vpc_id = match require_str(&args, "vpc_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cidr = match require_str(&args, "cidr_block") {
            Ok(c) => c,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        let mut owned = vec![
            "ec2".into(),
            "create-subnet".into(),
            "--vpc-id".into(),
            vpc_id.clone(),
            "--cidr-block".into(),
            cidr.clone(),
            "--region".into(),
            region.clone(),
            "--output".into(),
            "json".into(),
        ];
        if let Some(az) = arg_str(&args, "availability_zone") {
            owned.push("--availability-zone".into());
            owned.push(az.into());
        }
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        match aws_json(profile, &refs).await {
            Ok(v) => {
                let subnet_id = v
                    .pointer("/Subnet/SubnetId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Some(name) = arg_str(&args, "name") {
                    if !subnet_id.is_empty() {
                        let _ = aws_json(
                            profile,
                            &[
                                "ec2",
                                "create-tags",
                                "--resources",
                                &subnet_id,
                                "--tags",
                                &format!("Key=Name,Value={name}"),
                                "--region",
                                &region,
                                "--output",
                                "json",
                            ],
                        )
                        .await;
                    }
                }
                ToolResult::success(
                    format!("Created subnet {subnet_id} ({cidr}) in {vpc_id}"),
                    json!({"action":"create","resource":"subnet","subnet_id":subnet_id,"vpc_id":vpc_id,"cidr_block":cidr,"raw":v}),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkSubnetDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.subnet.delete",
                "Delete subnet",
                "Delete an AWS subnet (ec2 delete-subnet).",
                &["subnet", "delete", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "subnet_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["subnet_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let subnet_id = match require_str(&args, "subnet_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "delete-subnet",
                "--subnet-id",
                &subnet_id,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("Deleted subnet {subnet_id}"),
                json!({"action":"delete","resource":"subnet","subnet_id":subnet_id,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkSgCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.sg.create",
                "Create security group",
                "Create an EC2 security group (ec2 create-security-group).",
                &["security-group", "sg", "create", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_id": { "type": "string" },
                        "group_name": { "type": "string" },
                        "description": { "type": "string", "default": "managed by oscar" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_id", "group_name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let vpc_id = match require_str(&args, "vpc_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = match require_str(&args, "group_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let desc = arg_str(&args, "description").unwrap_or("managed by oscar");
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "create-security-group",
                "--group-name",
                &name,
                "--description",
                desc,
                "--vpc-id",
                &vpc_id,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => {
                let gid = v
                    .get("GroupId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                ToolResult::success(
                    format!("Created security group {gid} ({name})"),
                    json!({"action":"create","resource":"security_group","group_id":gid,"group_name":name,"vpc_id":vpc_id,"raw":v}),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkSgDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.sg.delete",
                "Delete security group",
                "Delete an EC2 security group (ec2 delete-security-group).",
                &["security-group", "sg", "delete", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["group_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let group_id = match require_str(&args, "group_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "delete-security-group",
                "--group-id",
                &group_id,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("Deleted security group {group_id}"),
                json!({"action":"delete","resource":"security_group","group_id":group_id,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkSgIngressAuthorize {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.sg.ingress.authorize",
                "Authorize SG ingress rule",
                "Add an inbound rule to a security group (ec2 authorize-security-group-ingress). Prefer least-privilege CIDR/port.",
                &["security-group", "sg", "ingress", "authorize", "create", "network", "firewall"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_id": { "type": "string" },
                        "protocol": { "type": "string", "default": "tcp" },
                        "from_port": { "type": "integer" },
                        "to_port": { "type": "integer" },
                        "cidr": { "type": "string", "description": "IPv4 CIDR e.g. 10.0.0.0/8" },
                        "source_group_id": { "type": "string", "description": "Optional SG id instead of CIDR" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["group_id", "from_port", "to_port"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let group_id = match require_str(&args, "group_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let protocol = arg_str(&args, "protocol").unwrap_or("tcp");
        let from = args.get("from_port").and_then(|v| v.as_i64()).unwrap_or(0);
        let to = args.get("to_port").and_then(|v| v.as_i64()).unwrap_or(from);
        let region = region_of(&args, profile);
        let from_s = from.to_string();
        let to_s = to.to_string();
        let mut owned = vec![
            "ec2".into(),
            "authorize-security-group-ingress".into(),
            "--group-id".into(),
            group_id.clone(),
            "--protocol".into(),
            protocol.into(),
            "--port".into(),
            if from == to {
                from_s.clone()
            } else {
                format!("{from}-{to}")
            },
            "--region".into(),
            region.clone(),
            "--output".into(),
            "json".into(),
        ];
        // AWS CLI --port works for single; for range use IpPermissions JSON for robustness
        if let Some(sg) = arg_str(&args, "source_group_id") {
            owned.push("--source-group".into());
            owned.push(sg.into());
        } else if let Some(cidr) = arg_str(&args, "cidr") {
            owned.push("--cidr".into());
            owned.push(cidr.into());
        } else {
            return ToolResult::error("cidr or source_group_id is required");
        }
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        match aws_json(profile, &refs).await {
            Ok(v) => ToolResult::success(
                format!("Authorized ingress on {group_id} {protocol}/{from}-{to}"),
                json!({"action":"authorize_ingress","group_id":group_id,"protocol":protocol,"from_port":from,"to_port":to,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkSgIngressRevoke {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.sg.ingress.revoke",
                "Revoke SG ingress rule",
                "Remove an inbound rule from a security group (ec2 revoke-security-group-ingress).",
                &["security-group", "sg", "ingress", "revoke", "delete", "network", "firewall"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_id": { "type": "string" },
                        "protocol": { "type": "string", "default": "tcp" },
                        "from_port": { "type": "integer" },
                        "to_port": { "type": "integer" },
                        "cidr": { "type": "string" },
                        "source_group_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["group_id", "from_port", "to_port"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let group_id = match require_str(&args, "group_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let protocol = arg_str(&args, "protocol").unwrap_or("tcp");
        let from = args.get("from_port").and_then(|v| v.as_i64()).unwrap_or(0);
        let to = args.get("to_port").and_then(|v| v.as_i64()).unwrap_or(from);
        let region = region_of(&args, profile);
        let port = if from == to {
            from.to_string()
        } else {
            format!("{from}-{to}")
        };
        let mut owned = vec![
            "ec2".into(),
            "revoke-security-group-ingress".into(),
            "--group-id".into(),
            group_id.clone(),
            "--protocol".into(),
            protocol.into(),
            "--port".into(),
            port,
            "--region".into(),
            region,
            "--output".into(),
            "json".into(),
        ];
        if let Some(sg) = arg_str(&args, "source_group_id") {
            owned.push("--source-group".into());
            owned.push(sg.into());
        } else if let Some(cidr) = arg_str(&args, "cidr") {
            owned.push("--cidr".into());
            owned.push(cidr.into());
        } else {
            return ToolResult::error("cidr or source_group_id is required");
        }
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        match aws_json(profile, &refs).await {
            Ok(v) => ToolResult::success(
                format!("Revoked ingress on {group_id} {protocol}/{from}-{to}"),
                json!({"action":"revoke_ingress","group_id":group_id,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkRouteCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.route.create",
                "Create route",
                "Create a route in a route table (ec2 create-route). Provide exactly one target (gateway_id, nat_gateway_id, transit_gateway_id, or vpc_peering_connection_id).",
                &["route", "create", "network", "route-table"],
                json!({
                    "type": "object",
                    "properties": {
                        "route_table_id": { "type": "string" },
                        "destination_cidr_block": { "type": "string" },
                        "gateway_id": { "type": "string" },
                        "nat_gateway_id": { "type": "string" },
                        "transit_gateway_id": { "type": "string" },
                        "vpc_peering_connection_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["route_table_id", "destination_cidr_block"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rtb = match require_str(&args, "route_table_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let dest = match require_str(&args, "destination_cidr_block") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        let mut owned = vec![
            "ec2".into(),
            "create-route".into(),
            "--route-table-id".into(),
            rtb.clone(),
            "--destination-cidr-block".into(),
            dest.clone(),
            "--region".into(),
            region,
            "--output".into(),
            "json".into(),
        ];
        let target = if let Some(g) = arg_str(&args, "gateway_id") {
            owned.push("--gateway-id".into());
            owned.push(g.into());
            "gateway"
        } else if let Some(g) = arg_str(&args, "nat_gateway_id") {
            owned.push("--nat-gateway-id".into());
            owned.push(g.into());
            "nat"
        } else if let Some(g) = arg_str(&args, "transit_gateway_id") {
            owned.push("--transit-gateway-id".into());
            owned.push(g.into());
            "tgw"
        } else if let Some(g) = arg_str(&args, "vpc_peering_connection_id") {
            owned.push("--vpc-peering-connection-id".into());
            owned.push(g.into());
            "pcx"
        } else {
            return ToolResult::error(
                "one of gateway_id, nat_gateway_id, transit_gateway_id, vpc_peering_connection_id is required",
            );
        };
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        match aws_json(profile, &refs).await {
            Ok(v) => ToolResult::success(
                format!("Created route {dest} via {target} on {rtb}"),
                json!({"action":"create","resource":"route","route_table_id":rtb,"destination":dest,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkRouteDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.route.delete",
                "Delete route",
                "Delete a route from a route table (ec2 delete-route).",
                &["route", "delete", "network", "route-table"],
                json!({
                    "type": "object",
                    "properties": {
                        "route_table_id": { "type": "string" },
                        "destination_cidr_block": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["route_table_id", "destination_cidr_block"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rtb = match require_str(&args, "route_table_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let dest = match require_str(&args, "destination_cidr_block") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "delete-route",
                "--route-table-id",
                &rtb,
                "--destination-cidr-block",
                &dest,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("Deleted route {dest} from {rtb}"),
                json!({"action":"delete","resource":"route","route_table_id":rtb,"destination":dest,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkPeeringCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.peering.create",
                "Create VPC peering",
                "Create a VPC peering connection (ec2 create-vpc-peering-connection). Accepter may need accept.",
                &["peering", "create", "network", "vpc"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_id": { "type": "string", "description": "Requester VPC" },
                        "peer_vpc_id": { "type": "string" },
                        "peer_region": { "type": "string" },
                        "peer_owner_id": { "type": "string" },
                        "name": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_id", "peer_vpc_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let vpc_id = match require_str(&args, "vpc_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let peer = match require_str(&args, "peer_vpc_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        let mut owned = vec![
            "ec2".into(),
            "create-vpc-peering-connection".into(),
            "--vpc-id".into(),
            vpc_id.clone(),
            "--peer-vpc-id".into(),
            peer.clone(),
            "--region".into(),
            region.clone(),
            "--output".into(),
            "json".into(),
        ];
        if let Some(pr) = arg_str(&args, "peer_region") {
            owned.push("--peer-region".into());
            owned.push(pr.into());
        }
        if let Some(po) = arg_str(&args, "peer_owner_id") {
            owned.push("--peer-owner-id".into());
            owned.push(po.into());
        }
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        match aws_json(profile, &refs).await {
            Ok(v) => {
                let pcx = v
                    .pointer("/VpcPeeringConnection/VpcPeeringConnectionId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Some(name) = arg_str(&args, "name") {
                    if !pcx.is_empty() {
                        let _ = aws_json(
                            profile,
                            &[
                                "ec2",
                                "create-tags",
                                "--resources",
                                &pcx,
                                "--tags",
                                &format!("Key=Name,Value={name}"),
                                "--region",
                                &region,
                                "--output",
                                "json",
                            ],
                        )
                        .await;
                    }
                }
                ToolResult::success(
                    format!("Created peering {pcx} ({vpc_id} ↔ {peer}); may need accept"),
                    json!({"action":"create","resource":"peering","pcx_id":pcx,"vpc_id":vpc_id,"peer_vpc_id":peer,"raw":v}),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkPeeringAccept {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.peering.accept",
                "Accept VPC peering",
                "Accept a VPC peering connection (ec2 accept-vpc-peering-connection).",
                &["peering", "accept", "write", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_peering_connection_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_peering_connection_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let pcx = match require_str(&args, "vpc_peering_connection_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "accept-vpc-peering-connection",
                "--vpc-peering-connection-id",
                &pcx,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("Accepted peering {pcx}"),
                json!({"action":"accept","resource":"peering","pcx_id":pcx,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkPeeringDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.peering.delete",
                "Delete VPC peering",
                "Delete a VPC peering connection (ec2 delete-vpc-peering-connection).",
                &["peering", "delete", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_peering_connection_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_peering_connection_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let pcx = match require_str(&args, "vpc_peering_connection_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "delete-vpc-peering-connection",
                "--vpc-peering-connection-id",
                &pcx,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("Deleted peering {pcx}"),
                json!({"action":"delete","resource":"peering","pcx_id":pcx,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkEndpointCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.endpoint.create",
                "Create VPC endpoint",
                "Create a VPC endpoint / PrivateLink interface or gateway (ec2 create-vpc-endpoint).",
                &["endpoint", "privatelink", "create", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_id": { "type": "string" },
                        "service_name": { "type": "string", "description": "e.g. com.amazonaws.us-east-1.s3" },
                        "vpc_endpoint_type": { "type": "string", "default": "Gateway", "description": "Gateway | Interface" },
                        "subnet_ids": { "type": "array", "items": { "type": "string" }, "description": "Required for Interface" },
                        "security_group_ids": { "type": "array", "items": { "type": "string" } },
                        "route_table_ids": { "type": "array", "items": { "type": "string" }, "description": "For Gateway endpoints" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_id", "service_name"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let vpc_id = match require_str(&args, "vpc_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let service = match require_str(&args, "service_name") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ep_type = arg_str(&args, "vpc_endpoint_type").unwrap_or("Gateway");
        let region = region_of(&args, profile);
        let mut owned = vec![
            "ec2".into(),
            "create-vpc-endpoint".into(),
            "--vpc-id".into(),
            vpc_id.clone(),
            "--service-name".into(),
            service.clone(),
            "--vpc-endpoint-type".into(),
            ep_type.into(),
            "--region".into(),
            region,
            "--output".into(),
            "json".into(),
        ];
        if let Some(arr) = args.get("subnet_ids").and_then(|v| v.as_array()) {
            let ids: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
            if !ids.is_empty() {
                owned.push("--subnet-ids".into());
                owned.push(ids.join(" "));
            }
        }
        if let Some(arr) = args.get("security_group_ids").and_then(|v| v.as_array()) {
            let ids: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
            if !ids.is_empty() {
                owned.push("--security-group-ids".into());
                owned.push(ids.join(" "));
            }
        }
        if let Some(arr) = args.get("route_table_ids").and_then(|v| v.as_array()) {
            let ids: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
            if !ids.is_empty() {
                owned.push("--route-table-ids".into());
                owned.push(ids.join(" "));
            }
        }
        // Fix: aws expects multiple values as separate args not joined string
        // Rebuild properly for subnet-ids
        let mut fixed: Vec<String> = vec![
            "ec2".into(),
            "create-vpc-endpoint".into(),
            "--vpc-id".into(),
            vpc_id.clone(),
            "--service-name".into(),
            service.clone(),
            "--vpc-endpoint-type".into(),
            ep_type.into(),
            "--region".into(),
            region_of(&args, profile),
            "--output".into(),
            "json".into(),
        ];
        if let Some(arr) = args.get("subnet_ids").and_then(|v| v.as_array()) {
            fixed.push("--subnet-ids".into());
            for x in arr.iter().filter_map(|x| x.as_str()) {
                fixed.push(x.into());
            }
        }
        if let Some(arr) = args.get("security_group_ids").and_then(|v| v.as_array()) {
            fixed.push("--security-group-ids".into());
            for x in arr.iter().filter_map(|x| x.as_str()) {
                fixed.push(x.into());
            }
        }
        if let Some(arr) = args.get("route_table_ids").and_then(|v| v.as_array()) {
            fixed.push("--route-table-ids".into());
            for x in arr.iter().filter_map(|x| x.as_str()) {
                fixed.push(x.into());
            }
        }
        let _ = owned;
        let refs: Vec<&str> = fixed.iter().map(|s| s.as_str()).collect();
        match aws_json(profile, &refs).await {
            Ok(v) => {
                let id = v
                    .pointer("/VpcEndpoint/VpcEndpointId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                ToolResult::success(
                    format!("Created VPC endpoint {id} ({service})"),
                    json!({"action":"create","resource":"vpc_endpoint","vpc_endpoint_id":id,"service_name":service,"raw":v}),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkEndpointDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.endpoint.delete",
                "Delete VPC endpoint",
                "Delete a VPC endpoint (ec2 delete-vpc-endpoints).",
                &["endpoint", "privatelink", "delete", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "vpc_endpoint_id": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["vpc_endpoint_id"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let id = match require_str(&args, "vpc_endpoint_id") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let region = region_of(&args, profile);
        match aws_json(
            profile,
            &[
                "ec2",
                "delete-vpc-endpoints",
                "--vpc-endpoint-ids",
                &id,
                "--region",
                &region,
                "--output",
                "json",
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("Deleted VPC endpoint {id}"),
                json!({"action":"delete","resource":"vpc_endpoint","vpc_endpoint_id":id,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsNetworkTagCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            write_meta(
                "aws.network.tag.create",
                "Tag EC2 network resources",
                "Create/overwrite tags on VPC/subnet/SG/etc (ec2 create-tags).",
                &["tag", "create", "network"],
                json!({
                    "type": "object",
                    "properties": {
                        "resource_ids": { "type": "array", "items": { "type": "string" } },
                        "tags": {
                            "type": "object",
                            "additionalProperties": { "type": "string" },
                            "description": "Key-value tags e.g. {\"Name\":\"app-vpc\"}"
                        },
                        "profile_id": { "type": "string" },
                        "region": { "type": "string" }
                    },
                    "required": ["resource_ids", "tags"]
                }),
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match first_aws_profile_ctx(ctx, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ids: Vec<String> = args
            .get("resource_ids")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if ids.is_empty() {
            return ToolResult::error("resource_ids required");
        }
        let tags_obj = args.get("tags").and_then(|v| v.as_object());
        let Some(tags_obj) = tags_obj else {
            return ToolResult::error("tags object required");
        };
        let region = region_of(&args, profile);
        let mut owned = vec![
            "ec2".into(),
            "create-tags".into(),
            "--resources".into(),
        ];
        owned.extend(ids.clone());
        owned.push("--tags".into());
        for (k, v) in tags_obj {
            if let Some(vs) = v.as_str() {
                owned.push(format!("Key={k},Value={vs}"));
            }
        }
        owned.push("--region".into());
        owned.push(region);
        owned.push("--output".into());
        owned.push("json".into());
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        match aws_json(profile, &refs).await {
            Ok(v) => ToolResult::success(
                format!("Tagged {} resource(s)", ids.len()),
                json!({"action":"tag","resource_ids":ids,"raw":v}),
            ),
            Err(e) => e,
        }
    }
}
