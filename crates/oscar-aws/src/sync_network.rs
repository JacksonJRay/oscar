//! AWS EC2 + Lambda + connectivity fabric → unified [`NetworkInventory`] via CLI.

use crate::map_network::map_aws_network_full;
use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::{
    auth_request_from_error, resolve_aws_process_creds, BinaryInventory, Profile,
};
use oscar_tools::inventory::NetworkInventory;
use oscar_tools::sync::{run_json_command_with_env, which_ok, NetworkInventorySource};

pub struct AwsNetworkSource;

#[async_trait]
impl NetworkInventorySource for AwsNetworkSource {
    fn cloud(&self) -> Cloud {
        Cloud::Aws
    }

    async fn sync_network(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<NetworkInventory> {
        if !which_ok("aws").await {
            return Err(OscarError::Tool(
                "AWS CLI (`aws`) not found on PATH — install AWS CLI v2 so oscar can invoke it"
                    .into(),
            ));
        }

        let binaries = BinaryInventory::detect();
        let creds = resolve_aws_process_creds(profile, &binaries).map_err(|a| {
            OscarError::AuthRequired(format!(
                "{} | hints: {}",
                a.reason,
                a.hint_commands.join(" ; ")
            ))
        })?;
        let env: Vec<(String, String)> = creds.env.into_iter().collect();

        let region = region
            .map(|s| s.to_string())
            .or_else(|| profile.default_region.clone())
            .unwrap_or_else(|| "us-east-1".into());

        let vpcs = ec2_json(&env, &region, "describe-vpcs")
            .await
            .map_err(|e| map_err(profile, e))?;
        let subnets = ec2_json(&env, &region, "describe-subnets")
            .await
            .map_err(|e| map_err(profile, e))?;
        // Best-effort fabric — failures do not fail whole sync
        let enis = ec2_json(&env, &region, "describe-network-interfaces")
            .await
            .ok();
        let eips = ec2_json(&env, &region, "describe-addresses").await.ok();
        let sgs = ec2_json(&env, &region, "describe-security-groups")
            .await
            .ok();
        let nacls = ec2_json(&env, &region, "describe-network-acls")
            .await
            .ok();
        let rts = ec2_json(&env, &region, "describe-route-tables")
            .await
            .ok();
        let lambdas = lambda_list_functions(&env, &region).await.ok();
        let peerings = ec2_json(&env, &region, "describe-vpc-peering-connections")
            .await
            .ok();
        let tgws = ec2_json(&env, &region, "describe-transit-gateways")
            .await
            .ok();
        let vpns = ec2_json(&env, &region, "describe-vpn-connections")
            .await
            .ok();
        let endpoints = ec2_json(&env, &region, "describe-vpc-endpoints")
            .await
            .ok();
        let nats = ec2_json(&env, &region, "describe-nat-gateways").await.ok();
        let igws = ec2_json(&env, &region, "describe-internet-gateways")
            .await
            .ok();
        let prefix_lists = ec2_json(&env, &region, "describe-managed-prefix-lists")
            .await
            .ok();
        let dx = dx_connections(&env, &region).await.ok();

        Ok(map_aws_network_full(
            &profile.id,
            Some(region),
            &vpcs,
            &subnets,
            enis.as_ref(),
            eips.as_ref(),
            sgs.as_ref(),
            nacls.as_ref(),
            rts.as_ref(),
            lambdas.as_ref(),
            peerings.as_ref(),
            tgws.as_ref(),
            vpns.as_ref(),
            endpoints.as_ref(),
            nats.as_ref(),
            igws.as_ref(),
            prefix_lists.as_ref(),
            dx.as_ref(),
        ))
    }
}

fn map_err(profile: &Profile, e: OscarError) -> OscarError {
    let text = e.to_string();
    if let Some(a) = auth_request_from_error(Cloud::Aws, Some(&profile.id), &text) {
        return OscarError::AuthRequired(format!(
            "{} | {}",
            a.reason,
            a.hint_commands.join(" ; ")
        ));
    }
    e
}

async fn ec2_json(
    env: &[(String, String)],
    region: &str,
    op: &str,
) -> OscarResult<serde_json::Value> {
    let args = ["ec2", op, "--region", region, "--output", "json"];
    run_json_command_with_env("aws", &args, env).await
}

async fn lambda_list_functions(
    env: &[(String, String)],
    region: &str,
) -> OscarResult<serde_json::Value> {
    let args = [
        "lambda",
        "list-functions",
        "--region",
        region,
        "--output",
        "json",
    ];
    run_json_command_with_env("aws", &args, env).await
}

async fn dx_connections(
    env: &[(String, String)],
    region: &str,
) -> OscarResult<serde_json::Value> {
    let args = [
        "directconnect",
        "describe-connections",
        "--region",
        region,
        "--output",
        "json",
    ];
    run_json_command_with_env("aws", &args, env).await
}
