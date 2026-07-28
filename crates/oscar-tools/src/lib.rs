//! Tool inventory + Code Mode surface (`tools.search` / `tools.execute`).

pub mod catalog;
pub mod helpers;
pub mod inventory;
pub mod mesh;
pub mod multi;
pub mod node;
pub mod plugins;
mod pattern_schema;
mod registry;
mod scan;
pub mod sync;
mod traits;

pub use helpers::{
    auth_for, load_dns_cache, load_dns_resolver_cache, load_network_cache, profiles_for_cloud,
    resolve_profiles,
};
pub use catalog::{agent_tools_primer, tools_execute_description, tools_search_description};
pub use mesh::register_mesh;
pub use multi::register_multi;
pub use node::register_node;
pub use plugins::{example_plugin_toml, register_plugins};
pub use pattern_schema::{
    default_mode_label, discovery_blurb, discovery_tool_result, pattern_properties, to_tool_result,
    DiscoveryReady,
};
pub use registry::{
    mode_denied_message, parse_capability, parse_cloud, parse_domain, ToolRegistry,
    NATIVE_ACCOUNT_TOOL_IDS,
};
pub use scan::{
    scan_dns_inventory, scan_dns_resolver_inventory, scan_k8s_inventory, scan_network_inventory,
    PublicDnsProbe,
};
pub use sync::{
    command_on_path, ensure_dns_inventory, ensure_network_inventory, run_json_command,
    run_json_command_with_env, run_text_command, which_ok, write_dns_cache,
    write_dns_resolver_cache, write_k8s_cache, write_network_cache, DnsInventorySource, DnsSyncOpts,
    K8sInventorySource, NetworkInventorySource,
};
pub use traits::{Tool, ToolContext, ToolMeta, ToolResult};
