use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use oscar_agent::{Agent, AgentOptions, CompactConfig, ContextManager};
use oscar_core::config::{InstallBinariesPolicy, OscarConfig, Paths, ToolsSettings};
use oscar_core::events::AgentEvent;
use oscar_core::{ExecutionMode, ThinkingConfig};
use oscar_identity::{
    assume_role_into_profile, critical_csp_binaries, load_provider_api_key, plan_install,
    run_install_commands, store_aws_long_lived, store_aws_short_lived, store_provider_api_key,
    validate_aws, BinaryInventory, KeychainStore, Profile, ProfileStore,
};
use oscar_providers::{create_provider, inject_headless_llm_key, list_provider_ids};
use oscar_tools::sync::{DnsInventorySource, NetworkInventorySource};
use oscar_aws::DnsResolverInventorySource;
use oscar_azure::AzureDnsResolverInventorySource;
use oscar_gcp::GcpDnsResolverInventorySource;
use oscar_tools::{
    load_dns_cache, load_network_cache, write_dns_cache, write_network_cache, DnsSyncOpts,
    ToolRegistry,
};
use oscar_tui::{run_tui, App, AppConfig, ToolCatalogEntry};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "oscar",
    about = "oscar — multi-cloud native dredger (agentic multi-cloud + k8s troubleshooting)",
    long_about = "\
oscar is an agentic CLI for multi-cloud and Kubernetes troubleshooting (AWS, GCP, Azure, k8s).

MODES
  • Default: full-screen Ratatui chat with a multi-cloud engineering agent
  • Headless: oscar ask \"…\"  /  oscar ask --stream \"…\"

AGENT TOOLS (Code Mode)
  The model only sees two tools: tools_search and tools_execute.
  tools_search returns inventory entries with full descriptions + input_schema.
  tools_execute runs first-class tools (DNS/network/path/k8s). See: oscar tools catalog

AUTH (secrets never go to the model)
  LLM keys: oscar auth provider-key  or  --llm-api-key (stored in OS keychain)
  Built-in providers do NOT read XAI_API_KEY/OPENAI_API_KEY unless provider.api_key_env is set (custom only).
  Cloud: keychain keys, short-lived STS/session, or detected binary sessions (aws/gcloud/az/kubectl).
  Secure TUI bar for paste; chat transcript never includes raw secrets.

EXAMPLES
  oscar auth provider-key --provider xai --key-file ~/.oscar-xai.key
  oscar auth aws-sso-login --profile aws-default
  oscar inventory sync --cloud aws --kind network --region us-east-1
  oscar ask --provider xai --llm-api-key \"…\" \"where is 10.0.4?\"
  oscar tools search \"dns pattern\"
  oscar tools catalog
",
    version,
    propagate_version = true,
    after_help = "Docs: oscar auth | oscar identities | oscar settings | oscar skills | oscar access | oscar tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Session mode: readonly (default) or readwrite
    #[arg(long, global = true, env = "OSCAR_MODE", long_help = "Hard tool gate: readonly blocks write-capability tools even if cloud credentials allow writes.")]
    mode: Option<String>,

    /// LLM provider id: xai | openai | anthropic | opencode-zen | opencode-go | custom
    #[arg(long, global = true, env = "OSCAR_PROVIDER", long_help = "Select LLM backend. Keys come from OS keychain (oscar auth provider-key), not ambient env, unless provider.api_key_env is configured for a custom provider.")]
    provider: Option<String>,

    /// Model id for the selected provider
    #[arg(long, global = true, env = "OSCAR_MODEL")]
    model: Option<String>,

    /// Enable model thinking/reasoning channel
    #[arg(long, global = true, value_enum)]
    thinking: Option<OnOff>,

    /// Headless: write LLM API key into OS keychain for the selected provider (never echoed to agent chat)
    #[arg(long, global = true, long_help = "Stores the key in the OS keychain under oscar/provider/<id>. Does not print the key. Prefer --key-file via `oscar auth provider-key` to avoid shell history.")]
    llm_api_key: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Headless one-shot agent question (no TUI)
    #[command(long_about = "Run one agent turn without the TUI. Streams tokens to stdout unless --stream emits NDJSON AgentEvents. LLM key via --llm-api-key is stored in keychain and never printed.")]
    Ask {
        /// User question / prompt for the agent
        prompt: String,
        /// Stream NDJSON AgentEvents (content, tools, auth, context) to stdout
        #[arg(long)]
        stream: bool,
        /// Final machine-readable envelope (e.g. json)
        #[arg(short, long, value_name = "FORMAT")]
        output: Option<String>,
        /// Store LLM API key in OS keychain for this provider (not ambient XAI_/OPENAI_ env)
        #[arg(long)]
        llm_api_key: Option<String>,
    },
    /// Show or set execution mode (readonly | readwrite)
    Mode {
        #[command(subcommand)]
        action: Option<ModeCmd>,
    },
    /// Manage cloud profile metadata (secrets stay in keychain)
    Profiles {
        #[command(subcommand)]
        action: ProfilesCmd,
    },
    /// List/search first-class tools and agent Code Mode catalog
    #[command(long_about = "Inspect the tool inventory the agent searches via tools_search. Use `catalog` for the full Code Mode documentation the model receives.")]
    Tools {
        #[command(subcommand)]
        action: ToolsCmd,
    },
    /// List or set LLM provider (keys via auth provider-key)
    #[command(long_about = "Provider selection for the agent LLM. Built-in: xai, openai, anthropic (compat gateway), opencode-zen, opencode-go. Custom OpenAI-compatible endpoints: set provider id + base_url in config and api_key_env only if you intentionally want env-based custom keys.")]
    Provider {
        #[command(subcommand)]
        action: Option<ProviderCmd>,
    },
    /// Compact the current/last saved session messages on disk
    Compact,
    /// List / show / delete / resume saved chat sessions (history)
    #[command(long_about = "Grok Build–style chat history under ~/.config/oscar/sessions/.\n\n\
In TUI: history auto-saves after each turn · /history · /new · /resume <id>\n\n\
CLI:\n  oscar sessions list\n  oscar sessions show <id>\n  oscar sessions delete <id>\n  oscar sessions resume <id>   # open TUI on that chat")]
    Sessions {
        #[command(subcommand)]
        action: Option<SessionsCmd>,
    },
    /// Sync CSP inventories into unified DnsInventory / NetworkInventory caches
    #[command(long_about = "Live-sync cloud inventories used by pattern-search tools. Format is always unified (not CSP-raw). Requires working cloud auth (binary session or keychain).")]
    Inventory {
        #[command(subcommand)]
        action: InventoryCmd,
    },
    /// Credentials: LLM keychain, cloud SSO/short-lived keys, binary sessions
    #[command(long_about = "Manage authentication. Secrets go to the OS keychain or interactive SSO subprocesses. The agent model never receives raw keys—only auth_required guidance and redacted tool results.")]
    Auth {
        #[command(subcommand)]
        action: AuthCmd,
    },
    /// List detected CSP/k8s binaries on PATH; plan/install missing CLIs
    #[command(long_about = "Inspect host CLIs used by first-class tools. Use `plan` to see package-manager commands; `install --yes` runs them after you approve (admin/sudo). Policy lives in `oscar settings install-policy`.")]
    Binaries {
        #[command(subcommand)]
        action: Option<BinariesCmd>,
    },
    /// User settings menu: disable tools/clouds, binary install policy
    #[command(long_about = "Grok-Build-style settings for first-class tools.\n\n\
• disable-tool / enable-tool — omit tools from tools_search (e.g. AWS-only shops disable GCP/Azure tools)\n\
• disable-cloud / enable-cloud — hide a whole cloud from search/execute\n\
• install-policy off|recommend|ask-admin|install-all — whether the agent only suggests installs, or may request admin elevation\n\
• menu — interactive text menu\n\n\
Agent never runs sudo without explicit `approve install` (or oscar binaries install --yes).")]
    Settings {
        #[command(subcommand)]
        action: Option<SettingsCmd>,
    },
    /// List and inspect skills (prompt playbooks that steer outside the harness)
    #[command(long_about = "Skills are SKILL.md packages (like Grok Build skills) that steer the agent for specialized tasks without rewriting the core harness.\n\n\
Locations (priority): ./.oscar/skills/  →  ~/.config/oscar/skills/  →  builtin\n\n\
In chat: /skills  |  /skill least-privilege-iam\n\
Agent tools: system.skills.list  |  system.skills.get")]
    Skills {
        #[command(subcommand)]
        action: Option<SkillsCmd>,
    },
    /// Show configured identities / access and whether credentials are still valid
    #[command(long_about = "Lists oscar profiles, ambient CLI sessions (aws/gcloud/az), LLM keychain keys, and kubectl contexts.\n\
Shows auth source (keychain, short_lived, binary_session) and live validity — never prints secret values.\n\n\
TUI: /identities or Ctrl+I")]
    Identities {
        #[command(subcommand)]
        action: Option<IdentitiesCmd>,
    },
    /// Configure MCP servers (tools mount as first-class Code Mode inventory)
    #[command(long_about = "Model Context Protocol servers extend oscar without dumping tools into the system prompt.\n\
Each remote tool is registered as `mcp.<server>.<tool>` and discovered only via tools_search / tools_execute.\n\n\
Config: ~/.config/oscar/config.toml under [mcp] and [mcp.servers.<name>]\n\n\
Examples:\n  oscar mcp add filesystem -- npx -y @modelcontextprotocol/server-filesystem /tmp\n  oscar mcp list\n  oscar mcp doctor\n  oscar mcp tools\n  oscar tools search mcp")]
    Mcp {
        #[command(subcommand)]
        action: Option<McpCmd>,
    },
    /// Manage / troubleshoot / test users, roles, permissions (IAM) across CSPs
    #[command(long_about = "Identity and access management for AWS IAM, GCP IAM, and Azure RBAC.\n\n\
List/search users & roles, create/delete principals, attach/detach policies, add/remove bindings,\n\
and simulate/test permissions. Write mutations require --mode readwrite (or oscar mode set readwrite).\n\n\
Examples:\n  oscar access whoami --cloud aws\n  oscar access users list --cloud aws\n  oscar access search admin --cloud aws\n  oscar access test --cloud aws --action s3:GetObject --resource arn:aws:s3:::bucket/*\n  oscar access simulate --cloud aws --principal-arn arn:aws:iam::…:user/x --action ec2:DescribeInstances\n  oscar mode set readwrite && oscar access user create --cloud aws --name oscar-tmp\n")]
    Access {
        #[command(subcommand)]
        action: AccessCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AccessCmd {
    /// Catalog of IAM tools + quick playbook
    Catalog,
    /// Current identity (AWS STS / gcloud / az account)
    Whoami {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        profile: Option<String>,
    },
    /// List users / service accounts
    Users {
        #[command(subcommand)]
        action: AccessListCmd,
    },
    /// List roles
    Roles {
        #[command(subcommand)]
        action: AccessListCmd,
    },
    /// List groups (AWS) or role assignments (Azure)
    Groups {
        #[command(subcommand)]
        action: AccessListCmd,
    },
    /// List policies / bindings
    Policies {
        #[command(subcommand)]
        action: AccessListCmd,
    },
    /// Pattern search IAM entities
    Search {
        pattern: String,
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Test whether a principal can perform an action
    Test {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        permission: Option<String>,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        resource: Option<String>,
        #[arg(long)]
        principal_arn: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        assignee: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    /// AWS: simulate-principal-policy
    Simulate {
        #[arg(long)]
        principal_arn: String,
        #[arg(long)]
        action: String,
        #[arg(long, default_value = "*")]
        resource: String,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Create IAM user (AWS) / service account (GCP) — requires readwrite
    User {
        #[command(subcommand)]
        action: AccessUserCmd,
    },
    /// Create/delete role (AWS) or role assignment (Azure)
    Role {
        #[command(subcommand)]
        action: AccessRoleCmd,
    },
    /// Attach/detach managed policy (AWS) or add/remove IAM binding (GCP)
    Policy {
        #[command(subcommand)]
        action: AccessPolicyCmd,
    },
    /// Troubleshoot playbook
    Troubleshoot {
        #[arg(long, default_value = "auto")]
        cloud: String,
        #[arg(long)]
        symptom: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AccessListCmd {
    List {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u64,
    },
}

#[derive(Subcommand, Debug)]
enum AccessUserCmd {
    Create {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    Delete {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    Get {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AccessRoleCmd {
    Create {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        name: String,
        /// Trust policy JSON (AWS) / role name for Azure assignment
        #[arg(long)]
        trust_policy: Option<String>,
        #[arg(long)]
        assignee: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    Delete {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        assignee: Option<String>,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    Get {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AccessPolicyCmd {
    /// AWS: create managed policy
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        document: String,
        #[arg(long)]
        profile: Option<String>,
    },
    /// AWS: delete managed policy by ARN
    Delete {
        #[arg(long)]
        arn: String,
        #[arg(long)]
        profile: Option<String>,
    },
    /// AWS attach or GCP add-binding
    Attach {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        policy_arn: Option<String>,
        #[arg(long)]
        target_type: Option<String>,
        #[arg(long)]
        target_name: Option<String>,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    Detach {
        #[arg(long, default_value = "aws")]
        cloud: String,
        #[arg(long)]
        policy_arn: Option<String>,
        #[arg(long)]
        target_type: Option<String>,
        #[arg(long)]
        target_name: Option<String>,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SkillsCmd {
    /// List discovered skills (default)
    List,
    /// Show full skill body
    Show { name: String },
    /// Print skills search paths
    Path,
}

#[derive(Subcommand, Debug)]
enum IdentitiesCmd {
    /// Live-validate all identities (default)
    Check,
    /// Fast list (keychain presence only, no live probe)
    List,
    /// JSON output of full inventory
    Json,
}

#[derive(Subcommand, Debug)]
enum McpCmd {
    /// List configured MCP servers (default)
    List,
    /// Add an MCP server (stdio by default; use --transport http|sse + --url for remote)
    Add {
        /// Server name (letters, numbers, _ -)
        name: String,
        /// Full command + args after `--` for stdio, e.g. npx -y @modelcontextprotocol/server-filesystem /tmp
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        #[arg(long, default_value = "true")]
        enabled: bool,
        /// Optional install hint string
        #[arg(long)]
        install_hint: Option<String>,
        /// Transport: stdio (default) | http | sse
        #[arg(long, default_value = "stdio")]
        transport: String,
        /// Remote MCP base URL (required for http/sse)
        #[arg(long)]
        url: Option<String>,
        /// HTTP header KEY=VALUE (repeatable), e.g. --header "Authorization=Bearer ${TOKEN}"
        #[arg(long = "header", value_name = "KEY=VALUE")]
        headers: Vec<String>,
    },
    /// Remove a server from config
    Remove { name: String },
    /// Enable a server
    Enable { name: String },
    /// Disable a server
    Disable { name: String },
    /// Probe connectivity + list remote tools
    Doctor {
        /// Optional single server name
        name: Option<String>,
    },
    /// Show first-class tool ids that would be mounted from connected servers
    Tools,
    /// Print example TOML snippet
    Example,
    /// Print example plugin tool TOML (third-party tools under plugins/)
    PluginExample,
    /// List installable MCP presets (M11)
    Presets,
    /// Reconnect all enabled MCP servers and print remount status (M9)
    Reload,
    /// OAuth browser login for an HTTP MCP server (PKCE; stores token in mcp_credentials.json)
    Auth {
        /// Server name from config
        name: String,
    },
    /// Store a bearer token for an MCP server without browser OAuth
    SetToken {
        name: String,
        /// Token string (prefer --token-file to avoid shell history)
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        token_file: Option<std::path::PathBuf>,
    },
    /// Remove stored OAuth token for a server
    Logout {
        name: String,
    },
    /// Add a common MCP server preset into config (M11)
    Install {
        /// Preset name: filesystem | git | memory | fetch | time | sequential-thinking
        preset: String,
        /// Override server name in config (default = preset)
        #[arg(long)]
        name: Option<String>,
        /// Extra trailing args (e.g. allowed path for filesystem)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
        #[arg(long, default_value = "true")]
        enabled: bool,
    },
}

#[derive(Subcommand, Debug)]
enum BinariesCmd {
    /// Show binary inventory (default)
    List,
    /// Plan install commands for missing critical (or --all enabled-tool) binaries
    Plan {
        /// Include full critical CSP set (aws/gcloud/az/kubectl)
        #[arg(long, default_value_t = false)]
        all: bool,
    },
    /// Run install plan (requires --yes; may use sudo)
    Install {
        /// Confirm elevated package install
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value_t = false)]
        all: bool,
    },
}

#[derive(Subcommand, Debug)]
enum SettingsCmd {
    /// Print current tools settings (default)
    Show,
    /// Interactive text menu (toggle tools/clouds/policy)
    Menu,
    /// Disable a first-class tool id so it never appears in tools_search
    DisableTool {
        /// Tool id (e.g. gcp.dns.inventory.sync)
        id: String,
    },
    /// Re-enable a previously disabled tool
    EnableTool {
        id: String,
    },
    /// Hide an entire cloud from search/execute: aws | gcp | azure | k8s
    DisableCloud {
        cloud: String,
    },
    /// Re-enable a cloud
    EnableCloud {
        cloud: String,
    },
    /// Set install_binaries policy: off | recommend | ask-admin | install-all
    InstallPolicy {
        /// off=never; recommend=suggest only; ask-admin=request elevated install; install-all=prefer full set for enabled tools
        policy: String,
    },
    /// Allow agent to prompt for admin install (still needs user approve)
    AllowAdminPrompt {
        /// on | off
        value: String,
    },
    /// List registered tool ids (for disable-tool)
    Tools,
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// Store LLM provider API key in OS keychain (preferred; not env)
    #[command(long_about = "Writes provider API key to OS keychain under oscar/provider/<id>. Prefer --key-file. Key is never printed. Built-in providers will not fall back to XAI_API_KEY/OPENAI_API_KEY unless config sets provider.api_key_env (custom providers).")]
    ProviderKey {
        #[arg(long, long_help = "Provider id: xai | openai | anthropic | opencode-zen | opencode-go | custom")]
        provider: String,
        #[arg(long, long_help = "API key string (avoid if possible—prefer --key-file)")]
        key: Option<String>,
        /// Read key from file (avoids shell history); file content never sent to the agent
        #[arg(long)]
        key_file: Option<String>,
    },
    /// Store long-lived AWS access keys in keychain for a oscar profile
    #[command(long_about = "Stores AccessKeyId + SecretAccessKey in the profile keychain namespace. Prefer short-lived aws-session / aws-assume-role / aws-sso-login when possible.")]
    AwsKeys {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        access_key_id: String,
        #[arg(long)]
        secret_access_key: String,
    },
    /// Store short-lived AWS session credentials (STS / temp keys) in keychain
    #[command(long_about = "Stores temporary AWS credentials including session token. Ideal for STS or console-generated short-term keys. Agent never sees these values.")]
    AwsSession {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        access_key_id: String,
        #[arg(long)]
        secret_access_key: String,
        #[arg(long)]
        session_token: String,
    },
    /// Assume an IAM role; store short-lived creds in keychain
    #[command(long_about = "Uses current binary/keychain base identity to call sts assume-role, then stores temporary keys in keychain for the oscar profile.")]
    AwsAssumeRole {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        role_arn: String,
        #[arg(long, default_value = "oscar-session")]
        session_name: String,
    },
    /// Interactive AWS SSO login via aws CLI (no keys captured into agent chat)
    #[command(long_about = "Runs `aws sso login` as a subprocess so the user completes OAuth/SSO in browser. Oscar does not scrape or store the SSO token into chat—only enables binary-session auth afterward. Type `retry` in chat after login if a tool was paused.")]
    AwsSsoLogin {
        /// Optional AWS named profile for the CLI
        #[arg(long)]
        aws_profile: Option<String>,
        /// Oscar profile to associate (for status messages only)
        #[arg(long)]
        profile: Option<String>,
    },
    /// Validate AWS access for a profile (keychain or binary session)
    AwsTest {
        #[arg(long)]
        profile: String,
    },
    /// gcloud user login (browser/SSO); enables binary session without pasting keys into chat
    #[command(long_about = "Runs `gcloud auth login` (and optionally application-default). No tokens are read into the agent transcript.")]
    GcloudLogin {
        #[arg(long, default_value_t = false)]
        adc: bool,
    },
    /// az login (device code / browser); binary session for Azure tools
    AzLogin {
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Store GCP service account JSON in keychain (file path; contents never printed)
    GcpSa {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        file: String,
    },
    /// Show auth policy summary (no secrets)
    Policy,
}

#[derive(Subcommand, Debug)]
enum InventoryCmd {
    /// Live-sync CSP inventories into unified cache formats
    Sync {
        /// Cloud: aws | gcp | azure | all
        #[arg(long)]
        cloud: String,
        /// Kind: dns | network | resolver | k8s | all (dns=zones; network=VPC; resolver=R53 Resolver/Firewall)
        #[arg(long, default_value = "dns")]
        kind: String,
        /// Oscar profile id (optional; all matching cloud profiles if omitted)
        #[arg(long)]
        profile: Option<String>,
        /// Skip DNS record sets (zones only) when kind includes dns
        #[arg(long)]
        zones_only: bool,
        /// AWS region override for network sync
        #[arg(long)]
        region: Option<String>,
    },
    /// Show DNS + network cache status for profiles
    Status,
    /// Write fixture NetworkInventory (no AWS credentials) for local pattern tests
    SeedFixture {
        /// Profile id to attach cache under
        #[arg(long, default_value = "aws-fixture")]
        profile: String,
    },
}

#[derive(Subcommand, Debug)]
enum ModeCmd {
    Show,
    Set { mode: String },
}

#[derive(Subcommand, Debug)]
enum ProfilesCmd {
    List,
    Add {
        #[arg(long)]
        cloud: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        region: Option<String>,
    },
    Remove {
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum SessionsCmd {
    /// List recent chats (default)
    List,
    /// Print session metadata + last messages
    Show {
        id: String,
    },
    /// Delete a saved session
    Delete {
        id: String,
    },
    /// Open TUI on a session (or most recent if omitted)
    Resume {
        id: Option<String>,
    },
    /// Create a new empty session and print its id
    New,
}

#[derive(Subcommand, Debug)]
enum ToolsCmd {
    /// List all registered first-class tools (id, capability, domain, description)
    List,
    /// Search inventory (same ranking the agent tools_search uses)
    Search {
        /// Free-text query (e.g. "dns private", "path analyze")
        query: String,
        /// Max hits (default 15, same as agent)
        #[arg(long, default_value_t = 15)]
        limit: usize,
    },
    /// Execute a first-class tool (same path as agent tools_execute)
    #[command(long_about = "Runs tools_execute locally for verification. Pass JSON args with --args or --args-file. Example: oscar tools execute dns.where --args '{\"name\":\"api.example\"}'")]
    Execute {
        /// Tool id from tools search
        tool_id: String,
        /// JSON object of arguments (default {})
        #[arg(long, default_value = "{}")]
        args: String,
        /// Read arguments JSON from a file instead of --args
        #[arg(long)]
        args_file: Option<String>,
    },
    /// Print Code Mode documentation the agent receives for tools_search / tools_execute
    #[command(long_about = "Dumps the long tool descriptions and usage primer injected into the agent. Use this to verify the model has clear guidance for search+execute.")]
    Catalog,
}

#[derive(Subcommand, Debug)]
enum ProviderCmd {
    /// List built-in providers and mark the configured default
    #[command(long_about = "Shows provider ids. Keys are never listed. Use oscar auth provider-key to store a key, oscar provider set to change default.")]
    List,
    /// Set default provider id in config
    Set {
        /// Provider id
        id: String,
    },
    /// Show current provider + whether a keychain key is present (never prints the key)
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("oscar=info".parse()?))
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let paths = Paths::discover()?;
    paths.ensure()?;
    let mut cfg = OscarConfig::load(&paths)?;

    if let Some(m) = &cli.mode {
        cfg.mode = ExecutionMode::parse(m).context("invalid --mode")?;
    }
    if let Some(p) = &cli.provider {
        cfg.provider.id = p.clone();
    }
    if let Some(m) = &cli.model {
        cfg.provider.model = Some(m.clone());
    }
    if let Some(t) = &cli.thinking {
        cfg.thinking = match t {
            OnOff::On => ThinkingConfig::On {
                budget_tokens: None,
            },
            OnOff::Off => ThinkingConfig::Off,
        };
    }
    // Headless global LLM key → keychain (never rely on default XAI_API_KEY env)
    if let Some(key) = &cli.llm_api_key {
        inject_headless_llm_key(&cfg.provider.id, key).map_err(|e| anyhow::anyhow!(e))?;
    }

    match cli.command {
        None => run_chat(cfg, paths).await,
        Some(Commands::Ask {
            prompt,
            stream,
            output,
            llm_api_key,
        }) => {
            if let Some(key) = llm_api_key {
                inject_headless_llm_key(&cfg.provider.id, &key)
                    .map_err(|e| anyhow::anyhow!(e))?;
            }
            run_ask(cfg, paths, prompt, stream, output).await
        }
        Some(Commands::Binaries { action }) => run_binaries(action, &cfg),
        Some(Commands::Settings { action }) => run_settings(action, &mut cfg, &paths),
        Some(Commands::Skills { action }) => run_skills(action, &cfg),
        Some(Commands::Identities { action }) => run_identities(action, &paths),
        Some(Commands::Mcp { action }) => run_mcp(action, &mut cfg, &paths).await,
        Some(Commands::Access { action }) => run_access(action, &cfg, &paths).await,
        Some(Commands::Auth { action }) => run_auth(action, &paths).await,
        Some(Commands::Mode { action }) => {
            match action.unwrap_or(ModeCmd::Show) {
                ModeCmd::Show => {
                    println!("{}", cfg.mode);
                }
                ModeCmd::Set { mode } => {
                    cfg.mode = ExecutionMode::parse(&mode).context("invalid mode")?;
                    cfg.save(&paths)?;
                    println!("mode set to {}", cfg.mode);
                }
            }
            Ok(())
        }
        Some(Commands::Profiles { action }) => {
            let mut store = ProfileStore::load(&paths)?;
            match action {
                ProfilesCmd::List => {
                    if store.list().is_empty() {
                        println!("(no profiles)");
                        println!("# add: oscar profiles add --cloud aws|gcp|azure|k8s --label NAME --account ID");
                    } else {
                        println!(
                            "{:<8} {:<22} {:<14} {:<20} {:<16} {}",
                            "CSP", "ID", "LABEL", "ACCOUNT_KIND", "ACCOUNT", "REGION"
                        );
                        println!("{}", "-".repeat(96));
                        // Stable CSP order: AWS, GCP, Azure, K8s
                        for cloud in [
                            oscar_core::Cloud::Aws,
                            oscar_core::Cloud::Gcp,
                            oscar_core::Cloud::Azure,
                            oscar_core::Cloud::K8s,
                            oscar_core::Cloud::Multi,
                        ] {
                            for p in store.list().iter().filter(|p| p.cloud == cloud) {
                                println!(
                                    "{:<8} {:<22} {:<14} {:<20} {:<16} {}",
                                    cloud.tag(),
                                    p.id,
                                    p.label,
                                    cloud.account_kind(),
                                    p.account_ref,
                                    p.default_region.as_deref().unwrap_or("-")
                                );
                            }
                        }
                        println!();
                        println!(
                            "# ids are CSP-prefixed (aws-… / gcp-… / azure-… / k8s-…) so profiles never collide across clouds"
                        );
                    }
                }
                ProfilesCmd::Add {
                    cloud,
                    label,
                    account,
                    region,
                } => {
                    let cloud = oscar_core::Cloud::parse(&cloud).context("invalid cloud")?;
                    let mut p = Profile::new(cloud, label, account);
                    p.default_region = region;
                    let id = p.id.clone();
                    store.upsert(p);
                    store.save()?;
                    println!("added profile {id}");
                }
                ProfilesCmd::Remove { id } => {
                    if store.remove(&id) {
                        store.save()?;
                        println!("removed {id}");
                    } else {
                        println!("not found: {id}");
                    }
                }
            }
            Ok(())
        }
        Some(Commands::Tools { action }) => {
            // Include MCP-mounted tools so search/list matches the agent inventory.
            let registry = build_registry_with_mcp(&cfg).await;
            match action {
                ToolsCmd::List => {
                    println!(
                        "# first-class tools (agent discovers these via tools_search → tools_execute)\n# id\tcapability\tdomain\tdescription"
                    );
                    for m in registry.list() {
                        println!(
                            "{}\t{}\t{}\t{}",
                            m.id, m.capability, m.domain, m.description
                        );
                    }
                }
                ToolsCmd::Search { query, limit } => {
                    let inv = BinaryInventory::detect();
                    let hits = registry.search_as_json_gated_limited(
                        &query,
                        None,
                        None,
                        None,
                        Some(&inv),
                        Some(&cfg.tools),
                        limit,
                    );
                    println!("{}", serde_json::to_string_pretty(&hits)?);
                }
                ToolsCmd::Execute {
                    tool_id,
                    args,
                    args_file,
                } => {
                    let raw = if let Some(path) = args_file {
                        std::fs::read_to_string(&path)
                            .with_context(|| format!("read --args-file {path}"))?
                    } else {
                        args
                    };
                    let arguments: serde_json::Value = serde_json::from_str(&raw)
                        .context("--args must be a JSON object")?;
                    let inv = BinaryInventory::detect();
                    let profiles = ProfileStore::load(&paths)?;
                    let ctx = oscar_tools::ToolContext {
                        mode: cfg.mode,
                        profiles: Arc::new(profiles),
                        cancel: tokio_util::sync::CancellationToken::new(),
                        config_dir: paths.config_dir.clone(),
                        binaries: Arc::new(inv),
                        settings: Arc::new(cfg.tools.clone()),
                        skills_settings: Arc::new(cfg.skills.clone()),
                        preferred_profile_id: None,
                    };
                    let result = registry.execute(&tool_id, arguments, &ctx).await;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    if !result.ok {
                        anyhow::bail!("tools_execute failed: {}", result.summary);
                    }
                }
                ToolsCmd::Catalog => {
                    println!("=== tools_search (model tool schema description) ===\n");
                    println!("{}", oscar_tools::tools_search_description());
                    println!("\n=== tools_execute (model tool schema description) ===\n");
                    println!("{}", oscar_tools::tools_execute_description());
                    println!("\n=== agent primer ===\n");
                    println!("{}", oscar_tools::agent_tools_primer());
                    println!("\n=== registered tool ids ({}) ===", registry.list().len());
                    for m in registry.list() {
                        println!("- {} — {}", m.id, m.name);
                    }
                }
            }
            Ok(())
        }
        Some(Commands::Provider { action }) => {
            match action.unwrap_or(ProviderCmd::List) {
                ProviderCmd::List => {
                    println!("# * = configured default  | keys: oscar auth provider-key (not ambient env)");
                    for id in list_provider_ids() {
                        let mark = if *id == cfg.provider.id { "*" } else { " " };
                        let key_state = match load_provider_api_key(id) {
                            Ok(Some(_)) => "keychain=yes",
                            Ok(None) => "keychain=no",
                            Err(_) => "keychain=?",
                        };
                        println!("{mark} {id}\t{key_state}");
                    }
                    println!("custom: set provider id + base_url in config; optional api_key_env for custom env-only keys");
                }
                ProviderCmd::Set { id } => {
                    // Allow custom ids; built-ins validated loosely
                    cfg.provider.id = id;
                    cfg.save(&paths)?;
                    println!(
                        "provider set to {} (store key: oscar auth provider-key --provider {} --key-file …)",
                        cfg.provider.id, cfg.provider.id
                    );
                }
                ProviderCmd::Status => {
                    let id = &cfg.provider.id;
                    let key_state = match load_provider_api_key(id) {
                        Ok(Some(_)) => "present (value hidden)".to_string(),
                        Ok(None) => "missing".to_string(),
                        Err(e) => format!("error: {e}"),
                    };
                    println!("provider={id}");
                    println!("model={}", cfg.provider.model.as_deref().unwrap_or("(default)"));
                    println!("base_url={}", cfg.provider.base_url.as_deref().unwrap_or("(default)"));
                    println!(
                        "api_key_env={}",
                        cfg.provider
                            .api_key_env
                            .as_deref()
                            .unwrap_or("(none — keychain only for built-ins)")
                    );
                    println!("keychain_key={key_state}");
                    println!("note=raw keys are never printed or sent to the agent transcript");
                }
            }
            Ok(())
        }
        Some(Commands::Compact) => {
            run_sessions_compact(&paths)?;
            Ok(())
        }
        Some(Commands::Sessions { action }) => run_sessions(action, cfg, paths).await,
        Some(Commands::Inventory { action }) => match action {
            InventoryCmd::Status => {
                let store = ProfileStore::load(&paths)?;
                if store.list().is_empty() {
                    println!("(no profiles — oscar profiles add --cloud aws --label default --account <id>)");
                    println!("(or: oscar inventory seed-fixture --profile aws-fixture)");
                }
                for p in store.list() {
                    let dns = load_dns_cache(&paths.config_dir, &p.id);
                    let net = load_network_cache(&paths.config_dir, &p.id, p.default_region.as_deref());
                    let dns_s = match &dns {
                        Some(inv) => {
                            let recs: usize = inv.zones.iter().map(|z| z.records.len()).sum();
                            format!("dns_zones={} dns_records={}", inv.zones.len(), recs)
                        }
                        None => "dns=none".into(),
                    };
                    let net_s = match &net {
                        Some(inv) => format!(
                            "net_vpcs={} net_subnets={} net_addrs={} format=NetworkInventory",
                            inv.vpcs.len(),
                            inv.subnets.len(),
                            inv.addresses.len()
                        ),
                        None => "network=none".into(),
                    };
                    println!("{}\t{}\t{}\t{}", p.id, p.cloud, dns_s, net_s);
                }
                // Also show orphan fixture caches under config if profile missing
                Ok(())
            }
            InventoryCmd::SeedFixture { profile } => {
                let mut store = ProfileStore::load(&paths)?;
                if store.get(&profile).is_none() {
                    let mut p = Profile::new(oscar_core::Cloud::Aws, "fixture", "fixture-account");
                    p.id = profile.clone();
                    p.default_region = Some("us-east-1".into());
                    store.upsert(p);
                    store.save()?;
                }
                let inv = oscar_aws::fixture_network_inventory(&profile);
                write_network_cache(&paths.config_dir, &inv)?;
                println!(
                    "seeded NetworkInventory profile={} vpcs={} subnets={} addresses={} (unified format)",
                    profile,
                    inv.vpcs.len(),
                    inv.subnets.len(),
                    inv.addresses.len()
                );
                Ok(())
            }
            InventoryCmd::Sync {
                cloud,
                kind,
                profile,
                zones_only,
                region,
            } => {
                let store = ProfileStore::load(&paths)?;
                let cloud = cloud.to_ascii_lowercase();
                let kind = kind.to_ascii_lowercase();
                let do_dns = kind == "dns" || kind == "all";
                let do_net = kind == "network" || kind == "net" || kind == "all";
                let do_resolver = kind == "resolver"
                    || kind == "dns-resolver"
                    || kind == "r53resolver"
                    || kind == "all";
                let mut opts = DnsSyncOpts::default();
                opts.include_records = !zones_only;
                let mut any = false;
                for p in store.list() {
                    if let Some(ref pid) = profile {
                        if &p.id != pid {
                            continue;
                        }
                    }
                    let run_aws = cloud == "aws" || cloud == "all";
                    let run_gcp = cloud == "gcp" || cloud == "all";
                    let run_azure = cloud == "azure" || cloud == "all";
                    if run_aws && p.cloud == oscar_core::Cloud::Aws {
                        // Seed fixtures are offline-only; skip live CLI against fake labels.
                        if p.account_ref == "fixture-account" {
                            continue;
                        }
                        if do_dns {
                            any = true;
                            match oscar_aws::AwsDnsSource.sync_dns(p, &opts).await {
                                Ok(inv) => {
                                    write_dns_cache(&paths.config_dir, &inv)?;
                                    let recs: usize =
                                        inv.zones.iter().map(|z| z.records.len()).sum();
                                    println!(
                                        "aws {} dns → {} zones, {} records (DnsInventory)",
                                        p.id,
                                        inv.zones.len(),
                                        recs
                                    );
                                }
                                Err(e) => eprintln!("aws {} dns: ERROR {e}", p.id),
                            }
                        }
                        if do_net {
                            any = true;
                            let r = region.as_deref().or(p.default_region.as_deref());
                            match oscar_aws::AwsNetworkSource.sync_network(p, r).await {
                                Ok(inv) => {
                                    write_network_cache(&paths.config_dir, &inv)?;
                                    println!(
                                        "aws {} network → vpcs={} subnets={} addresses={} (NetworkInventory)",
                                        p.id,
                                        inv.vpcs.len(),
                                        inv.subnets.len(),
                                        inv.addresses.len()
                                    );
                                }
                                Err(e) => eprintln!("aws {} network: ERROR {e}", p.id),
                            }
                        }
                        if do_resolver {
                            any = true;
                            let r = region.as_deref().or(p.default_region.as_deref());
                            match oscar_aws::AwsDnsResolverSource
                                .sync_resolver(p, r)
                                .await
                            {
                                Ok(inv) => {
                                    oscar_tools::write_dns_resolver_cache(
                                        &paths.config_dir,
                                        &inv,
                                    )?;
                                    println!(
                                        "aws {} resolver → endpoints={} rules={} firewall={} query_logs={} (DnsResolverInventory)",
                                        p.id,
                                        inv.endpoints.len(),
                                        inv.rules.len(),
                                        inv.firewall_rule_groups.len(),
                                        inv.query_log_configs.len()
                                    );
                                }
                                Err(e) => eprintln!("aws {} resolver: ERROR {e}", p.id),
                            }
                        }
                    }
                    if run_gcp && p.cloud == oscar_core::Cloud::Gcp {
                        if do_dns {
                            any = true;
                            match oscar_gcp::GcpDnsSource.sync_dns(p, &opts).await {
                                Ok(inv) => {
                                    write_dns_cache(&paths.config_dir, &inv)?;
                                    let recs: usize =
                                        inv.zones.iter().map(|z| z.records.len()).sum();
                                    println!(
                                        "gcp {} dns → {} zones, {} records (DnsInventory)",
                                        p.id,
                                        inv.zones.len(),
                                        recs
                                    );
                                }
                                Err(e) => eprintln!("gcp {} dns: ERROR {e}", p.id),
                            }
                        }
                        if do_net {
                            any = true;
                            let r = region.as_deref().or(p.default_region.as_deref());
                            match oscar_gcp::GcpNetworkSource.sync_network(p, r).await {
                                Ok(inv) => {
                                    write_network_cache(&paths.config_dir, &inv)?;
                                    println!(
                                        "gcp {} network → vpcs={} subnets={} addresses={} (NetworkInventory)",
                                        p.id,
                                        inv.vpcs.len(),
                                        inv.subnets.len(),
                                        inv.addresses.len()
                                    );
                                }
                                Err(e) => eprintln!("gcp {} network: ERROR {e}", p.id),
                            }
                        }
                        if do_resolver {
                            any = true;
                            match oscar_gcp::GcpDnsResolverSource
                                .sync_resolver(p, None)
                                .await
                            {
                                Ok(inv) => {
                                    oscar_tools::write_dns_resolver_cache(
                                        &paths.config_dir,
                                        &inv,
                                    )?;
                                    println!(
                                        "gcp {} resolver → policies={} (DnsResolverInventory)",
                                        p.id,
                                        inv.policies.len()
                                    );
                                }
                                Err(e) => eprintln!("gcp {} resolver: ERROR {e}", p.id),
                            }
                        }
                    }
                    if run_azure && p.cloud == oscar_core::Cloud::Azure {
                        if do_dns {
                            any = true;
                            match oscar_azure::AzureDnsSource.sync_dns(p, &opts).await {
                                Ok(inv) => {
                                    write_dns_cache(&paths.config_dir, &inv)?;
                                    let recs: usize =
                                        inv.zones.iter().map(|z| z.records.len()).sum();
                                    println!(
                                        "azure {} dns → {} zones, {} records (DnsInventory)",
                                        p.id,
                                        inv.zones.len(),
                                        recs
                                    );
                                }
                                Err(e) => eprintln!("azure {} dns: ERROR {e}", p.id),
                            }
                        }
                        if do_net {
                            any = true;
                            let r = region.as_deref().or(p.default_region.as_deref());
                            match oscar_azure::AzureNetworkSource.sync_network(p, r).await {
                                Ok(inv) => {
                                    write_network_cache(&paths.config_dir, &inv)?;
                                    println!(
                                        "azure {} network → vnets={} subnets={} addresses={} (NetworkInventory)",
                                        p.id,
                                        inv.vpcs.len(),
                                        inv.subnets.len(),
                                        inv.addresses.len()
                                    );
                                }
                                Err(e) => eprintln!("azure {} network: ERROR {e}", p.id),
                            }
                        }
                        if do_resolver {
                            any = true;
                            let r = region.as_deref().or(p.default_region.as_deref());
                            match oscar_azure::AzureDnsResolverSource
                                .sync_resolver(p, r)
                                .await
                            {
                                Ok(inv) => {
                                    oscar_tools::write_dns_resolver_cache(
                                        &paths.config_dir,
                                        &inv,
                                    )?;
                                    println!(
                                        "azure {} resolver → vnet_links={} private_resolvers={} (DnsResolverInventory)",
                                        p.id,
                                        inv.vnet_links.len(),
                                        inv.private_resolvers.len()
                                    );
                                }
                                Err(e) => eprintln!("azure {} resolver: ERROR {e}", p.id),
                            }
                        }
                    }
                    let run_k8s = cloud == "k8s" || cloud == "all";
                    if run_k8s
                        && (kind == "k8s" || kind == "cluster" || kind == "all" || do_net)
                        && (p.cloud == oscar_core::Cloud::K8s || !p.clusters.is_empty())
                    {
                        any = true;
                        if p.clusters.is_empty() {
                            match oscar_k8s::sync_and_cache(
                                &paths.config_dir,
                                None,
                                Some(&p.id),
                            )
                            .await
                            {
                                Ok(inv) => println!(
                                    "k8s {} → {} resources (K8sInventory)",
                                    p.id,
                                    inv.resources.len()
                                ),
                                Err(e) => eprintln!("k8s {}: ERROR {e}", p.id),
                            }
                        } else {
                            for c in &p.clusters {
                                match oscar_k8s::sync_and_cache(
                                    &paths.config_dir,
                                    c.context.as_deref().or(Some(c.name.as_str())),
                                    Some(&p.id),
                                )
                                .await
                                {
                                    Ok(inv) => println!(
                                        "k8s {}/{} → {} resources",
                                        p.id,
                                        c.name,
                                        inv.resources.len()
                                    ),
                                    Err(e) => {
                                        eprintln!("k8s {}/{}: ERROR {e}", p.id, c.name)
                                    }
                                }
                            }
                        }
                    }
                }
                // Ambient kubectl (current context) when cloud=k8s|all
                let run_k8s = cloud == "k8s" || cloud == "all";
                if run_k8s && (kind == "k8s" || kind == "cluster" || kind == "all") {
                    any = true;
                    match oscar_k8s::sync_and_cache(&paths.config_dir, None, None).await {
                        Ok(inv) => println!(
                            "k8s default → {} resources (K8sInventory)",
                            inv.resources.len()
                        ),
                        Err(e) => eprintln!("k8s default: ERROR {e}"),
                    }
                }
                if !any {
                    eprintln!(
                        "no matching profiles for cloud={cloud} kind={kind}. Add one: oscar profiles add --cloud aws --label default --account <id>"
                    );
                    eprintln!("or seed without AWS: oscar inventory seed-fixture");
                    eprintln!("k8s: oscar inventory sync --cloud k8s --kind k8s");
                }
                Ok(())
            }
        },
    }
}

async fn run_auth(action: AuthCmd, paths: &Paths) -> Result<()> {
    match action {
        AuthCmd::Policy => {
            println!(
                r#"oscar auth policy:
- LLM keys: OS keychain via `oscar auth provider-key` or headless `--llm-api-key` (stores into keychain).
  Default env vars (XAI_API_KEY, OPENAI_API_KEY, …) are NOT used unless config sets provider.api_key_env (custom providers only).
- CSP: keychain long-lived keys, short-lived STS/session tokens, OR detected binary sessions (aws/gcloud/az/kubectl already logged in).
- Prefer short-lived role creds: `oscar auth aws-assume-role` / `oscar auth aws-session`.
- Detected binaries: `oscar binaries`
"#
            );
            let inv = BinaryInventory::detect();
            println!("{}", inv.agent_summary());
            let _ = paths;
            Ok(())
        }
        AuthCmd::ProviderKey {
            provider,
            key,
            key_file,
        } => {
            let key = if let Some(f) = key_file {
                std::fs::read_to_string(f)?.trim().to_string()
            } else {
                key.ok_or_else(|| anyhow::anyhow!("provide --key or --key-file"))?
            };
            store_provider_api_key(&provider, &key)?;
            println!("stored LLM API key for provider `{provider}` in OS keychain");
            Ok(())
        }
        AuthCmd::AwsKeys {
            profile,
            access_key_id,
            secret_access_key,
        } => {
            let store = ProfileStore::load(paths)?;
            let p = store
                .get(&profile)
                .ok_or_else(|| anyhow::anyhow!("unknown profile `{profile}`"))?
                .clone();
            store_aws_long_lived(&p, &access_key_id, &secret_access_key)?;
            println!("stored long-lived AWS keys for profile `{profile}` in keychain");
            Ok(())
        }
        AuthCmd::AwsSession {
            profile,
            access_key_id,
            secret_access_key,
            session_token,
        } => {
            let store = ProfileStore::load(paths)?;
            let p = store
                .get(&profile)
                .ok_or_else(|| anyhow::anyhow!("unknown profile `{profile}`"))?
                .clone();
            store_aws_short_lived(
                &p,
                &access_key_id,
                &secret_access_key,
                &session_token,
                None,
            )?;
            println!("stored short-lived AWS session for profile `{profile}` in keychain");
            Ok(())
        }
        AuthCmd::AwsAssumeRole {
            profile,
            role_arn,
            session_name,
        } => {
            let store = ProfileStore::load(paths)?;
            let p = store
                .get(&profile)
                .ok_or_else(|| anyhow::anyhow!("unknown profile `{profile}`"))?
                .clone();
            let binaries = BinaryInventory::detect();
            let msg = assume_role_into_profile(&p, &role_arn, &session_name, &binaries)?;
            println!("{msg}");
            Ok(())
        }
        AuthCmd::AwsTest { profile } => {
            let store = ProfileStore::load(paths)?;
            let p = store
                .get(&profile)
                .ok_or_else(|| anyhow::anyhow!("unknown profile `{profile}`"))?
                .clone();
            let binaries = BinaryInventory::detect();
            match validate_aws(&p, &binaries) {
                Ok(id) => {
                    println!("OK profile={profile} source=keychain|binary_session");
                    // Identity JSON is non-secret account metadata; still redact just in case
                    println!("{}", oscar_core::redact_text(&id));
                }
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        AuthCmd::AwsSsoLogin {
            aws_profile,
            profile,
        } => {
            println!(
                "Launching AWS SSO login (browser/device). Secrets stay in the AWS CLI session — not in oscar chat."
            );
            if let Some(p) = &profile {
                println!("oscar profile association: {p} (use `retry` in chat after login if a tool paused)");
            }
            let mut cmd = std::process::Command::new("aws");
            cmd.arg("sso").arg("login");
            if let Some(ap) = &aws_profile {
                cmd.args(["--profile", ap]);
            }
            let status = cmd.status().context("failed to run aws sso login")?;
            if status.success() {
                println!("SSO login finished. Agent still cannot read local keys; tools use binary session or keychain only.");
            } else {
                anyhow::bail!("aws sso login exited with {status}");
            }
            Ok(())
        }
        AuthCmd::GcloudLogin { adc } => {
            println!("Launching gcloud auth login (browser). Tokens stay with gcloud — not agent transcript.");
            let status = std::process::Command::new("gcloud")
                .args(["auth", "login"])
                .status()
                .context("gcloud auth login")?;
            if !status.success() {
                anyhow::bail!("gcloud auth login failed: {status}");
            }
            if adc {
                let st = std::process::Command::new("gcloud")
                    .args(["auth", "application-default", "login"])
                    .status()
                    .context("gcloud adc login")?;
                if !st.success() {
                    anyhow::bail!("application-default login failed: {st}");
                }
            }
            println!("gcloud login complete. Use `retry` in chat if a tool was waiting on auth.");
            Ok(())
        }
        AuthCmd::AzLogin { tenant } => {
            println!("Launching az login. Tokens stay with Azure CLI — not agent transcript.");
            let mut cmd = std::process::Command::new("az");
            cmd.arg("login");
            if let Some(t) = &tenant {
                cmd.args(["--tenant", t]);
            }
            let status = cmd.status().context("az login")?;
            if !status.success() {
                anyhow::bail!("az login failed: {status}");
            }
            println!("az login complete. Use `retry` in chat if a tool was waiting on auth.");
            Ok(())
        }
        AuthCmd::GcpSa { profile, file } => {
            let store = ProfileStore::load(paths)?;
            let p = store
                .get(&profile)
                .ok_or_else(|| anyhow::anyhow!("unknown profile `{profile}`"))?
                .clone();
            let raw = std::fs::read_to_string(file)?;
            KeychainStore::set(
                &p.secret_keyring_id,
                oscar_core::SecretKind::ServiceAccountJson,
                &raw,
            )?;
            // Do not print file contents
            println!(
                "stored GCP service account JSON for profile `{profile}` (content hidden; agent cannot read keychain secrets)"
            );
            Ok(())
        }
    }
}

fn build_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    oscar_tools::register_multi(&mut registry);
    oscar_aws::register(&mut registry);
    oscar_gcp::register(&mut registry);
    oscar_azure::register(&mut registry);
    oscar_k8s::register(&mut registry);
    let n = oscar_tools::register_plugins(&mut registry);
    if n > 0 {
        tracing::info!(count = n, "registered plugin tools");
    }
    registry
}

/// Native tools + MCP servers from config (MCP tools mount as mcp.<server>.<tool>).
async fn build_registry_with_mcp(cfg: &OscarConfig) -> ToolRegistry {
    let mut registry = build_registry();
    if cfg.mcp.enabled && !cfg.mcp.servers.is_empty() {
        let _mgr = oscar_mcp::connect_and_register(&mut registry, cfg.mcp.clone()).await;
    }
    registry
}

async fn run_access(action: AccessCmd, cfg: &OscarConfig, paths: &Paths) -> Result<()> {
    use oscar_identity::{BinaryInventory, ProfileStore};
    use oscar_tools::ToolContext;
    use tokio_util::sync::CancellationToken;

    let registry = build_registry();
    let profiles = Arc::new(ProfileStore::load(paths)?);
    let binaries = Arc::new(BinaryInventory::detect());
    let settings = Arc::new(cfg.tools.clone());
    let skills_settings = Arc::new(cfg.skills.clone());
    let ctx = ToolContext {
        mode: cfg.mode,
        profiles,
        cancel: CancellationToken::new(),
        config_dir: paths.config_dir.clone(),
        binaries,
        settings,
        skills_settings,
        preferred_profile_id: None,
    };

    let (tool_id, args) = match action {
        AccessCmd::Catalog => {
            println!("# oscar access — IAM users / roles / permissions\n");
            println!("Troubleshoot: oscar access troubleshoot --cloud aws");
            println!("Whoami:       oscar access whoami --cloud aws|gcp|azure");
            println!("List:         oscar access users|roles|groups|policies list --cloud aws");
            println!("Search:       oscar access search <pattern> --cloud aws");
            println!("Test:         oscar access test --cloud aws --action s3:GetObject");
            println!("Simulate:     oscar access simulate --principal-arn arn:… --action ec2:DescribeInstances");
            println!("Manage:       oscar mode set readwrite");
            println!("              oscar access user create --cloud aws --name tmp");
            println!("              oscar access policy attach --cloud aws --policy-arn arn:… --target-type user --target-name tmp");
            println!("              oscar access policy attach --cloud gcp --role roles/viewer --member user:a@b.com --project my-proj");
            println!("\n# registered access-domain tools");
            for m in registry.list() {
                if m.domain.to_string() == "access" {
                    println!(
                        "  {}\t{}\t{}\t{}",
                        m.id, m.capability, m.clouds.first().map(|c| c.to_string()).unwrap_or_default(), m.name
                    );
                }
            }
            return Ok(());
        }
        AccessCmd::Whoami { cloud, profile } => {
            let id = match cloud.as_str() {
                "gcp" => {
                    // no dedicated whoami tool — use policy get with ambient or account
                    println!("(gcp) use: gcloud auth list / gcloud config get-value project");
                    let out = std::process::Command::new("gcloud")
                        .args(["auth", "list", "--format=json"])
                        .output();
                    if let Ok(o) = out {
                        println!("{}", String::from_utf8_lossy(&o.stdout));
                    }
                    return Ok(());
                }
                "azure" => {
                    let out = std::process::Command::new("az")
                        .args(["account", "show", "-o", "json"])
                        .output();
                    if let Ok(o) = out {
                        println!("{}", String::from_utf8_lossy(&o.stdout));
                    } else {
                        anyhow::bail!("az account show failed");
                    }
                    return Ok(());
                }
                _ => "aws.iam.caller.identity",
            };
            (id.to_string(), json_profile(profile))
        }
        AccessCmd::Users {
            action: AccessListCmd::List {
                cloud,
                profile,
                project,
                limit,
            },
        } => {
            let id = match cloud.as_str() {
                "gcp" => "gcp.iam.service_accounts.list",
                "azure" => "azure.iam.users.list",
                _ => "aws.iam.users.list",
            };
            (
                id.to_string(),
                json_obj([
                    ("profile_id", profile.map(serde_json::Value::String)),
                    ("project", project.map(serde_json::Value::String)),
                    ("max_items", Some(serde_json::json!(limit))),
                    ("limit", Some(serde_json::json!(limit))),
                ]),
            )
        }
        AccessCmd::Roles {
            action: AccessListCmd::List {
                cloud,
                profile,
                project: _,
                limit,
            },
        } => {
            let id = match cloud.as_str() {
                "gcp" => "gcp.iam.roles.list",
                "azure" => "azure.iam.role_definitions.list",
                _ => "aws.iam.roles.list",
            };
            (
                id.to_string(),
                json_obj([
                    ("profile_id", profile.map(serde_json::Value::String)),
                    ("max_items", Some(serde_json::json!(limit))),
                    ("limit", Some(serde_json::json!(limit))),
                ]),
            )
        }
        AccessCmd::Groups {
            action: AccessListCmd::List {
                cloud,
                profile,
                project: _,
                limit,
            },
        } => {
            let id = match cloud.as_str() {
                "azure" => "azure.iam.role_assignments.list",
                "gcp" => "gcp.iam.policy.get",
                _ => "aws.iam.groups.list",
            };
            (
                id.to_string(),
                json_obj([
                    ("profile_id", profile.map(serde_json::Value::String)),
                    ("max_items", Some(serde_json::json!(limit))),
                ]),
            )
        }
        AccessCmd::Policies {
            action: AccessListCmd::List {
                cloud,
                profile,
                project,
                limit,
            },
        } => {
            let id = match cloud.as_str() {
                "gcp" => "gcp.iam.policy.get",
                "azure" => "azure.iam.role_assignments.list",
                _ => "aws.iam.policies.list",
            };
            (
                id.to_string(),
                json_obj([
                    ("profile_id", profile.map(serde_json::Value::String)),
                    ("project", project.map(serde_json::Value::String)),
                    ("max_items", Some(serde_json::json!(limit))),
                    ("scope", Some(serde_json::json!("Local"))),
                ]),
            )
        }
        AccessCmd::Search {
            pattern,
            cloud,
            profile,
        } => {
            let id = match cloud.as_str() {
                "gcp" => "gcp.iam.pattern.search",
                "azure" => "azure.iam.pattern.search",
                _ => "aws.iam.pattern.search",
            };
            (
                id.to_string(),
                json_obj([
                    ("pattern", Some(serde_json::json!(pattern))),
                    ("profile_id", profile.map(serde_json::Value::String)),
                ]),
            )
        }
        AccessCmd::Test {
            cloud,
            action,
            permission,
            role,
            resource,
            principal_arn,
            project,
            assignee,
            profile,
        } => {
            let id = match cloud.as_str() {
                "gcp" => "gcp.iam.access.test",
                "azure" => "azure.iam.access.test",
                _ => "aws.iam.access.test",
            };
            let act = action.clone().or(permission.clone());
            (
                id.to_string(),
                json_obj([
                    (
                        "action",
                        if cloud == "aws" {
                            act.clone().map(serde_json::Value::String)
                        } else {
                            None
                        },
                    ),
                    (
                        "permission",
                        if cloud == "gcp" {
                            act.map(serde_json::Value::String)
                        } else {
                            None
                        },
                    ),
                    ("role", role.map(serde_json::Value::String)),
                    ("resource", resource.map(serde_json::Value::String)),
                    ("principal_arn", principal_arn.map(serde_json::Value::String)),
                    ("project", project.map(serde_json::Value::String)),
                    ("assignee", assignee.map(serde_json::Value::String)),
                    ("profile_id", profile.map(serde_json::Value::String)),
                ]),
            )
        }
        AccessCmd::Simulate {
            principal_arn,
            action,
            resource,
            profile,
        } => (
            "aws.iam.simulate".into(),
            json_obj([
                ("policy_source_arn", Some(serde_json::json!(principal_arn))),
                ("action_names", Some(serde_json::json!([action]))),
                ("resource_arns", Some(serde_json::json!([resource]))),
                ("profile_id", profile.map(serde_json::Value::String)),
            ]),
        ),
        AccessCmd::User { action } => match action {
            AccessUserCmd::Create {
                cloud,
                name,
                project,
                profile,
            } => {
                let id = match cloud.as_str() {
                    "gcp" => "gcp.iam.service_account.create",
                    _ => "aws.iam.user.create",
                };
                (
                    id.to_string(),
                    json_obj([
                        ("user_name", Some(serde_json::json!(name.clone()))),
                        ("account_id", Some(serde_json::json!(name))),
                        ("project", project.map(serde_json::Value::String)),
                        ("profile_id", profile.map(serde_json::Value::String)),
                    ]),
                )
            }
            AccessUserCmd::Delete {
                cloud,
                name,
                project,
                profile,
            } => {
                let id = match cloud.as_str() {
                    "gcp" => "gcp.iam.service_account.delete",
                    _ => "aws.iam.user.delete",
                };
                (
                    id.to_string(),
                    json_obj([
                        ("user_name", Some(serde_json::json!(name.clone()))),
                        ("email", Some(serde_json::json!(name))),
                        ("project", project.map(serde_json::Value::String)),
                        ("profile_id", profile.map(serde_json::Value::String)),
                    ]),
                )
            }
            AccessUserCmd::Get {
                cloud,
                name,
                profile,
            } => {
                if cloud != "aws" {
                    anyhow::bail!("user get currently implemented for --cloud aws");
                }
                (
                    "aws.iam.user.get".into(),
                    json_obj([
                        ("user_name", Some(serde_json::json!(name))),
                        ("profile_id", profile.map(serde_json::Value::String)),
                    ]),
                )
            }
        },
        AccessCmd::Role { action } => match action {
            AccessRoleCmd::Create {
                cloud,
                name,
                trust_policy,
                assignee,
                scope,
                profile,
            } => {
                if cloud == "azure" {
                    (
                        "azure.iam.role_assignment.create".into(),
                        json_obj([
                            ("role", Some(serde_json::json!(name))),
                            ("assignee", assignee.map(serde_json::Value::String)),
                            ("scope", scope.map(serde_json::Value::String)),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                } else {
                    let trust = trust_policy.ok_or_else(|| {
                        anyhow::anyhow!("--trust-policy JSON required for AWS role create")
                    })?;
                    (
                        "aws.iam.role.create".into(),
                        json_obj([
                            ("role_name", Some(serde_json::json!(name))),
                            (
                                "assume_role_policy_document",
                                Some(serde_json::json!(trust)),
                            ),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                }
            }
            AccessRoleCmd::Delete {
                cloud,
                name,
                assignee,
                role,
                scope,
                profile,
            } => {
                if cloud == "azure" {
                    (
                        "azure.iam.role_assignment.delete".into(),
                        json_obj([
                            ("assignee", assignee.map(serde_json::Value::String)),
                            (
                                "role",
                                role.or(name).map(serde_json::Value::String),
                            ),
                            ("scope", scope.map(serde_json::Value::String)),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                } else {
                    let name = name.ok_or_else(|| anyhow::anyhow!("--name required"))?;
                    (
                        "aws.iam.role.delete".into(),
                        json_obj([
                            ("role_name", Some(serde_json::json!(name))),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                }
            }
            AccessRoleCmd::Get {
                cloud,
                name,
                profile,
            } => {
                if cloud != "aws" {
                    anyhow::bail!("role get currently for --cloud aws");
                }
                (
                    "aws.iam.role.get".into(),
                    json_obj([
                        ("role_name", Some(serde_json::json!(name))),
                        ("profile_id", profile.map(serde_json::Value::String)),
                    ]),
                )
            }
        },
        AccessCmd::Policy { action } => match action {
            AccessPolicyCmd::Create {
                name,
                document,
                profile,
            } => (
                "aws.iam.policy.create".into(),
                json_obj([
                    ("policy_name", Some(serde_json::json!(name))),
                    ("policy_document", Some(serde_json::json!(document))),
                    ("profile_id", profile.map(serde_json::Value::String)),
                ]),
            ),
            AccessPolicyCmd::Delete { arn, profile } => (
                "aws.iam.policy.delete".into(),
                json_obj([
                    ("policy_arn", Some(serde_json::json!(arn))),
                    ("profile_id", profile.map(serde_json::Value::String)),
                ]),
            ),
            AccessPolicyCmd::Attach {
                cloud,
                policy_arn,
                target_type,
                target_name,
                role,
                member,
                project,
                profile,
            } => {
                if cloud == "gcp" {
                    (
                        "gcp.iam.binding.add".into(),
                        json_obj([
                            ("role", role.map(serde_json::Value::String)),
                            ("member", member.map(serde_json::Value::String)),
                            ("project", project.map(serde_json::Value::String)),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                } else {
                    (
                        "aws.iam.policy.attach".into(),
                        json_obj([
                            ("policy_arn", policy_arn.map(serde_json::Value::String)),
                            ("target_type", target_type.map(serde_json::Value::String)),
                            ("target_name", target_name.map(serde_json::Value::String)),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                }
            }
            AccessPolicyCmd::Detach {
                cloud,
                policy_arn,
                target_type,
                target_name,
                role,
                member,
                project,
                profile,
            } => {
                if cloud == "gcp" {
                    (
                        "gcp.iam.binding.remove".into(),
                        json_obj([
                            ("role", role.map(serde_json::Value::String)),
                            ("member", member.map(serde_json::Value::String)),
                            ("project", project.map(serde_json::Value::String)),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                } else {
                    (
                        "aws.iam.policy.detach".into(),
                        json_obj([
                            ("policy_arn", policy_arn.map(serde_json::Value::String)),
                            ("target_type", target_type.map(serde_json::Value::String)),
                            ("target_name", target_name.map(serde_json::Value::String)),
                            ("profile_id", profile.map(serde_json::Value::String)),
                        ]),
                    )
                }
            }
        },
        AccessCmd::Troubleshoot { cloud, symptom } => (
            "access.troubleshoot".into(),
            json_obj([
                ("cloud", Some(serde_json::json!(cloud))),
                ("symptom", symptom.map(serde_json::Value::String)),
            ]),
        ),
    };

    let result = registry.execute(&tool_id, args, &ctx).await;
    if result.ok {
        println!("{}", serde_json::to_string_pretty(&result.data)?);
        eprintln!("{}", result.summary);
        Ok(())
    } else {
        eprintln!("error: {}", result.summary);
        if !result.data.is_null() {
            eprintln!("{}", serde_json::to_string_pretty(&result.data)?);
        }
        anyhow::bail!("access tool `{tool_id}` failed")
    }
}

fn json_profile(profile: Option<String>) -> serde_json::Value {
    json_obj([("profile_id", profile.map(serde_json::Value::String))])
}

fn json_obj(pairs: impl IntoIterator<Item = (&'static str, Option<serde_json::Value>)>) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in pairs {
        if let Some(v) = v {
            m.insert(k.to_string(), v);
        }
    }
    serde_json::Value::Object(m)
}

async fn build_agent(cfg: &OscarConfig, paths: &Paths) -> Result<Agent> {
    let profiles = Arc::new(ProfileStore::load(paths)?);
    let tools = Arc::new(build_registry_with_mcp(cfg).await);
    let provider = create_provider(&cfg.provider).map_err(|e| anyhow::anyhow!(e))?;
    let model = cfg
        .provider
        .model
        .clone()
        .unwrap_or_else(|| provider.default_model());
    let window = provider
        .model_info(&model)
        .map(|m| m.context_window)
        .unwrap_or(128_000);
    let context = ContextManager::new(
        model.clone(),
        window,
        CompactConfig::from(&cfg.context),
    );
    let options = AgentOptions {
        mode: cfg.mode,
        thinking: cfg.thinking.clone(),
        model,
        max_tool_rounds: 12,
    };
    Ok(Agent::new_with_skills(
        provider,
        tools,
        profiles,
        context,
        options,
        cfg.tools.clone(),
        cfg.skills.clone(),
    ))
}

async fn run_mcp(
    action: Option<McpCmd>,
    cfg: &mut OscarConfig,
    paths: &Paths,
) -> Result<()> {
    use oscar_core::{mcp_tool_id, McpServerConfig};
    match action.unwrap_or(McpCmd::List) {
        McpCmd::List => {
            println!("# mcp master_enabled={}", cfg.mcp.enabled);
            println!("# max_output_bytes={}", cfg.mcp.max_output_bytes);
            if cfg.mcp.servers.is_empty() {
                println!("(no servers — oscar mcp example | oscar mcp add …)");
            }
            for (name, s) in &cfg.mcp.servers {
                let state = if s.enabled { "on" } else { "OFF" };
                let cmd = s
                    .command
                    .as_deref()
                    .map(|c| format!("{c} {}", s.args.join(" ")))
                    .or_else(|| s.url.clone())
                    .unwrap_or_else(|| "—".into());
                println!("{state}\t{name}\t{}\t{cmd}", s.transport);
            }
            println!();
            println!("Tools mount as mcp.<server>.<tool> via tools_search — not system prompt.");
        }
        McpCmd::PluginExample => {
            println!("{}", oscar_tools::example_plugin_toml());
            println!("# Install: mkdir -p ~/.config/oscar/plugins && cp this file there");
            println!("# Discover: oscar tools search plugin");
        }
        McpCmd::Example => {
            println!(
                r#"# ~/.config/oscar/config.toml

[mcp]
enabled = true
max_output_bytes = 20000

# stdio server (spawned process)
[mcp.servers.filesystem]
enabled = true
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
install_hint = "npm i -g @modelcontextprotocol/server-filesystem  # or use npx as above"

# remote HTTP / streamable MCP (JSON-RPC POST; optional Mcp-Session-Id)
[mcp.servers.remote]
enabled = false
transport = "http"
url = "https://mcp.example.com/mcp"
# Static bearer (or use oscar mcp set-token / oscar mcp auth):
# headers = {{ Authorization = "Bearer ${{MCP_TOKEN}}" }}
# OAuth PKCE (oscar mcp auth remote):
# oauth_authorize_url = "https://mcp.example.com/oauth/authorize"
# oauth_token_url = "https://mcp.example.com/oauth/token"
# oauth_client_id = "oscar"
# oauth_scopes = "tools"
"#
            );
        }
        McpCmd::Add {
            name,
            command,
            enabled,
            install_hint,
            transport,
            url,
            headers,
        } => {
            let mut sc = McpServerConfig::default();
            sc.enabled = enabled;
            sc.transport = transport.to_ascii_lowercase();
            sc.install_hint = install_hint;
            if sc.transport == "stdio" || sc.transport.is_empty() {
                if command.is_empty() {
                    anyhow::bail!(
                        "usage: oscar mcp add <name> -- <command> [args…]\n       oscar mcp add <name> --transport http --url https://mcp.example/mcp"
                    );
                }
                sc.transport = "stdio".into();
                sc.command = Some(command[0].clone());
                sc.args = command[1..].to_vec();
            } else {
                let u = url.ok_or_else(|| {
                    anyhow::anyhow!("--url is required for transport={}", sc.transport)
                })?;
                sc.url = Some(u);
                for h in headers {
                    if let Some((k, v)) = h.split_once('=') {
                        sc.headers.insert(k.trim().into(), v.trim().into());
                    } else {
                        anyhow::bail!("--header expects KEY=VALUE, got `{h}`");
                    }
                }
            }
            sc.validate(&name).map_err(|e| anyhow::anyhow!(e))?;
            cfg.mcp.servers.insert(name.clone(), sc);
            cfg.save(paths)?;
            println!("added mcp.servers.{name} (enabled={enabled}, transport={})", transport);
            println!("Run: oscar mcp doctor {name}");
        }
        McpCmd::Remove { name } => {
            if cfg.mcp.servers.remove(&name).is_some() {
                cfg.save(paths)?;
                println!("removed {name}");
            } else {
                anyhow::bail!("unknown server `{name}`");
            }
        }
        McpCmd::Enable { name } => {
            let s = cfg
                .mcp
                .servers
                .get_mut(&name)
                .ok_or_else(|| anyhow::anyhow!("unknown `{name}`"))?;
            s.enabled = true;
            cfg.save(paths)?;
            println!("enabled {name}");
        }
        McpCmd::Disable { name } => {
            let s = cfg
                .mcp
                .servers
                .get_mut(&name)
                .ok_or_else(|| anyhow::anyhow!("unknown `{name}`"))?;
            s.enabled = false;
            cfg.save(paths)?;
            println!("disabled {name}");
        }
        McpCmd::Doctor { name } => {
            if !cfg.mcp.enabled {
                println!("mcp.enabled = false in config — enable in [mcp]");
            }
            let statuses = if let Some(n) = name {
                let Some(sc) = cfg.mcp.servers.get(&n) else {
                    anyhow::bail!("unknown server `{n}`");
                };
                let mut one = oscar_core::McpSettings {
                    enabled: true,
                    max_output_bytes: cfg.mcp.max_output_bytes,
                    servers: Default::default(),
                };
                one.servers.insert(n.clone(), sc.clone());
                oscar_mcp::McpManager::doctor_all(&one).await
            } else {
                oscar_mcp::McpManager::doctor_all(&cfg.mcp).await
            };
            for s in statuses {
                let mark = if s.connected { "OK " } else { "BAD" };
                println!(
                    "[{mark}] {} enabled={} tools={} err={}",
                    s.name,
                    s.enabled,
                    s.tool_count,
                    s.error.as_deref().unwrap_or("—")
                );
                if let Some(h) = &s.install_hint {
                    println!("       install: {h}");
                }
                for t in &s.tools {
                    println!("       → {}", mcp_tool_id(&s.name, t));
                }
            }
        }
        McpCmd::Tools => {
            let reg = build_registry_with_mcp(cfg).await;
            let mut n = 0;
            for m in reg.list() {
                if m.id.starts_with("mcp.") {
                    println!(
                        "{}\t{}",
                        m.id,
                        m.description.chars().take(80).collect::<String>()
                    );
                    n += 1;
                }
            }
            println!("# {n} mcp tool(s) mounted into registry");
        }
        McpCmd::Presets => {
            println!("# MCP install presets (oscar mcp install <preset> [--name NAME] [-- extra args])");
            for p in mcp_presets() {
                println!(
                    "{}\n  command: {} {}\n  hint: {}\n",
                    p.name,
                    p.command,
                    p.args.join(" "),
                    p.install_hint
                );
            }
        }
        McpCmd::Reload => {
            // M9: CLI always rebuilds registry on tools/search/execute; doctor reconnects now.
            // TUI sessions should /new or restart agent after config changes.
            println!("# mcp reload — reconnecting enabled servers…");
            if !cfg.mcp.enabled {
                println!("mcp.enabled = false — nothing to remount");
            }
            let statuses = oscar_mcp::McpManager::doctor_all(&cfg.mcp).await;
            let mut ok = 0usize;
            let mut bad = 0usize;
            let mut tools = 0usize;
            for s in &statuses {
                let mark = if s.connected { "OK " } else { "BAD" };
                if s.connected {
                    ok += 1;
                    tools += s.tool_count;
                } else if s.enabled {
                    bad += 1;
                }
                let oauth = oscar_mcp::token_status(paths, &s.name);
                println!(
                    "[{mark}] {} transport={} tools={} {} err={}",
                    s.name,
                    s.transport,
                    s.tool_count,
                    oauth,
                    s.error.as_deref().unwrap_or("—")
                );
            }
            println!(
                "# remount snapshot: connected={ok} failed={bad} tools={tools}"
            );
            println!(
                "# CLI tools_* rebuild MCP on each command. In TUI: /mcp reload"
            );
        }
        McpCmd::Auth { name } => {
            let sc = cfg
                .mcp
                .servers
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("unknown server `{name}` — oscar mcp list"))?
                .clone();
            match oscar_mcp::run_oauth_login(paths, &name, &sc).await {
                Ok(msg) => {
                    println!("{msg}");
                    println!("Run: oscar mcp doctor {name}");
                }
                Err(e) => {
                    eprintln!("oauth failed: {e}");
                    eprintln!(
                        "hint: set oauth_authorize_url / oauth_token_url / oauth_client_id in [mcp.servers.{name}],\nor store a token: oscar mcp set-token {name} --token-file ~/.mcp-token"
                    );
                    anyhow::bail!(e);
                }
            }
        }
        McpCmd::SetToken {
            name,
            token,
            token_file,
        } => {
            if !cfg.mcp.servers.contains_key(&name) {
                eprintln!("warning: `{name}` not in config yet — token stored anyway");
            }
            let tok = if let Some(p) = token_file {
                std::fs::read_to_string(&p)
                    .with_context(|| format!("read {}", p.display()))?
                    .trim()
                    .to_string()
            } else if let Some(t) = token {
                t
            } else {
                anyhow::bail!("provide --token or --token-file");
            };
            if tok.is_empty() {
                anyhow::bail!("empty token");
            }
            oscar_mcp::set_access_token(paths, &name, &tok, None, None, None)
                .map_err(|e| anyhow::anyhow!(e))?;
            println!(
                "stored bearer token for `{name}` at {}",
                paths.mcp_credentials_file.display()
            );
            println!("(file mode 0600 when supported; never printed again)");
            println!("Run: oscar mcp doctor {name}");
        }
        McpCmd::Logout { name } => {
            if oscar_mcp::clear_token(paths, &name).map_err(|e| anyhow::anyhow!(e))? {
                println!("removed stored token for `{name}`");
            } else {
                println!("no stored token for `{name}`");
            }
        }
        McpCmd::Install {
            preset,
            name,
            extra,
            enabled,
        } => {
            let p = mcp_presets()
                .into_iter()
                .find(|x| x.name.eq_ignore_ascii_case(&preset))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown preset `{preset}` — run: oscar mcp presets"
                    )
                })?;
            let server_name = name.unwrap_or_else(|| p.name.to_string());
            if cfg.mcp.servers.contains_key(&server_name) {
                anyhow::bail!(
                    "server `{server_name}` already exists — remove first or pass --name"
                );
            }
            let mut sc = McpServerConfig::default();
            sc.enabled = enabled;
            sc.transport = "stdio".into();
            sc.command = Some(p.command.to_string());
            let mut args: Vec<String> = p.args.iter().map(|s| (*s).to_string()).collect();
            args.extend(extra);
            // filesystem preset needs at least one path
            if p.name == "filesystem"
                && !args
                    .iter()
                    .any(|a| a.starts_with('/') || a == "." || a.starts_with('~'))
            {
                args.push(
                    std::env::current_dir()
                        .map(|d| d.display().to_string())
                        .unwrap_or_else(|_| "/tmp".into()),
                );
            }
            sc.args = args;
            sc.install_hint = Some(p.install_hint.to_string());
            if let Some(cap) = p.capability_default {
                sc.capability_default = Some(cap.to_string());
            }
            sc.validate(&server_name).map_err(|e| anyhow::anyhow!(e))?;
            cfg.mcp.servers.insert(server_name.clone(), sc);
            cfg.save(paths)?;
            println!("installed preset `{}` as mcp.servers.{server_name}", p.name);
            println!("Run: oscar mcp doctor {server_name}");
            println!("Tools mount as mcp.{server_name}.* after next agent start");
        }
    }
    Ok(())
}

struct McpPreset {
    name: &'static str,
    command: &'static str,
    args: Vec<&'static str>,
    install_hint: &'static str,
    capability_default: Option<&'static str>,
}

fn mcp_presets() -> Vec<McpPreset> {
    vec![
        McpPreset {
            name: "filesystem",
            command: "npx",
            args: vec!["-y", "@modelcontextprotocol/server-filesystem"],
            install_hint: "Node + npx (or npm i -g @modelcontextprotocol/server-filesystem)",
            // write_file etc. inferred Write; default Read for safety on list/read
            capability_default: None,
        },
        McpPreset {
            name: "git",
            command: "npx",
            args: vec!["-y", "@modelcontextprotocol/server-git"],
            install_hint: "Node + npx; pass repo path as trailing arg",
            capability_default: None,
        },
        McpPreset {
            name: "memory",
            command: "npx",
            args: vec!["-y", "@modelcontextprotocol/server-memory"],
            install_hint: "Node + npx @modelcontextprotocol/server-memory",
            capability_default: Some("write"),
        },
        McpPreset {
            name: "fetch",
            command: "npx",
            args: vec!["-y", "@modelcontextprotocol/server-fetch"],
            install_hint: "Node + npx @modelcontextprotocol/server-fetch",
            capability_default: Some("read"),
        },
        McpPreset {
            name: "time",
            command: "npx",
            args: vec!["-y", "@modelcontextprotocol/server-time"],
            install_hint: "Node + npx @modelcontextprotocol/server-time",
            capability_default: Some("read"),
        },
        McpPreset {
            name: "sequential-thinking",
            command: "npx",
            args: vec!["-y", "@modelcontextprotocol/server-sequential-thinking"],
            install_hint: "Node + npx @modelcontextprotocol/server-sequential-thinking",
            capability_default: Some("read"),
        },
    ]
}

fn run_identities(action: Option<IdentitiesCmd>, paths: &Paths) -> Result<()> {
    use oscar_identity::{
        build_identity_inventory, build_identity_inventory_quick, BinaryInventory, ProfileStore,
        Validity,
    };
    let store = ProfileStore::load(paths)?;
    let action = action.unwrap_or(IdentitiesCmd::Check);
    let inv = match action {
        IdentitiesCmd::List => build_identity_inventory_quick(&store),
        IdentitiesCmd::Check | IdentitiesCmd::Json => {
            let binaries = BinaryInventory::detect();
            build_identity_inventory(&store, &binaries)
        }
    };
    if matches!(action, IdentitiesCmd::Json) {
        println!("{}", serde_json::to_string_pretty(&inv)?);
        return Ok(());
    }

    println!("┌─ oscar identities (by CSP: AWS · GCP · Azure · K8s · LLM) ─────┐");
    println!("│  {}  │", inv.summary_line());
    println!("└──────────────────────────────────────────────────────────────┘");
    // Group print order for clear CSP distinction
    let order = ["aws", "gcp", "azure", "k8s", "llm", "multi"];
    let mut shown: std::collections::HashSet<String> = std::collections::HashSet::new();
    for csp in order {
        let group: Vec<_> = inv.entries.iter().filter(|e| e.cloud == csp).collect();
        if group.is_empty() {
            continue;
        }
        let tag = match csp {
            "aws" => "[AWS]",
            "gcp" => "[GCP]",
            "azure" => "[AZURE]",
            "k8s" => "[K8S]",
            "llm" => "[LLM]",
            _ => "[MULTI]",
        };
        println!("  {tag}");
        for e in group {
            shown.insert(e.id.clone());
            let mark = match e.validity {
                Validity::Valid => "OK ",
                Validity::Expired => "EXP",
                Validity::Invalid => "BAD",
                Validity::Missing => "---",
                Validity::Unknown => "???",
            };
            println!("    [{mark}] {:12} {}", format!("{:?}", e.kind), e.id);
            println!("         source={}  {}", e.auth_source, e.detail);
            if !e.secrets_present.is_empty() {
                println!(
                    "         secrets: {} (names only)",
                    e.secrets_present.join(", ")
                );
            }
            for c in &e.clusters {
                println!(
                    "         k8s [{}] {} — {}",
                    c.validity.glyph(),
                    c.name,
                    c.detail
                );
            }
        }
    }
    // Any leftover clouds (shouldn't happen)
    for e in &inv.entries {
        if shown.contains(&e.id) {
            continue;
        }
        println!(
            "  [{}] {:?} {} {}",
            e.cloud,
            e.kind,
            e.id,
            e.detail
        );
    }
    for n in &inv.notes {
        println!("  note: {n}");
    }
    println!();
    println!("TUI: oscar → /identities or Ctrl+I");
    println!("CLI: oscar identities check | list | json");
    Ok(())
}

fn run_skills(action: Option<SkillsCmd>, cfg: &OscarConfig) -> Result<()> {
    use oscar_core::{discover_skills, find_skill, user_skills_dir};
    match action.unwrap_or(SkillsCmd::List) {
        SkillsCmd::List => {
            let skills = discover_skills(&cfg.skills);
            println!("# oscar skills ({} found)", skills.len());
            for s in &skills {
                println!("  {}  [{}]", s.name, s.source);
                println!("      {}", s.description);
                if let Some(w) = &s.when_to_use {
                    println!("      when: {w}");
                }
            }
            println!();
            println!("Show: oscar skills show <name>");
            println!("Chat: /skill <name>  |  Agent: system.skills.get");
        }
        SkillsCmd::Show { name } => {
            match find_skill(&name, &cfg.skills) {
                Some(s) => {
                    println!("# {} ({})", s.name, s.source);
                    if let Some(p) = &s.path {
                        println!("# path: {p}");
                    }
                    println!("# {}", s.description);
                    println!();
                    println!("{}", s.body);
                }
                None => anyhow::bail!("unknown skill `{name}`"),
            }
        }
        SkillsCmd::Path => {
            println!("project: ./.oscar/skills/<name>/SKILL.md");
            if let Some(u) = user_skills_dir() {
                println!("user:    {}/<name>/SKILL.md", u.display());
            }
            println!("builtin: shipped with oscar (least-privilege-iam, network-vlsm-path, k8s-cni-connectivity, discovery-intent, permission-test-plan)");
            for p in &cfg.skills.paths {
                println!("extra:   {p}");
            }
        }
    }
    Ok(())
}

fn run_binaries(action: Option<BinariesCmd>, cfg: &OscarConfig) -> Result<()> {
    let inv = BinaryInventory::detect();
    match action.unwrap_or(BinariesCmd::List) {
        BinariesCmd::List => {
            println!("{}", serde_json::to_string_pretty(&inv)?);
            eprintln!("{}", inv.agent_summary());
            eprintln!(
                "install_policy={} (oscar settings install-policy …)",
                cfg.tools.install_binaries.as_str()
            );
        }
        BinariesCmd::Plan { all } => {
            let wanted = if all {
                critical_csp_binaries()
            } else {
                critical_csp_binaries()
                    .into_iter()
                    .filter(|b| binary_cloud_enabled(b, &cfg.tools))
                    .collect()
            };
            let plan = plan_install(&wanted, &inv);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            if plan.commands.is_empty() {
                eprintln!("nothing to install (or no package manager mapping)");
            } else {
                eprintln!("To install: oscar binaries install --yes");
            }
        }
        BinariesCmd::Install { yes, all } => {
            if !yes {
                anyhow::bail!("refusing to install without --yes (may run sudo)");
            }
            if matches!(cfg.tools.install_binaries, InstallBinariesPolicy::Off) {
                anyhow::bail!(
                    "install_binaries policy is off — set: oscar settings install-policy recommend|ask-admin|install-all"
                );
            }
            let wanted = if all
                || matches!(cfg.tools.install_binaries, InstallBinariesPolicy::InstallAll)
            {
                critical_csp_binaries()
                    .into_iter()
                    .filter(|b| binary_cloud_enabled(b, &cfg.tools))
                    .collect()
            } else {
                critical_csp_binaries()
                    .into_iter()
                    .filter(|b| binary_cloud_enabled(b, &cfg.tools))
                    .collect::<Vec<_>>()
            };
            let plan = plan_install(&wanted, &inv);
            if plan.commands.is_empty() {
                println!("nothing to install");
                return Ok(());
            }
            eprintln!("running:");
            for c in &plan.commands {
                eprintln!("  $ {c}");
            }
            let (ok, out) = run_install_commands(&plan.commands);
            print!("{out}");
            let inv2 = BinaryInventory::detect();
            eprintln!("{}", inv2.agent_summary());
            if !ok {
                anyhow::bail!("one or more install commands failed");
            }
        }
    }
    Ok(())
}

fn binary_cloud_enabled(binary: &str, settings: &ToolsSettings) -> bool {
    match binary {
        "aws" => settings.is_cloud_enabled("aws"),
        "gcloud" => settings.is_cloud_enabled("gcp"),
        "az" => settings.is_cloud_enabled("azure"),
        "kubectl" | "helm" => settings.is_cloud_enabled("k8s"),
        _ => true,
    }
}

fn run_settings(
    action: Option<SettingsCmd>,
    cfg: &mut OscarConfig,
    paths: &Paths,
) -> Result<()> {
    match action.unwrap_or(SettingsCmd::Show) {
        SettingsCmd::Show => {
            print_settings(cfg);
        }
        SettingsCmd::Tools => {
            let registry = build_registry();
            for m in registry.list() {
                let state = if cfg.tools.is_tool_enabled(&m.id) {
                    "on"
                } else {
                    "OFF"
                };
                println!("{state}\t{}\t{}", m.id, m.name);
            }
        }
        SettingsCmd::DisableTool { id } => {
            cfg.tools.disable_tool(&id);
            cfg.save(paths)?;
            println!("disabled tool `{id}` (omitted from tools_search)");
        }
        SettingsCmd::EnableTool { id } => {
            cfg.tools.enable_tool(&id);
            cfg.save(paths)?;
            println!("enabled tool `{id}`");
        }
        SettingsCmd::DisableCloud { cloud } => {
            let c = normalize_cloud_name(&cloud)?;
            cfg.tools.disable_cloud(&c);
            cfg.save(paths)?;
            println!(
                "disabled cloud `{c}` — related tools hidden from search/execute"
            );
        }
        SettingsCmd::EnableCloud { cloud } => {
            let c = normalize_cloud_name(&cloud)?;
            cfg.tools.enable_cloud(&c);
            cfg.save(paths)?;
            println!("enabled cloud `{c}`");
        }
        SettingsCmd::InstallPolicy { policy } => {
            let p = InstallBinariesPolicy::parse(&policy).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid policy `{policy}` — use off | recommend | ask-admin | install-all"
                )
            })?;
            cfg.tools.install_binaries = p;
            cfg.save(paths)?;
            println!("install_binaries policy = {}", p.as_str());
            match p {
                InstallBinariesPolicy::Off => {
                    println!("agent will only report missing binaries; no install prompts");
                }
                InstallBinariesPolicy::Recommend => {
                    println!("agent recommends install commands; does not request elevation");
                }
                InstallBinariesPolicy::AskAdmin => {
                    println!(
                        "agent may request admin install; approve with `approve install` in chat or `oscar binaries install --yes`"
                    );
                }
                InstallBinariesPolicy::InstallAll => {
                    println!(
                        "agent prefers full binary set for enabled tools/clouds; still needs `approve install` for sudo"
                    );
                }
            }
        }
        SettingsCmd::AllowAdminPrompt { value } => {
            let on = matches!(value.to_ascii_lowercase().as_str(), "on" | "true" | "1" | "yes");
            let off = matches!(value.to_ascii_lowercase().as_str(), "off" | "false" | "0" | "no");
            if !on && !off {
                anyhow::bail!("use on|off");
            }
            cfg.tools.allow_admin_install_prompt = on;
            cfg.save(paths)?;
            println!("allow_admin_install_prompt = {on}");
        }
        SettingsCmd::Menu => {
            run_settings_menu(cfg, paths)?;
        }
    }
    Ok(())
}

fn normalize_cloud_name(cloud: &str) -> Result<String> {
    match cloud.to_ascii_lowercase().as_str() {
        "aws" => Ok("aws".into()),
        "gcp" | "google" => Ok("gcp".into()),
        "azure" | "az" => Ok("azure".into()),
        "k8s" | "kubernetes" | "kube" => Ok("k8s".into()),
        other => anyhow::bail!("unknown cloud `{other}` — aws | gcp | azure | k8s"),
    }
}

fn print_settings(cfg: &OscarConfig) {
    let s = &cfg.tools;
    let on = |b: bool| if b { "[on ]" } else { "[off]" };
    let row = |label: &str, value: &str| {
        println!("│  {:<18} {:<32} │", label, value);
    };
    println!("┌──────────────────────────────────────────────────────┐");
    println!("│  oscar settings                                       │");
    println!("│  ~/.config/oscar/config.toml                          │");
    println!("├──────────────────────────────────────────────────────┤");
    row("mode", &cfg.mode.to_string());
    row("provider", &cfg.provider.id);
    row("install_binaries", s.install_binaries.as_str());
    row("admin_install", on(s.allow_admin_install_prompt));
    row("show_thinking", on(cfg.ui.show_thinking));
    println!("├──────────────────────────────────────────────────────┤");
    println!("│  Clouds                                              │");
    for c in ["aws", "gcp", "azure", "k8s"] {
        row(&format!("  {c}"), on(s.is_cloud_enabled(c)));
    }
    println!("├──────────────────────────────────────────────────────┤");
    row("disabled_tools", &format!("{}", s.disabled.len()));
    for id in s.disabled.iter().take(6) {
        let short = if id.len() > 40 {
            format!("{}...", &id[..37])
        } else {
            id.clone()
        };
        row("  off", &short);
    }
    if s.disabled.len() > 6 {
        row("  ...", &format!("+{} more", s.disabled.len() - 6));
    }
    println!("└──────────────────────────────────────────────────────┘");
    println!();
    println!("  TUI:  oscar   →  /settings  or  Ctrl+,");
    println!("  CLI:  oscar settings menu");
    println!("        oscar settings disable-cloud gcp");
    println!("        oscar settings install-policy install-all");
    println!("        oscar settings tools");
}

fn run_settings_menu(cfg: &mut OscarConfig, paths: &Paths) -> Result<()> {
    use std::io::{self, Write};
    loop {
        println!();
        print_settings(cfg);
        println!();
        println!("┌─ interactive menu ───────────────────────────────────────┐");
        println!("│  Clouds                                                  │");
        println!("│    1 aws   2 gcp   3 azure   4 k8s   (toggle)            │");
        println!("│    a  AWS-only preset   m  enable all clouds             │");
        println!("│  Install policy                                          │");
        println!("│    5 off  6 recommend  7 ask-admin  8 install-all        │");
        println!("│    9 toggle allow_admin_install_prompt                   │");
        println!("│  Agent                                                   │");
        println!("│    r readonly   w readwrite   i toggle show_thinking     │");
        println!("│  Tools                                                   │");
        println!("│    t list   d <id> disable   e <id> enable   c clear off │");
        println!("│  q quit                                                  │");
        println!("└──────────────────────────────────────────────────────────┘");
        print!("settings> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "q" || line == "quit" {
            break;
        }
        if line == "t" {
            let registry = build_registry();
            println!("state  id");
            for m in registry.list() {
                let state = if cfg.tools.is_tool_enabled(&m.id) {
                    "●"
                } else {
                    "○"
                };
                println!("{state}  {}", m.id);
            }
            continue;
        }
        if line == "c" {
            cfg.tools.disabled.clear();
            cfg.save(paths)?;
            println!("re-enabled all tools");
            continue;
        }
        if line == "a" {
            cfg.tools.enable_cloud("aws");
            for c in ["gcp", "azure", "k8s"] {
                cfg.tools.disable_cloud(c);
            }
            cfg.save(paths)?;
            println!("preset: AWS only");
            continue;
        }
        if line == "m" {
            for c in ["aws", "gcp", "azure", "k8s"] {
                cfg.tools.enable_cloud(c);
            }
            cfg.save(paths)?;
            println!("all clouds enabled");
            continue;
        }
        if line == "r" {
            cfg.mode = ExecutionMode::ReadOnly;
            cfg.save(paths)?;
            continue;
        }
        if line == "w" {
            cfg.mode = ExecutionMode::ReadWrite;
            cfg.save(paths)?;
            continue;
        }
        if line == "i" {
            cfg.ui.show_thinking = !cfg.ui.show_thinking;
            cfg.save(paths)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("d ") {
            cfg.tools.disable_tool(rest.trim());
            cfg.save(paths)?;
            println!("disabled {}", rest.trim());
            continue;
        }
        if let Some(rest) = line.strip_prefix("e ") {
            cfg.tools.enable_tool(rest.trim());
            cfg.save(paths)?;
            println!("enabled {}", rest.trim());
            continue;
        }
        match line {
            "1" => toggle_cloud_menu(cfg, paths, "aws")?,
            "2" => toggle_cloud_menu(cfg, paths, "gcp")?,
            "3" => toggle_cloud_menu(cfg, paths, "azure")?,
            "4" => toggle_cloud_menu(cfg, paths, "k8s")?,
            "5" => {
                cfg.tools.install_binaries = InstallBinariesPolicy::Off;
                cfg.save(paths)?;
            }
            "6" => {
                cfg.tools.install_binaries = InstallBinariesPolicy::Recommend;
                cfg.save(paths)?;
            }
            "7" => {
                cfg.tools.install_binaries = InstallBinariesPolicy::AskAdmin;
                cfg.save(paths)?;
            }
            "8" => {
                cfg.tools.install_binaries = InstallBinariesPolicy::InstallAll;
                cfg.save(paths)?;
            }
            "9" => {
                cfg.tools.allow_admin_install_prompt = !cfg.tools.allow_admin_install_prompt;
                cfg.save(paths)?;
            }
            _ => println!("unknown choice — see menu"),
        }
    }
    Ok(())
}

fn toggle_cloud_menu(cfg: &mut OscarConfig, paths: &Paths, cloud: &str) -> Result<()> {
    if cfg.tools.is_cloud_enabled(cloud) {
        cfg.tools.disable_cloud(cloud);
        println!("disabled cloud {cloud}");
    } else {
        cfg.tools.enable_cloud(cloud);
        println!("enabled cloud {cloud}");
    }
    cfg.save(paths)?;
    Ok(())
}

async fn run_ask(
    cfg: OscarConfig,
    paths: Paths,
    prompt: String,
    stream: bool,
    output: Option<String>,
) -> Result<()> {
    let mut agent = build_agent(&cfg, &paths).await?;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(256);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();

    let handle = tokio::spawn(async move {
        agent.run_turn(prompt, tx, cancel2).await;
        agent
    });

    let mut content = String::new();
    let mut usage = None;
    while let Some(ev) = rx.recv().await {
        if stream {
            println!("{}", serde_json::to_string(&ev)?);
        } else {
            match &ev {
                AgentEvent::ContentDelta { text } => {
                    content.push_str(text);
                    print!("{text}");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                AgentEvent::ThinkingDelta { text } if cfg.thinking.is_on() => {
                    eprint!("{text}");
                }
                AgentEvent::ToolStart { tool_id, .. } => {
                    eprintln!("[tool] {tool_id}");
                }
                AgentEvent::ToolEnd { tool_id, summary } => {
                    eprintln!("[tool] {tool_id}: {summary}");
                }
                AgentEvent::Error { message } => {
                    eprintln!("error: {message}");
                }
                AgentEvent::Done { usage: u } => {
                    usage = u.clone();
                    if !content.is_empty() && !content.ends_with('\n') {
                        println!();
                    }
                }
                AgentEvent::ContextUsage(s) => {
                    eprintln!(
                        "[ctx] {}/{} ({:.0}%)",
                        s.used_tokens, s.context_window, s.percent
                    );
                }
                AgentEvent::InstallApprovalRequired {
                    packages,
                    commands,
                    reason,
                    install_all,
                } => {
                    eprintln!(
                        "[install-approval{}] {reason}",
                        if *install_all { " install-all" } else { "" }
                    );
                    if !packages.is_empty() {
                        eprintln!("  packages: {}", packages.join(", "));
                    }
                    for c in commands {
                        eprintln!("  $ {c}");
                    }
                    eprintln!(
                        "  approve: oscar binaries install --yes  |  chat: approve install"
                    );
                }
                AgentEvent::InstallCompleted { ok, summary } => {
                    eprintln!("[install {}] {summary}", if *ok { "ok" } else { "fail" });
                }
                _ => {}
            }
        }
        if matches!(ev, AgentEvent::Done { .. }) {
            break;
        }
    }

    let _agent = handle.await?;

    if let Some(fmt) = output {
        if fmt == "json" {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "content": content,
                    "usage": usage,
                }))?
            );
        }
    }
    Ok(())
}

async fn run_chat(cfg: OscarConfig, paths: Paths) -> Result<()> {
    run_chat_with_session(cfg, paths, None).await
}

async fn run_chat_with_session(
    cfg: OscarConfig,
    paths: Paths,
    resume_id: Option<String>,
) -> Result<()> {
    let profiles = ProfileStore::load(&paths)?;
    let profile_count = profiles.list().len();

    // Build provider early to resolve model name for status bar; agent rebuilt per turn host.
    let provider_result = create_provider(&cfg.provider);
    let (provider_id, model) = match &provider_result {
        Ok(p) => {
            let model = cfg
                .provider
                .model
                .clone()
                .unwrap_or_else(|| p.default_model());
            (p.id().to_string(), model)
        }
        Err(e) => {
            eprintln!("warning: provider not ready ({e}). Chat will error until API key is set.");
            (
                cfg.provider.id.clone(),
                cfg.provider.model.clone().unwrap_or_else(|| "—".into()),
            )
        }
    };

    let tool_catalog: Vec<ToolCatalogEntry> = {
        let reg = build_registry();
        reg.list()
            .into_iter()
            .map(|m| ToolCatalogEntry {
                id: m.id,
                name: m.name,
                domain: m.domain.to_string(),
                cloud: m
                    .clouds
                    .first()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "multi".into()),
            })
            .collect()
    };

    let mut app = App::new(AppConfig {
        provider: provider_id.clone(),
        model: model.clone(),
        mode: cfg.mode,
        show_thinking: cfg.ui.show_thinking || cfg.thinking.is_on(),
        profile_count,
        oscar_config: cfg.clone(),
        tool_catalog,
        profiles_path: paths.profiles_file.clone(),
        provider_ready: provider_result.is_ok(),
    });

    // Load or create persistent chat session (Grok Build–style history)
    let mut stored = if let Some(id) = resume_id {
        oscar_core::load_session(&paths, &id).unwrap_or_else(|_| {
            oscar_core::StoredChatSession::new(&provider_id, &model, cfg.mode.to_string())
        })
    } else {
        oscar_core::load_current_or_latest(&paths)?
            .unwrap_or_else(|| {
                oscar_core::StoredChatSession::new(&provider_id, &model, cfg.mode.to_string())
            })
    };
    // Ensure transcript has at least bootstrap line
    if stored.transcript.is_empty() {
        stored.transcript = transcript_from_messages(&stored.messages);
    }
    app.load_transcript(&stored.transcript, &stored.id, &stored.title);
    let created_at = stored.created_at;

    let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(256);
    let (user_tx, mut user_rx) = mpsc::channel::<String>(32);
    let (secret_tx, mut secret_rx) = mpsc::channel(8);
    let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(8);
    let (config_tx, mut config_rx) = mpsc::channel::<OscarConfig>(8);
    let (session_tx, session_rx) = mpsc::channel::<oscar_core::StoredChatSession>(4);
    let (transcript_tx, mut transcript_rx) = mpsc::channel::<Vec<oscar_core::TranscriptLine>>(8);

    let mut agent = match provider_result {
        Ok(_) => {
            let mut a = build_agent(&cfg, &paths).await?;
            a.load_chat_history(&stored);
            a.session.id = stored.id.clone();
            a.session.title = stored.title.clone();
            Some(a)
        }
        Err(_) => None,
    };

    // Push initial session to TUI (already loaded on app; keep channel for resume mid-run)
    let _ = session_tx.send(stored.clone()).await;

    let tui_handle = tokio::spawn(async move {
        run_tui(
            app,
            event_rx,
            user_tx,
            secret_tx,
            cancel_tx,
            config_tx,
            session_rx,
            transcript_tx,
        )
        .await
    });

    let event_tx_host = event_tx.clone();
    let session_tx_host = session_tx.clone();
    let host = tokio::spawn(async move {
        let mut cancel = CancellationToken::new();
        let mut cfg = cfg;
        let mut stored = stored;
        let created_at = created_at;
        loop {
            // Pull latest TUI transcript for saves
            while let Ok(tr) = transcript_rx.try_recv() {
                stored.transcript = tr;
            }
            tokio::select! {
                biased;
                Some(()) = cancel_rx.recv() => {
                    cancel.cancel();
                    cancel = CancellationToken::new();
                }
                Some(tr) = transcript_rx.recv() => {
                    stored.transcript = tr;
                    if let Some(a) = agent.as_ref() {
                        persist_chat(&paths, &mut stored, a, created_at);
                    }
                }
                Some(new_cfg) = config_rx.recv() => {
                    let provider_changed = new_cfg.provider.id != cfg.provider.id
                        || new_cfg.provider.model != cfg.provider.model;
                    cfg = new_cfg;
                    if let Err(e) = cfg.save(&paths) {
                        let _ = event_tx_host
                            .send(AgentEvent::Error {
                                message: format!("failed to save settings: {e}"),
                            })
                            .await;
                        continue;
                    }
                    // Hot-reload tools/mode; rebuild agent if provider/model changed.
                    if provider_changed {
                        let pending = agent.as_ref().and_then(|a| a.pending_retry.clone());
                        let pending_install =
                            agent.as_ref().and_then(|a| a.pending_install.clone());
                        let old_msgs = agent.as_ref().map(|a| a.session.messages.clone());
                        let old_id = agent.as_ref().map(|a| a.session.id.clone());
                        let old_title = agent.as_ref().map(|a| a.session.title.clone());
                        let old_skills = agent.as_ref().map(|a| a.active_skills.clone());
                        match build_agent(&cfg, &paths).await {
                            Ok(mut a) => {
                                a.pending_retry = pending;
                                a.pending_install = pending_install;
                                if let Some(msgs) = old_msgs {
                                    a.session.messages = msgs;
                                }
                                if let Some(id) = old_id {
                                    a.session.id = id;
                                }
                                if let Some(t) = old_title {
                                    a.session.title = t;
                                }
                                if let Some(sk) = old_skills {
                                    a.active_skills = sk;
                                }
                                a.refresh_system();
                                agent = Some(a);
                            }
                            Err(e) => {
                                let _ = event_tx_host
                                    .send(AgentEvent::Error { message: e.to_string() })
                                    .await;
                            }
                        }
                    } else if let Some(a) = agent.as_mut() {
                        a.reload_settings(cfg.tools.clone());
                        a.session.mode = cfg.mode;
                        a.session.thinking = cfg.thinking.clone();
                        a.session.context.config.auto = cfg.context.auto;
                        a.session.context.config.threshold = cfg.context.threshold;
                        a.session.context.config.keep_latest_thinking =
                            cfg.context.keep_latest_thinking;
                    } else if create_provider(&cfg.provider).is_ok() {
                        match build_agent(&cfg, &paths).await {
                            Ok(mut a) => {
                                a.load_chat_history(&stored);
                                a.session.id = stored.id.clone();
                                agent = Some(a);
                            }
                            Err(e) => {
                                let _ = event_tx_host
                                    .send(AgentEvent::Error { message: e.to_string() })
                                    .await;
                            }
                        }
                    }
                    let _ = event_tx_host
                        .send(AgentEvent::ContentDelta {
                            text: format!(
                                "\n[settings applied] mode={} provider={} install={} clouds_off=[{}] tools_off={}\n",
                                cfg.mode,
                                cfg.provider.id,
                                cfg.tools.install_binaries.as_str(),
                                cfg.tools.disabled_clouds.join(", "),
                                cfg.tools.disabled.len(),
                            ),
                        })
                        .await;
                    let _ = event_tx_host
                        .send(AgentEvent::Done { usage: None })
                        .await;
                }
                Some((auth, kind, secret)) = secret_rx.recv() => {
                    // Store secret into keychain only — never log value or send it to the agent/model.
                    use oscar_core::SecretKind;
                    let secret_len = secret.len();

                    // LLM provider key paste: profile_hint = "provider:<id>"
                    if kind == SecretKind::ApiKey {
                        if let Some(hint) = auth.profile_hint.as_deref() {
                            if let Some(pid) = hint.strip_prefix("provider:") {
                                match store_provider_api_key(pid, &secret) {
                                    Ok(()) => {
                                        drop(secret);
                                        cfg.provider.id = pid.to_string();
                                        let _ = cfg.save(&paths);
                                        let _ = event_tx_host
                                            .send(AgentEvent::ContentDelta {
                                                text: format!(
                                                    "\n[secure bar] stored API key for provider `{pid}` ({secret_len} bytes) — value NOT visible to agent. Building agent…\n"
                                                ),
                                            })
                                            .await;
                                        match build_agent(&cfg, &paths).await {
                                            Ok(mut a) => {
                                                a.load_chat_history(&stored);
                                                a.session.id = stored.id.clone();
                                                a.session.title = stored.title.clone();
                                                agent = Some(a);
                                                let _ = event_tx_host
                                                    .send(AgentEvent::ContentDelta {
                                                        text: format!(
                                                            "\n[provider ready: {pid} — you can chat now]\n"
                                                        ),
                                                    })
                                                    .await;
                                            }
                                            Err(e) => {
                                                let _ = event_tx_host
                                                    .send(AgentEvent::Error {
                                                        message: format!(
                                                            "Provider key stored but agent still not ready: {e}"
                                                        ),
                                                    })
                                                    .await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        drop(secret);
                                        let _ = event_tx_host
                                            .send(AgentEvent::Error {
                                                message: format!("failed to store provider key: {e}"),
                                            })
                                            .await;
                                    }
                                }
                                continue;
                            }
                        }
                    }

                    let mut store = match ProfileStore::load(&paths) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = event_tx_host.send(AgentEvent::Error { message: e.to_string() }).await;
                            continue;
                        }
                    };
                    let profile_id = auth.profile_hint.clone().unwrap_or_else(|| {
                        format!("{}-default", auth.cloud)
                    });
                    if store.get(&profile_id).is_none() {
                        let mut p = Profile::new(auth.cloud, "default", "unknown");
                        p.id = profile_id.clone();
                        p.secret_keyring_id = format!("oscar/{profile_id}");
                        store.upsert(p);
                        let _ = store.save();
                    }
                    let mut all_kinds_ready = false;
                    if let Some(p) = store.get(&profile_id) {
                        if let Err(e) = KeychainStore::set(&p.secret_keyring_id, kind, &secret) {
                            let _ = event_tx_host.send(AgentEvent::Error { message: e.to_string() }).await;
                        } else {
                            // Field-by-field secure paste (e.g. access_key_id → secret → session_token).
                            all_kinds_ready = auth.kinds.iter().all(|k| {
                                KeychainStore::has(&p.secret_keyring_id, *k)
                            });
                            let msg = if all_kinds_ready {
                                format!(
                                    "\n[secure bar] stored {kind:?} for profile `{profile_id}` ({secret_len} bytes) — value NOT visible to agent. All requested fields present; auto-retrying paused tool.\n"
                                )
                            } else {
                                format!(
                                    "\n[secure bar] stored {kind:?} for profile `{profile_id}` ({secret_len} bytes) — value NOT visible to agent. Enter next field in the secure bar (still not shown to the agent).\n"
                                )
                            };
                            let _ = event_tx_host
                                .send(AgentEvent::ContentDelta { text: msg })
                                .await;
                        }
                        drop(secret);
                    }
                    // Preserve pending retry + install + preferred profile across rebuild.
                    let pending = agent.as_ref().and_then(|a| a.pending_retry.clone());
                    let pending_install = agent.as_ref().and_then(|a| a.pending_install.clone());
                    let preferred = agent
                        .as_ref()
                        .and_then(|a| a.preferred_profile_id.clone())
                        .or_else(|| Some(profile_id.clone()));
                    match build_agent(&cfg, &paths).await {
                        Ok(mut a) => {
                            a.pending_retry = pending;
                            a.pending_install = pending_install;
                            a.preferred_profile_id = preferred;
                            a.refresh_system();
                            // Only resume when all auth kinds for this request are in keychain
                            // (short-lived keys are multi-field: access + secret + session token).
                            if a.pending_retry.is_some() && all_kinds_ready {
                                cancel = CancellationToken::new();
                                a.resume_after_auth(event_tx_host.clone(), cancel.clone()).await;
                            }
                            agent = Some(a);
                        }
                        Err(e) => {
                            let _ = event_tx_host.send(AgentEvent::Error { message: e.to_string() }).await;
                        }
                    }
                }
                Some(user) = user_rx.recv() => {
                    // Session history slash commands
                    let ut = user.trim();
                    if ut == "/new" {
                        if let Some(a) = agent.as_mut() {
                            a.new_chat();
                            stored = oscar_core::StoredChatSession::new(
                                &a.provider_id,
                                &a.model_id,
                                a.session.mode.to_string(),
                            );
                            stored.id = a.session.id.clone();
                            stored.created_at = chrono::Utc::now();
                            stored.transcript = vec![oscar_core::TranscriptLine {
                                kind: "system".into(),
                                text: format!(
                                    "New chat `{}` · auto-saves after each turn · /history",
                                    &stored.id[..stored.id.len().min(8)]
                                ),
                            }];
                            let _ = oscar_core::save_session(&paths, &stored);
                            let _ = session_tx_host.send(stored.clone()).await;
                            let _ = event_tx_host
                                .send(AgentEvent::ContentDelta {
                                    text: format!(
                                        "\n[new chat {} — history cleared for this view]\n",
                                        &stored.id[..8.min(stored.id.len())]
                                    ),
                                })
                                .await;
                            let _ = event_tx_host.send(AgentEvent::Done { usage: None }).await;
                        }
                        continue;
                    }
                    if ut == "/history" || ut == "/sessions" || ut.starts_with("/history ") {
                        match oscar_core::list_sessions(&paths) {
                            Ok(list) => {
                                let mut lines = vec![
                                    "# chat history (~/.config/oscar/sessions/)".into(),
                                    format!("current: {}", stored.id),
                                    String::new(),
                                ];
                                if list.is_empty() {
                                    lines.push("(no sessions yet — chat will auto-save)".into());
                                }
                                for s in list.iter().take(30) {
                                    let cur = if s.id == stored.id { "*" } else { " " };
                                    lines.push(format!(
                                        "{cur} {}  {}  msgs={}  {}\n    {}",
                                        &s.id[..s.id.len().min(8)],
                                        s.updated_at.format("%Y-%m-%d %H:%M"),
                                        s.message_count,
                                        s.title,
                                        s.preview
                                    ));
                                }
                                lines.push(String::new());
                                lines.push("Resume: /resume <id>   New: /new   CLI: oscar sessions list".into());
                                let _ = event_tx_host
                                    .send(AgentEvent::ContentDelta {
                                        text: format!("{}\n", lines.join("\n")),
                                    })
                                    .await;
                            }
                            Err(e) => {
                                let _ = event_tx_host
                                    .send(AgentEvent::Error {
                                        message: e.to_string(),
                                    })
                                    .await;
                            }
                        }
                        let _ = event_tx_host.send(AgentEvent::Done { usage: None }).await;
                        continue;
                    }
                    if let Some(id) = ut.strip_prefix("/resume ").or_else(|| ut.strip_prefix("/session ")) {
                        let id = id.trim();
                        // Allow short prefix match
                        let resolved = resolve_session_id(&paths, id);
                        match resolved.and_then(|rid| oscar_core::load_session(&paths, &rid).ok()) {
                            Some(s) => {
                                stored = s;
                                if let Some(a) = agent.as_mut() {
                                    a.load_chat_history(&stored);
                                    a.session.id = stored.id.clone();
                                    a.session.title = stored.title.clone();
                                }
                                let _ = oscar_core::set_current_session_id(&paths, &stored.id);
                                let _ = session_tx_host.send(stored.clone()).await;
                                let _ = event_tx_host
                                    .send(AgentEvent::ContentDelta {
                                        text: format!(
                                            "\n[resumed «{}» {}]\n",
                                            stored.title,
                                            &stored.id[..stored.id.len().min(8)]
                                        ),
                                    })
                                    .await;
                            }
                            None => {
                                let _ = event_tx_host
                                    .send(AgentEvent::Error {
                                        message: format!(
                                            "session not found: {id} — /history to list"
                                        ),
                                    })
                                    .await;
                            }
                        }
                        let _ = event_tx_host.send(AgentEvent::Done { usage: None }).await;
                        continue;
                    }
                    // Slash commands handled partly in TUI; host handles agent-related ones.
                    if user.starts_with('/') {
                        if user.trim() == "/binaries" || user.starts_with("/binaries ") {
                            if let Some(a) = agent.as_mut() {
                                a.refresh_binaries();
                                let _ = event_tx_host
                                    .send(AgentEvent::ContentDelta {
                                        text: format!(
                                            "\n{}\ninstall_policy={}\n",
                                            a.binaries.agent_summary(),
                                            a.settings.install_binaries.as_str()
                                        ),
                                    })
                                    .await;
                                let _ = event_tx_host
                                    .send(AgentEvent::Done { usage: None })
                                    .await;
                            }
                            continue;
                        }
                        handle_slash(&user, &mut agent, &mut cfg, &paths, &event_tx_host).await;
                        continue;
                    }
                    let Some(agent) = agent.as_mut() else {
                        let _ = event_tx_host.send(AgentEvent::Error {
                            message: "No LLM provider configured. Opening Provider setup — select a provider and paste an API key (secure bar), or run: oscar auth provider-key --provider …".into(),
                        }).await;
                        let _ = event_tx_host.send(AgentEvent::Done { usage: None }).await;
                        continue;
                    };
                    cancel = CancellationToken::new();
                    let low = user.trim().to_ascii_lowercase();
                    // Admin install approval (agent emitted InstallApprovalRequired).
                    if matches!(
                        low.as_str(),
                        "approve install" | "approve-install" | "install yes" | "yes install"
                    ) {
                        let (ok, summary) = agent.run_pending_install();
                        let _ = event_tx_host
                            .send(AgentEvent::InstallCompleted {
                                ok,
                                summary: summary.clone(),
                            })
                            .await;
                        let _ = event_tx_host
                            .send(AgentEvent::ContentDelta {
                                text: format!("\n{summary}\n"),
                            })
                            .await;
                        let _ = event_tx_host
                            .send(AgentEvent::Done { usage: None })
                            .await;
                        continue;
                    }
                    if matches!(
                        low.as_str(),
                        "deny install" | "deny-install" | "reject install" | "no install"
                    ) {
                        let msg = agent.deny_pending_install();
                        let _ = event_tx_host
                            .send(AgentEvent::ContentDelta {
                                text: format!("\n{msg}\n"),
                            })
                            .await;
                        let _ = event_tx_host
                            .send(AgentEvent::Done { usage: None })
                            .await;
                        continue;
                    }
                    // After external SSO/login (no secret paste), user can type "retry" / "continue".
                    let retry_cmd = matches!(
                        low.as_str(),
                        "retry" | "continue" | "reauth done" | "auth done"
                    );
                    if agent.pending_retry.is_some() && retry_cmd {
                        if let Ok(store) = ProfileStore::load(&paths) {
                            agent.reload_profiles(Arc::new(store));
                        }
                        agent.resume_after_auth(event_tx_host.clone(), cancel.clone()).await;
                        while let Ok(tr) = transcript_rx.try_recv() {
                            stored.transcript = tr;
                        }
                        persist_chat(&paths, &mut stored, agent, created_at);
                        continue;
                    }
                    agent
                        .run_turn(user, event_tx_host.clone(), cancel.clone())
                        .await;
                    // Auto-save after every completed turn (E1 / Grok Build history)
                    while let Ok(tr) = transcript_rx.try_recv() {
                        stored.transcript = tr;
                    }
                    persist_chat(&paths, &mut stored, agent, created_at);
                }
                else => break,
            }
        }
    });

    tui_handle.await??;
    // Final transcript may be on the channel from TUI exit
    // (host may already be aborted — best-effort)
    host.abort();
    Ok(())
}

fn persist_chat(
    paths: &Paths,
    stored: &mut oscar_core::StoredChatSession,
    agent: &Agent,
    created_at: chrono::DateTime<chrono::Utc>,
) {
    let mut snap = agent.to_stored_session(stored.transcript.clone());
    snap.created_at = created_at;
    snap.id = agent.session.id.clone();
    snap.title = agent.session.title.clone();
    if snap.transcript.is_empty() {
        snap.transcript = transcript_from_messages(&snap.messages);
    }
    *stored = snap;
    if let Err(e) = oscar_core::save_session(paths, stored) {
        tracing::warn!(error = %e, "failed to save chat session");
    }
}

fn transcript_from_messages(messages: &[oscar_core::Message]) -> Vec<oscar_core::TranscriptLine> {
    let mut out = Vec::new();
    for m in messages {
        match m.role {
            oscar_core::MessageRole::System => continue,
            oscar_core::MessageRole::User => out.push(oscar_core::TranscriptLine {
                kind: "user".into(),
                text: m.content.clone(),
            }),
            oscar_core::MessageRole::Assistant => {
                if let Some(t) = &m.thinking {
                    if !t.is_empty() {
                        out.push(oscar_core::TranscriptLine {
                            kind: "thinking".into(),
                            text: t.clone(),
                        });
                    }
                }
                if !m.content.is_empty() {
                    out.push(oscar_core::TranscriptLine {
                        kind: "assistant".into(),
                        text: m.content.clone(),
                    });
                }
                for tc in &m.tool_calls {
                    out.push(oscar_core::TranscriptLine {
                        kind: "tool".into(),
                        text: format!("→ {} ({})", tc.name, tc.id),
                    });
                }
            }
            oscar_core::MessageRole::Tool => {
                let name = m.name.as_deref().unwrap_or("tool");
                let preview: String = m.content.chars().take(200).collect();
                out.push(oscar_core::TranscriptLine {
                    kind: "tool".into(),
                    text: format!("← {name}: {preview}"),
                });
            }
        }
    }
    out
}

fn resolve_session_id(paths: &Paths, prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    if oscar_core::load_session(paths, prefix).is_ok() {
        return Some(prefix.to_string());
    }
    let list = oscar_core::list_sessions(paths).ok()?;
    let matches: Vec<_> = list
        .into_iter()
        .filter(|s| s.id.starts_with(prefix))
        .collect();
    if matches.len() == 1 {
        Some(matches[0].id.clone())
    } else {
        None
    }
}

async fn run_sessions(
    action: Option<SessionsCmd>,
    cfg: OscarConfig,
    paths: Paths,
) -> Result<()> {
    match action.unwrap_or(SessionsCmd::List) {
        SessionsCmd::List => {
            let list = oscar_core::list_sessions(&paths)?;
            let cur = oscar_core::current_session_id(&paths).unwrap_or_default();
            println!("# chat sessions  (dir: {})", paths.sessions_dir.display());
            if list.is_empty() {
                println!("(none — start `oscar` and chat; sessions auto-save)");
                return Ok(());
            }
            for s in list {
                let mark = if s.id == cur { "*" } else { " " };
                println!(
                    "{mark} {}  {}  msgs={:<3}  {}",
                    &s.id[..s.id.len().min(8)],
                    s.updated_at.format("%Y-%m-%d %H:%M"),
                    s.message_count,
                    s.title
                );
                if !s.preview.is_empty() {
                    println!("    {}", s.preview);
                }
            }
            println!("\n* = current  ·  oscar sessions resume <id>  ·  /history in chat");
        }
        SessionsCmd::Show { id } => {
            let id = resolve_session_id(&paths, &id).unwrap_or(id);
            let s = oscar_core::load_session(&paths, &id)?;
            println!("id: {}", s.id);
            println!("title: {}", s.title);
            println!("updated: {}", s.updated_at);
            println!("provider: {} / {}", s.provider, s.model);
            println!("messages: {}", s.messages.len());
            println!("transcript lines: {}", s.transcript.len());
            println!("\n# last transcript");
            for line in s.transcript.iter().rev().take(20).collect::<Vec<_>>().into_iter().rev() {
                println!("[{}] {}", line.kind, line.text.chars().take(160).collect::<String>());
            }
        }
        SessionsCmd::Delete { id } => {
            let id = resolve_session_id(&paths, &id).unwrap_or(id);
            oscar_core::delete_session(&paths, &id)?;
            println!("deleted session {id}");
        }
        SessionsCmd::New => {
            let s = oscar_core::StoredChatSession::new(
                &cfg.provider.id,
                cfg.provider.model.as_deref().unwrap_or("default"),
                cfg.mode.to_string(),
            );
            oscar_core::save_session(&paths, &s)?;
            println!("created session {}", s.id);
            println!("resume: oscar sessions resume {}", &s.id[..8]);
        }
        SessionsCmd::Resume { id } => {
            let id = match id {
                Some(i) => resolve_session_id(&paths, &i).unwrap_or(i),
                None => oscar_core::current_session_id(&paths)
                    .or_else(|| {
                        oscar_core::list_sessions(&paths)
                            .ok()
                            .and_then(|l| l.into_iter().next().map(|s| s.id))
                    })
                    .context("no session to resume")?,
            };
            oscar_core::set_current_session_id(&paths, &id)?;
            println!("resuming session {id}");
            return run_chat_with_session(cfg, paths, Some(id)).await;
        }
    }
    Ok(())
}

fn run_sessions_compact(paths: &Paths) -> Result<()> {
    let id = oscar_core::current_session_id(paths)
        .or_else(|| {
            oscar_core::list_sessions(paths)
                .ok()
                .and_then(|l| l.into_iter().next().map(|s| s.id))
        })
        .context("no session to compact")?;
    let mut s = oscar_core::load_session(paths, &id)?;
    let before = s.messages.len();
    // Keep system + last 12 non-system messages
    let mut system: Vec<_> = s
        .messages
        .iter()
        .filter(|m| m.role == oscar_core::MessageRole::System)
        .cloned()
        .collect();
    let rest: Vec<_> = s
        .messages
        .iter()
        .filter(|m| m.role != oscar_core::MessageRole::System)
        .cloned()
        .collect();
    let keep = 12usize;
    let drop_n = rest.len().saturating_sub(keep);
    let kept: Vec<_> = rest.into_iter().rev().take(keep).collect::<Vec<_>>().into_iter().rev().collect();
    if drop_n > 0 {
        system.push(oscar_core::Message::system(format!(
            "[earlier turns compacted offline: {drop_n} messages removed]"
        )));
    }
    s.messages = system;
    s.messages.extend(kept);
    s.transcript = transcript_from_messages(&s.messages);
    s.touch();
    oscar_core::save_session(paths, &s)?;
    println!(
        "compacted session {}  messages {before} → {}",
        &id[..id.len().min(8)],
        s.messages.len()
    );
    Ok(())
}

async fn handle_slash(
    user: &str,
    agent: &mut Option<Agent>,
    cfg: &mut OscarConfig,
    paths: &Paths,
    tx: &mpsc::Sender<AgentEvent>,
) {
    let parts: Vec<&str> = user.split_whitespace().collect();
    match parts.first().copied() {
        Some("/compact") => {
            // Grok: `/compact` or `/compact keep the auth implementation details`
            let keep_note = {
                let rest = user.trim().strip_prefix("/compact").unwrap_or("").trim();
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_string())
                }
            };
            if let Some(agent) = agent.as_mut() {
                let _ = tx
                    .send(AgentEvent::CompactionStarted {
                        reason: oscar_core::events::CompactReason::Manual,
                    })
                    .await;
                let (before, after) = agent.compact_manual_with(keep_note.clone());
                let note = keep_note
                    .as_ref()
                    .map(|n| format!(" (preserve: {n})"))
                    .unwrap_or_default();
                let _ = tx
                    .send(AgentEvent::ContentDelta {
                        text: format!(
                            "\n[compact]{} {} → {} ({:.0}% → {:.0}% of max {})\n",
                            note,
                            before.format_short(),
                            after.format_short(),
                            before.percent,
                            after.percent,
                            after.context_window
                        ),
                    })
                    .await;
                let _ = tx
                    .send(AgentEvent::CompactionFinished {
                        before,
                        after: after.clone(),
                    })
                    .await;
                let _ = tx.send(AgentEvent::ContextUsage(after)).await;
            }
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/context") => {
            if let Some(agent) = agent.as_ref() {
                let snap = agent
                    .session
                    .context
                    .snapshot(agent.session.messages.len() as u32);
                let thr = agent.session.context.config.threshold;
                let detail = snap.format_detail(thr);
                let _ = tx
                    .send(AgentEvent::ContentDelta {
                        text: format!(
                            "{detail}\n# one-line\n{}\n{}\n",
                            snap.format_labeled(),
                            snap.format_short()
                        ),
                    })
                    .await;
                let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
            } else {
                let _ = tx
                    .send(AgentEvent::Error {
                        message: "no agent session — context unavailable".into(),
                    })
                    .await;
            }
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/mode") => {
            let _ = tx
                .send(AgentEvent::ContentDelta {
                    text: format!(
                        "current mode: {} (set via `oscar mode set` or --mode)\n",
                        cfg.mode
                    ),
                })
                .await;
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/thinking") => {
            let sub = parts.get(1).copied();
            match sub {
                Some("on") | Some("1") | Some("true") => {
                    cfg.thinking = oscar_core::messages::ThinkingConfig::On {
                        budget_tokens: None,
                    };
                    cfg.ui.show_thinking = true;
                    if let Err(e) = cfg.save(paths) {
                        let _ = tx
                            .send(AgentEvent::Error {
                                message: e.to_string(),
                            })
                            .await;
                    } else if let Some(a) = agent.as_mut() {
                        a.session.thinking = cfg.thinking.clone();
                    }
                }
                Some("off") | Some("0") | Some("false") => {
                    cfg.thinking = oscar_core::messages::ThinkingConfig::Off;
                    if let Err(e) = cfg.save(paths) {
                        let _ = tx
                            .send(AgentEvent::Error {
                                message: e.to_string(),
                            })
                            .await;
                    } else if let Some(a) = agent.as_mut() {
                        a.session.thinking = cfg.thinking.clone();
                    }
                }
                Some("toggle") | None => {
                    // bare /thinking reports; /thinking toggle flips
                    if sub == Some("toggle") {
                        cfg.thinking = if cfg.thinking.is_on() {
                            oscar_core::messages::ThinkingConfig::Off
                        } else {
                            oscar_core::messages::ThinkingConfig::On {
                                budget_tokens: None,
                            }
                        };
                        let _ = cfg.save(paths);
                        if let Some(a) = agent.as_mut() {
                            a.session.thinking = cfg.thinking.clone();
                        }
                    }
                }
                Some(other) => {
                    let _ = tx
                        .send(AgentEvent::Error {
                            message: format!(
                                "usage: /thinking [on|off|toggle]  (got `{other}`)"
                            ),
                        })
                        .await;
                    let _ = tx.send(AgentEvent::Done { usage: None }).await;
                    return;
                }
            }
            let _ = tx
                .send(AgentEvent::ContentDelta {
                    text: format!(
                        "thinking: {:?} · show_in_ui={} · Settings→Agent or Ctrl+T for UI\n",
                        cfg.thinking, cfg.ui.show_thinking
                    ),
                })
                .await;
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/mcp") => {
            let sub = parts.get(1).copied().unwrap_or("list");
            match sub {
                "list" | "status" | "show" => {
                    let mut lines = vec![
                        format!("# mcp master_enabled={}", cfg.mcp.enabled),
                        format!("max_output_bytes={}", cfg.mcp.max_output_bytes),
                        String::new(),
                    ];
                    if cfg.mcp.servers.is_empty() {
                        lines.push("(no servers — oscar mcp example | /mcp help)".into());
                    }
                    for (name, sc) in &cfg.mcp.servers {
                        let cmd = sc
                            .command
                            .as_deref()
                            .or(sc.url.as_deref())
                            .unwrap_or("—");
                        lines.push(format!(
                            "{} {}\t{}\t{}",
                            if sc.enabled { "on " } else { "off" },
                            name,
                            sc.transport,
                            cmd
                        ));
                    }
                    lines.push(String::new());
                    lines.push(
                        "Tools mount as mcp.<server>.<tool> — tools_search \"mcp\" then tools_execute."
                            .into(),
                    );
                    lines.push(
                        "Config: ~/.config/oscar/config.toml [mcp] + optional .oscar/config.toml"
                            .into(),
                    );
                    lines.push("TUI: /settings → MCP servers".into());
                    let _ = tx
                        .send(AgentEvent::ContentDelta {
                            text: format!("{}\n", lines.join("\n")),
                        })
                        .await;
                }
                "enable" | "disable" => {
                    let on = sub == "enable";
                    if let Some(name) = parts.get(2) {
                        if let Some(sc) = cfg.mcp.servers.get_mut(*name) {
                            sc.enabled = on;
                            if let Err(e) = cfg.save(paths) {
                                let _ = tx
                                    .send(AgentEvent::Error {
                                        message: e.to_string(),
                                    })
                                    .await;
                            } else {
                                // In-session remount (M9) when agent is live
                                if let Some(agent) = agent.as_mut() {
                                    let reg = build_registry_with_mcp(cfg).await;
                                    let n = reg
                                        .list()
                                        .iter()
                                        .filter(|m| m.id.starts_with("mcp."))
                                        .count();
                                    agent.replace_tools(std::sync::Arc::new(reg));
                                    let _ = tx
                                        .send(AgentEvent::ContentDelta {
                                            text: format!(
                                                "mcp.servers.{name} enabled={on} · remounted {n} mcp tool(s)\n"
                                            ),
                                        })
                                        .await;
                                } else {
                                    let _ = tx
                                        .send(AgentEvent::ContentDelta {
                                            text: format!(
                                                "mcp.servers.{name} enabled={on} (no live agent — next chat remounts)\n"
                                            ),
                                        })
                                        .await;
                                }
                            }
                        } else {
                            let _ = tx
                                .send(AgentEvent::Error {
                                    message: format!("unknown mcp server `{name}`"),
                                })
                                .await;
                        }
                    } else {
                        cfg.mcp.enabled = on;
                        let _ = cfg.save(paths);
                        if let Some(agent) = agent.as_mut() {
                            let reg = build_registry_with_mcp(cfg).await;
                            let n = reg
                                .list()
                                .iter()
                                .filter(|m| m.id.starts_with("mcp."))
                                .count();
                            agent.replace_tools(std::sync::Arc::new(reg));
                            let _ = tx
                                .send(AgentEvent::ContentDelta {
                                    text: format!(
                                        "mcp master enabled={on} · remounted {n} mcp tool(s)\n"
                                    ),
                                })
                                .await;
                        } else {
                            let _ = tx
                                .send(AgentEvent::ContentDelta {
                                    text: format!("mcp master enabled={on}\n"),
                                })
                                .await;
                        }
                    }
                }
                "reload" | "remount" => {
                    if let Some(agent) = agent.as_mut() {
                        let before = agent.mcp_tool_count();
                        let reg = build_registry_with_mcp(cfg).await;
                        let after = reg
                            .list()
                            .iter()
                            .filter(|m| m.id.starts_with("mcp."))
                            .count();
                        agent.replace_tools(std::sync::Arc::new(reg));
                        let _ = tx
                            .send(AgentEvent::ContentDelta {
                                text: format!(
                                    "[mcp reload] remounted in-session · mcp tools {before} → {after}\n"
                                ),
                            })
                            .await;
                    } else {
                        let _ = tx
                            .send(AgentEvent::ContentDelta {
                                text: "no live agent — run oscar mcp reload from CLI or start chat\n"
                                    .into(),
                            })
                            .await;
                    }
                }
                "help" | _ => {
                    let _ = tx
                        .send(AgentEvent::ContentDelta {
                            text: "\
/mcp list              # servers in config
/mcp enable [name]     # master or server (+ in-session remount)
/mcp disable [name]
/mcp reload            # reconnect MCP into live agent (M9)
CLI: oscar mcp add|doctor|tools|example|reload
TOML: [mcp.servers.<name>] stdio or transport=http url=…
Mount: tools_search → tools_execute mcp.<server>.<tool>
"
                            .into(),
                        })
                        .await;
                }
            }
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/settings") => {
            // /settings [show|disable-cloud X|enable-cloud X|install-policy P|disable-tool ID|enable-tool ID]
            let sub = parts.get(1).copied().unwrap_or("show");
            let mut err: Option<String> = None;
            match sub {
                "show" | "list" => {}
                "disable-cloud" => {
                    if let Some(c) = parts.get(2) {
                        match normalize_cloud_name(c) {
                            Ok(c) => {
                                cfg.tools.disable_cloud(&c);
                                if let Err(e) = cfg.save(paths) {
                                    err = Some(e.to_string());
                                }
                            }
                            Err(e) => err = Some(e.to_string()),
                        }
                    } else {
                        err = Some("usage: /settings disable-cloud aws|gcp|azure|k8s".into());
                    }
                }
                "enable-cloud" => {
                    if let Some(c) = parts.get(2) {
                        match normalize_cloud_name(c) {
                            Ok(c) => {
                                cfg.tools.enable_cloud(&c);
                                if let Err(e) = cfg.save(paths) {
                                    err = Some(e.to_string());
                                }
                            }
                            Err(e) => err = Some(e.to_string()),
                        }
                    } else {
                        err = Some("usage: /settings enable-cloud aws|gcp|azure|k8s".into());
                    }
                }
                "install-policy" => {
                    if let Some(p) = parts.get(2).and_then(|s| InstallBinariesPolicy::parse(s)) {
                        cfg.tools.install_binaries = p;
                        if let Err(e) = cfg.save(paths) {
                            err = Some(e.to_string());
                        }
                    } else {
                        err = Some(
                            "usage: /settings install-policy off|recommend|ask-admin|install-all"
                                .into(),
                        );
                    }
                }
                "disable-tool" => {
                    if let Some(id) = parts.get(2) {
                        cfg.tools.disable_tool(id);
                        if let Err(e) = cfg.save(paths) {
                            err = Some(e.to_string());
                        }
                    } else {
                        err = Some("usage: /settings disable-tool <tool_id>".into());
                    }
                }
                "enable-tool" => {
                    if let Some(id) = parts.get(2) {
                        cfg.tools.enable_tool(id);
                        if let Err(e) = cfg.save(paths) {
                            err = Some(e.to_string());
                        }
                    } else {
                        err = Some("usage: /settings enable-tool <tool_id>".into());
                    }
                }
                "reload" => {
                    match OscarConfig::load(paths) {
                        Ok(c) => {
                            cfg.tools = c.tools;
                        }
                        Err(e) => err = Some(e.to_string()),
                    }
                }
                other => {
                    err = Some(format!(
                        "unknown /settings subcommand `{other}` — show|disable-cloud|enable-cloud|install-policy|disable-tool|enable-tool|reload"
                    ));
                }
            }
            if let Some(e) = err {
                let _ = tx.send(AgentEvent::Error { message: e }).await;
            } else {
                if let Some(a) = agent.as_mut() {
                    a.reload_settings(cfg.tools.clone());
                }
                let text = format!(
                    "{}\n\nChat: approve install | deny install\nCLI: oscar settings menu\n",
                    cfg.tools.agent_summary()
                );
                let _ = tx
                    .send(AgentEvent::ContentDelta { text })
                    .await;
            }
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/skills") => {
            if let Some(a) = agent.as_mut() {
                a.reload_skills();
                let mut lines = vec!["# skills".to_string()];
                for s in &a.skills {
                    lines.push(format!(
                        "- {} ({}) — {}",
                        s.name, s.source, s.description
                    ));
                }
                lines.push(String::new());
                lines.push("Activate: /skill <name>".into());
                lines.push("CLI: oscar skills list | show <name>".into());
                let _ = tx
                    .send(AgentEvent::ContentDelta {
                        text: format!("{}\n", lines.join("\n")),
                    })
                    .await;
            }
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/skill") => {
            let name = parts.get(1).copied().unwrap_or("");
            if name.is_empty() {
                let _ = tx
                    .send(AgentEvent::Error {
                        message: "usage: /skill <name>  (list with /skills)".into(),
                    })
                    .await;
            } else if let Some(a) = agent.as_mut() {
                match a.activate_skill(name) {
                    Ok(msg) => {
                        let _ = tx
                            .send(AgentEvent::ContentDelta {
                                text: format!("\n{msg}\n"),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = tx.send(AgentEvent::Error { message: e }).await;
                    }
                }
            }
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        Some("/help") => {
            let _ = tx
                .send(AgentEvent::ContentDelta {
                    text: "\
# slash commands
/settings [show|disable-cloud|…]   Ctrl+,
/identities   Ctrl+I
/skills  /skill <name>
/mcp list|enable|disable
/thinking [on|off|toggle]
/context  /compact  /mode
/history  /sessions     # list saved chats
/resume <id>            # load a saved chat
/new                    # start fresh chat (auto-saves history)
/quit
approve install | deny install

Sessions auto-save to ~/.config/oscar/sessions/ after each turn.
CLI: oscar sessions list|show|delete|resume|new
"
                    .into(),
                })
                .await;
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
        _ => {
            let _ = tx
                .send(AgentEvent::Error {
                    message: format!("unknown command: {user}"),
                })
                .await;
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
        }
    }
}
