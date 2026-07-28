//! Profiles (metadata on disk) + secrets (OS keychain) + binary detection + CSP sessions.

mod binaries;
mod classify;
mod cluster_auth;
mod csp_session;
mod identity_status;
mod keychain;
mod packages;
mod profiles;

pub use binaries::{
    feasibility_for_tool, required_binaries_for_tool, BinaryInfo, BinaryInventory, BinaryRole,
    ToolFeasibility,
};
pub use cluster_auth::{
    auth_request_for_cluster_plan, build_cluster_auth_plan, fuzzy_cluster_score,
    infer_cluster_kind, infer_cluster_kind_from_kubeconfig, need_kind_question,
    oscar_kubeconfig_path, resolve_cluster_name_fuzzy, ClusterAuthPlan, ClusterAuthSurface,
    FuzzyClusterResolve, KubeconfigInfer,
};
pub use identity_status::{
    build_identity_inventory, build_identity_inventory_quick, ClusterIdentity, IdentityEntry,
    IdentityInventory, IdentityKind, Validity,
};
pub use packages::{
    binaries_for_tools, critical_csp_binaries, plan_install, run_install_commands, InstallPlan,
    PackageManager,
};
pub use classify::{classify_auth_error, is_reauth_failure};
pub use csp_session::{
    assume_role_into_profile, auth_aws_missing_binary, auth_aws_needed, auth_request_from_error,
    bind_aws_account_ref_if_pending, delete_provider_api_key, load_provider_api_key,
    looks_like_transcript_not_secret, parse_aws_env_exports, profile_allows_ambient_fallback,
    profile_has_fixed_account, profile_has_stored_aws_keys, resolve_aws_process_creds,
    resolve_azure_hints, resolve_gcp_hints, resolve_k8s_hints, store_aws_long_lived,
    store_aws_session_expiry, store_aws_short_lived, store_provider_api_key, validate_aws,
    validate_aws_secret_value, ProcessCreds,
};
pub use keychain::KeychainStore;
pub use profiles::{Profile, ProfileStore, ProfilesFile};
