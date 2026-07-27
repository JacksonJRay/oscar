//! Map CSP CLI/API stderr/stdout to auth failure kinds for re-prompt.

use oscar_core::AuthFailureKind;

/// Classify tool/CLI error text for auth handling.
pub fn classify_auth_error(text: &str) -> AuthFailureKind {
    let t = text.to_ascii_lowercase();

    if t.contains("not found on path")
        || t.contains("failed to spawn")
        || t.contains("no such file")
        || t.contains("is the cli installed")
    {
        return AuthFailureKind::BinaryMissing;
    }

    // Expired / temporary credentials
    if t.contains("expiredtoken")
        || t.contains("expired token")
        || t.contains("token has expired")
        || t.contains("security token included in the request is expired")
        || t.contains("invalid_grant")
        || t.contains("reauthentication")
        || t.contains("login required")
        || t.contains("your credentials have expired")
        || t.contains("refresh token")
        || t.contains("session has expired")
    {
        return AuthFailureKind::Expired;
    }

    // Invalid / missing credentials
    if t.contains("unable to locate credentials")
        || t.contains("no credentials")
        || t.contains("could not find credentials")
        || t.contains("missing credentials")
        || t.contains("not logged in")
        || t.contains("please run")
            && (t.contains("login") || t.contains("configure") || t.contains("auth"))
        || t.contains("invalidclienttokenid")
        || t.contains("unrecognizedclientexception")
        || t.contains("invalid access key")
        || t.contains("signaturedoesnotmatch")
        || t.contains("authfailure")
        || t.contains("unauthorized") && t.contains("authenticate")
        || t.contains("error loading sso")
        || t.contains("sso session")
        || t.contains("could not be found") && t.contains("profile")
    {
        return AuthFailureKind::Invalid;
    }

    // Permission (have identity, lack IAM)
    if t.contains("accessdenied")
        || t.contains("access denied")
        || t.contains("not authorized to perform")
        || t.contains("unauthorizedoperation")
        || t.contains("permission denied")
        || t.contains("403")
        || t.contains("forbidden")
    {
        return AuthFailureKind::PermissionDenied;
    }

    if t.contains("401") || t.contains("unauthenticated") {
        return AuthFailureKind::Invalid;
    }

    AuthFailureKind::Other
}

pub fn is_reauth_failure(kind: AuthFailureKind) -> bool {
    matches!(
        kind,
        AuthFailureKind::Expired | AuthFailureKind::Invalid | AuthFailureKind::Missing
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_token() {
        assert_eq!(
            classify_auth_error("An error occurred (ExpiredToken) when calling"),
            AuthFailureKind::Expired
        );
    }

    #[test]
    fn missing_creds() {
        assert_eq!(
            classify_auth_error("Unable to locate credentials"),
            AuthFailureKind::Invalid
        );
    }

    #[test]
    fn access_denied_not_reauth_required_as_expired() {
        assert_eq!(
            classify_auth_error("User is not authorized to perform: ec2:DescribeVpcs"),
            AuthFailureKind::PermissionDenied
        );
    }

    #[test]
    fn sso_session_invalid() {
        assert_eq!(
            classify_auth_error("Error loading SSO Token: Token has expired and refresh failed"),
            AuthFailureKind::Expired
        );
    }
}
