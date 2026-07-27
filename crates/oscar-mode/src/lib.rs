//! Hard enforcement of read-only vs read/write session modes.

use oscar_core::{Capability, ExecutionMode, OscarError, OscarResult};

/// Check whether a tool capability is allowed under the current mode.
pub fn check_capability(mode: ExecutionMode, capability: Capability, tool_id: &str) -> OscarResult<()> {
    if mode.allows(capability) {
        Ok(())
    } else {
        Err(OscarError::ModeDenied {
            tool_id: tool_id.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_blocks_write() {
        let err = check_capability(ExecutionMode::ReadOnly, Capability::Write, "aws.dns.create").unwrap_err();
        match err {
            OscarError::ModeDenied { tool_id } => assert_eq!(tool_id, "aws.dns.create"),
            _ => panic!("expected ModeDenied"),
        }
    }

    #[test]
    fn readonly_allows_read() {
        check_capability(ExecutionMode::ReadOnly, Capability::Read, "aws.dns.lookup").unwrap();
    }

    #[test]
    fn readwrite_allows_both() {
        check_capability(ExecutionMode::ReadWrite, Capability::Read, "t").unwrap();
        check_capability(ExecutionMode::ReadWrite, Capability::Write, "t").unwrap();
    }
}
