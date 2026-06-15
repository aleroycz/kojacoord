pub mod http_api;
pub mod server_management;

/// Constant-time comparison of two secrets.
///
/// Compares in time independent of the position of the first differing byte,
/// preventing timing side-channels that could leak an auth token byte-by-byte.
/// Length is folded into the result, so mismatched lengths also fail.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn equal_strings_match() {
        assert!(constant_time_eq(
            b"super-secret-token",
            b"super-secret-token"
        ));
    }

    #[test]
    fn different_strings_do_not_match() {
        assert!(!constant_time_eq(
            b"super-secret-token",
            b"super-secret-tokeX"
        ));
        assert!(!constant_time_eq(b"short", b"much-longer-value"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
