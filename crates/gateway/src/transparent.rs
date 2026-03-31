//! Transparent proxy mode support.
//!
//! In transparent mode, the agent calls upstream APIs directly (e.g.,
//! `api.github.com`) and iptables redirects the TCP connection to the
//! gateway sidecar. The proxy reads the original destination from
//! `SO_ORIGINAL_DST` (Linux) or uses the `Host` header, then routes
//! to the matching provider using `Registry.find(host)`.
//!
//! This module provides:
//! - Original destination extraction from redirected sockets
//! - Host-based provider resolution for the proxy handler
//! - iptables init script generation for container setup

use std::net::SocketAddr;

/// Resolved original destination of a redirected TCP connection.
#[derive(Debug, Clone)]
pub struct OriginalDest {
    /// The original destination IP address.
    pub ip: String,
    /// The original destination port.
    pub port: u16,
    /// The hostname (resolved from the Host header or SNI).
    pub hostname: String,
}

/// Extract the hostname from the request for transparent proxy routing.
///
/// Tries these sources in order:
/// 1. `Host` header (most reliable, always present in HTTP/1.1)
/// 2. Original destination from `SO_ORIGINAL_DST` (Linux iptables redirect)
///
/// Returns the hostname without port (e.g., "api.github.com").
pub fn resolve_hostname(
    headers: &axum::http::HeaderMap,
    _peer_addr: Option<SocketAddr>,
) -> Option<String> {
    // 1. Try the Host header.
    if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
        let hostname = extract_hostname(host);
        if !hostname.is_empty() {
            return Some(hostname.to_string());
        }
    }

    // 2. On Linux, we could read SO_ORIGINAL_DST from the socket.
    //    This requires the raw file descriptor which isn't available here.
    //    For now, we rely on the Host header.
    //    TODO: Implement SO_ORIGINAL_DST via a custom axum extractor.

    None
}

/// Extract hostname from a Host header value, handling IPv6 bracket notation.
/// - `"api.github.com"` → `"api.github.com"`
/// - `"api.github.com:443"` → `"api.github.com"`
/// - `"[2001:db8::1]:443"` → `"2001:db8::1"`
/// - `"[::1]"` → `"::1"`
fn extract_hostname(host: &str) -> &str {
    // IPv6 bracket notation: [addr] or [addr]:port
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[1..end],
            None => host, // malformed, return as-is
        };
    }
    // Regular host:port — split at last ':' to avoid splitting IPv6 bare addresses.
    match host.rfind(':') {
        Some(pos) => &host[..pos],
        None => host,
    }
}

/// Read the original destination from a redirected TCP socket on Linux.
/// Uses the `SO_ORIGINAL_DST` socket option set by iptables REDIRECT.
///
/// Returns the original destination address that the client was trying
/// to connect to before iptables redirected it to the proxy.
#[cfg(target_os = "linux")]
pub fn get_original_dst(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    use std::mem;
    use std::os::raw::c_int;

    // SOL_IP = 0, SO_ORIGINAL_DST = 80
    const SOL_IP: c_int = 0;
    const SO_ORIGINAL_DST: c_int = 80;

    unsafe {
        let mut addr: libc::sockaddr_in = mem::zeroed();
        let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut _,
            &mut len,
        );

        if ret != 0 {
            return None;
        }

        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);

        Some(SocketAddr::from((ip, port)))
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn get_original_dst(_fd: i32) -> Option<SocketAddr> {
    None
}

/// Generate an iptables init script for redirecting traffic to the proxy.
///
/// This script is designed to run in the agent container's network namespace,
/// following the same pattern as Istio's `istio-init` container.
///
/// `proxy_port`: The port the gateway proxy listens on (e.g., 8080).
/// `proxy_uid`: The UID of the proxy process (traffic from this UID is not redirected).
/// `excluded_ports`: Ports to exclude from redirection (e.g., ["22", "15090"]).
pub fn generate_iptables_init(
    proxy_port: u16,
    proxy_uid: u32,
    excluded_ports: &[String],
) -> String {
    let mut script = String::new();

    script.push_str("#!/bin/sh\n");
    script.push_str("# Gateway transparent proxy iptables setup.\n");
    script.push_str("# Run as root in the agent container's network namespace.\n");
    script.push_str("# Same pattern as Istio's istio-init container.\n\n");
    script.push_str("set -e\n\n");

    // Create a new chain for gateway redirect.
    script.push_str("# Create GATEWAY_REDIRECT chain\n");
    script.push_str("iptables -t nat -N GATEWAY_REDIRECT 2>/dev/null || true\n");
    script.push_str("iptables -t nat -N GATEWAY_OUTPUT 2>/dev/null || true\n\n");

    // Redirect rule: send traffic to the proxy port.
    script.push_str(&format!("# Redirect to proxy port {}\n", proxy_port));
    script.push_str(&format!(
        "iptables -t nat -A GATEWAY_REDIRECT -p tcp -j REDIRECT --to-port {}\n\n",
        proxy_port
    ));

    // Output chain: skip traffic from the proxy itself.
    script.push_str(&format!(
        "# Skip traffic from the proxy process (UID {})\n",
        proxy_uid
    ));
    script.push_str(&format!(
        "iptables -t nat -A GATEWAY_OUTPUT -m owner --uid-owner {} -j RETURN\n",
        proxy_uid
    ));

    // Skip loopback.
    script.push_str("# Skip loopback traffic\n");
    script.push_str("iptables -t nat -A GATEWAY_OUTPUT -o lo -j RETURN\n");

    // Skip excluded ports (validated as numeric to prevent injection).
    let valid_ports: Vec<u16> = excluded_ports
        .iter()
        .filter_map(|p| p.parse::<u16>().ok())
        .collect();
    if !valid_ports.is_empty() {
        script.push_str("\n# Excluded ports\n");
        for port in &valid_ports {
            script.push_str(&format!(
                "iptables -t nat -A GATEWAY_OUTPUT -p tcp --dport {} -j RETURN\n",
                port
            ));
        }
    }

    // Redirect all remaining outbound TCP to the gateway.
    script.push_str("\n# Redirect all other outbound TCP to gateway\n");
    script.push_str("iptables -t nat -A GATEWAY_OUTPUT -p tcp -j GATEWAY_REDIRECT\n\n");

    // Hook into OUTPUT chain.
    script.push_str("# Install in OUTPUT chain\n");
    script.push_str("iptables -t nat -A OUTPUT -p tcp -j GATEWAY_OUTPUT\n\n");

    script.push_str("echo 'Gateway iptables rules installed'\n");

    script
}

/// Generate the iptables cleanup script.
pub fn generate_iptables_cleanup() -> String {
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str("# Clean up gateway iptables rules.\n\n");
    script.push_str("set -e\n\n");
    script.push_str("iptables -t nat -D OUTPUT -p tcp -j GATEWAY_OUTPUT 2>/dev/null || true\n");
    script.push_str("iptables -t nat -F GATEWAY_OUTPUT 2>/dev/null || true\n");
    script.push_str("iptables -t nat -F GATEWAY_REDIRECT 2>/dev/null || true\n");
    script.push_str("iptables -t nat -X GATEWAY_OUTPUT 2>/dev/null || true\n");
    script.push_str("iptables -t nat -X GATEWAY_REDIRECT 2>/dev/null || true\n\n");
    script.push_str("echo 'Gateway iptables rules removed'\n");
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_hostname_from_host_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "api.github.com".parse().unwrap());

        let host = resolve_hostname(&headers, None);
        assert_eq!(host, Some("api.github.com".to_string()));
    }

    #[test]
    fn test_resolve_hostname_strips_port() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "api.stripe.com:443".parse().unwrap());

        let host = resolve_hostname(&headers, None);
        assert_eq!(host, Some("api.stripe.com".to_string()));
    }

    #[test]
    fn test_resolve_hostname_ipv6_bracket() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "[2001:db8::1]:443".parse().unwrap());

        let host = resolve_hostname(&headers, None);
        assert_eq!(host, Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_resolve_hostname_ipv6_bracket_no_port() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "[::1]".parse().unwrap());

        let host = resolve_hostname(&headers, None);
        assert_eq!(host, Some("::1".to_string()));
    }

    #[test]
    fn test_resolve_hostname_missing_header() {
        let headers = axum::http::HeaderMap::new();
        let host = resolve_hostname(&headers, None);
        assert!(host.is_none());
    }

    #[test]
    fn test_extract_hostname_variants() {
        assert_eq!(extract_hostname("api.github.com"), "api.github.com");
        assert_eq!(extract_hostname("api.github.com:443"), "api.github.com");
        assert_eq!(extract_hostname("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(extract_hostname("[::1]"), "::1");
    }

    #[test]
    fn test_iptables_rejects_invalid_ports() {
        let script = generate_iptables_init(
            8080,
            1337,
            &[
                "22".to_string(),
                "not-a-port".to_string(),
                "15090".to_string(),
                "; rm -rf /".to_string(),
            ],
        );
        assert!(script.contains("--dport 22"));
        assert!(script.contains("--dport 15090"));
        assert!(!script.contains("not-a-port"));
        assert!(!script.contains("rm -rf"));
    }

    #[test]
    fn test_generate_iptables_init() {
        let script = generate_iptables_init(8080, 1337, &["22".to_string(), "15090".to_string()]);

        assert!(script.contains("#!/bin/sh"));
        assert!(script.contains("GATEWAY_REDIRECT"));
        assert!(script.contains("--to-port 8080"));
        assert!(script.contains("--uid-owner 1337"));
        assert!(script.contains("--dport 22"));
        assert!(script.contains("--dport 15090"));
    }

    #[test]
    fn test_generate_iptables_init_no_excluded_ports() {
        let script = generate_iptables_init(9090, 0, &[]);

        assert!(script.contains("--to-port 9090"));
        assert!(!script.contains("Excluded ports"));
    }

    #[test]
    fn test_generate_iptables_cleanup() {
        let script = generate_iptables_cleanup();

        assert!(script.contains("#!/bin/sh"));
        assert!(script.contains("-D OUTPUT"));
        assert!(script.contains("-X GATEWAY_OUTPUT"));
        assert!(script.contains("-X GATEWAY_REDIRECT"));
    }

    #[test]
    fn test_get_original_dst_non_linux() {
        // On non-Linux, always returns None.
        let result = get_original_dst(0);
        #[cfg(not(target_os = "linux"))]
        assert!(result.is_none());
        #[cfg(target_os = "linux")]
        let _ = result; // May or may not work depending on socket
    }
}
