//! Egress audit — enumerate the network sockets owned by the
//! Whisper desktop process so the user can see exactly what we're
//! talking to.
//!
//! Why: in I2P-only mode the *only* legitimate outbound socket from
//! the Whisper process is the SAM TCP connection to our local i2pd
//! subprocess on 127.0.0.1. Any other established TCP connection
//! from this PID is suspicious — a sign of injection, a debugger
//! attached, or an unexpected library beaconing.
//!
//! What this is not: it is **not** a sandbox. A determined attacker
//! who has code execution inside our process can hide their socket,
//! patch this very function, or use raw kernel calls. The audit's
//! value is forensic / detective: surface anomalies to the user
//! before they cause real harm. The other Hardened Runtime
//! entitlements + library validation provide the actual prevention.
//!
//! Implementation: shells out to the system `lsof` (always present on
//! macOS). We pass `-p <pid>` so we only see *our* sockets — never
//! the i2pd subprocess (it has its own PID and we expect it to talk
//! to many remote peers; that's the entire point).

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct EgressConnection {
    pub proto: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub is_loopback: bool,
    pub is_expected: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct EgressAudit {
    /// All outbound + listener sockets owned by the Whisper process
    /// at the moment of the call. Excludes the i2pd subprocess.
    pub connections: Vec<EgressConnection>,
    /// The SAM bridge address the I2P runtime is using right now,
    /// if it's up. The audit considers a connection "expected" iff
    /// its remote endpoint matches this address.
    pub expected_sam_addr: Option<String>,
    /// Number of `connections` rows that did not match the
    /// expected SAM address. Surface this to the user prominently.
    pub unexpected_count: usize,
    /// Sockets owned by the bundled i2pd subprocess, if it's running.
    /// i2pd legitimately maintains connections to many I2P peers; this
    /// list is informational, surfaced for transparency rather than
    /// anomaly detection. (We still flag *non-i2p* sockets — anything
    /// connecting to a clearnet HTTPS port or a local IPC endpoint
    /// would be suspicious.)
    pub i2pd_connections: Vec<EgressConnection>,
    /// PID of the i2pd subprocess, when one is running.
    pub i2pd_pid: Option<u32>,
}

/// Run the audit for our own PID, optionally also enumerating sockets
/// owned by the bundled i2pd subprocess.
pub fn audit_self(expected_sam_addr: Option<&str>, i2pd_pid: Option<u32>) -> EgressAudit {
    let pid = std::process::id();
    let mut audit = audit_pid(pid, expected_sam_addr);
    if let Some(child_pid) = i2pd_pid {
        audit.i2pd_pid = Some(child_pid);
        audit.i2pd_connections = match run_lsof(child_pid) {
            Ok(raw) => parse_lsof(&raw, None),
            Err(e) => {
                tracing::warn!("egress audit: lsof for i2pd pid {child_pid} failed: {e}");
                Vec::new()
            }
        };
    }
    audit
}

fn audit_pid(pid: u32, expected_sam_addr: Option<&str>) -> EgressAudit {
    let raw = match run_lsof(pid) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("egress audit: lsof failed: {e}");
            return EgressAudit {
                expected_sam_addr: expected_sam_addr.map(String::from),
                ..EgressAudit::default()
            };
        }
    };
    let connections = parse_lsof(&raw, expected_sam_addr);
    let unexpected_count = connections.iter().filter(|c| !c.is_expected).count();
    EgressAudit {
        connections,
        expected_sam_addr: expected_sam_addr.map(String::from),
        unexpected_count,
        ..EgressAudit::default()
    }
}

fn run_lsof(pid: u32) -> std::io::Result<String> {
    // -a  AND every selector (vs. the macOS default which OR's them).
    //     Without this flag, `lsof -p PID -i` returns "files for PID
    //     OR any network file" — i.e. the network sockets of *every*
    //     process on the machine, attributed to our PID. That bug
    //     made the dashboard show neighbour-process traffic
    //     (Microsoft Remote Desktop, Chrome's FCM, Apple's identity
    //     daemon, …) as if Whisper were opening it. With -a the
    //     selectors are intersected: files that belong to PID AND
    //     are network sockets.
    // -i  network sockets only.
    // -n  no DNS resolution (avoid touching the network for the audit itself).
    // -P  no port-name resolution (numeric only).
    // -p  scope to this PID.
    let out = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid.to_string(), "-i", "-n", "-P"])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn parse_lsof(output: &str, expected_sam_addr: Option<&str>) -> Vec<EgressConnection> {
    let mut out = Vec::new();
    for line in output.lines().skip(1) {
        // lsof columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // The NAME field at the end can contain spaces (it does for IPv6),
        // but for our purposes we always have a single token because we
        // pass `-n -P` which avoids DNS/service-name expansion.
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }
        let proto = cols[7].to_string(); // "TCP" / "UDP"
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        // The NAME column may also include trailing "(STATE)" so
        // re-join from index 8 onward to keep the full descriptor.
        let name = cols[8..].join(" ");
        let (local_addr, remote_addr, state) = split_name(&name);
        let is_loopback =
            is_loopback_addr(&local_addr) && is_loopback_addr_or_listener(&remote_addr);

        // A connection is "expected" (not flagged as a finding) iff
        // it is NOT a public-routable internet egress, OR it is the
        // legitimate SAM bridge connection. The audit's actual job
        // is to surface "Whisper is talking to something on the
        // public internet that isn't our SAM bridge" — every other
        // socket category is OS / IPC / dev-tooling noise:
        //
        //   * LISTEN sockets are passive bindings, not outbound.
        //   * `*:* → *:*` UDP rows are unbound resolver / mDNS /
        //     IPv6-family-switch sockets that lsof reports for any
        //     macOS process.
        //   * Loopback (127/8, ::1) — Tauri IPC, WebKit internals.
        //   * Link-local (fe80::/10, 169.254/16) — local-link only.
        //   * RFC-1918 private (10/8, 172.16/12, 192.168/16) — never
        //     crosses a router; stays on the user's LAN.
        //   * Multicast / broadcast / unspecified (0.0.0.0, ff00::/8) —
        //     not point-to-point egress targets.
        //   * Same-IP self-loop (macOS routing localhost-style traffic
        //     via the LAN interface) — never leaves the machine.
        //
        // We use std::net::IpAddr's classifiers rather than string-
        // prefix matching so e.g. an IPv6 link-local address with a
        // zone identifier (`[fe80::1%en0]:1024`) parses cleanly and
        // every reserved range above is captured exactly.
        let sam_match = proto == "TCP"
            && expected_sam_addr
                .map(|sam| remote_addr_matches(&remote_addr, sam))
                .unwrap_or(false);
        let is_expected = state == "LISTEN"
            || sam_match
            || same_ip_self_loop(&local_addr, &remote_addr)
            || !is_public_routable_remote(&remote_addr);

        out.push(EgressConnection {
            proto,
            local_addr,
            remote_addr,
            state,
            is_loopback,
            is_expected,
        });
    }
    out
}

/// True if the local and remote endpoints share a host portion (port
/// can differ). macOS will sometimes route a localhost-style connection
/// via the LAN interface — the socket then shows up as
/// `192.168.x.y:NNN -> 192.168.x.y:MMM`. Both ends are the same machine,
/// so this is not an egress concern.
fn same_ip_self_loop(local: &str, remote: &str) -> bool {
    let local_host = strip_port(local);
    let remote_host = strip_port(remote);
    !local_host.is_empty() && local_host != "*" && local_host == remote_host
}

/// `127.0.0.1:53277` → `127.0.0.1`, `[::1]:53189` → `[::1]`, `*:64253` → `*`.
fn strip_port(addr: &str) -> &str {
    if let Some(end) = addr.rfind(']') {
        // IPv6 literal: take through the closing bracket.
        &addr[..=end]
    } else if let Some(colon) = addr.rfind(':') {
        &addr[..colon]
    } else {
        addr
    }
}

/// `lsof` formats the NAME column as either:
///   `127.0.0.1:50000->127.0.0.1:7656 (ESTABLISHED)`
///   `*:54321 (LISTEN)`
///   `*:*`
///   `[::1]:54321->[::1]:7656 (CLOSE_WAIT)`
fn split_name(name: &str) -> (String, String, String) {
    let (addrs, state) = match name.rfind('(') {
        Some(i) => {
            let s = name[i..].trim_matches(|c| c == '(' || c == ')').to_string();
            (name[..i].trim().to_string(), s)
        }
        None => (name.trim().to_string(), String::new()),
    };
    if let Some(arrow) = addrs.find("->") {
        (
            addrs[..arrow].to_string(),
            addrs[arrow + 2..].to_string(),
            state,
        )
    } else {
        (addrs, "*:*".to_string(), state)
    }
}

fn is_loopback_addr(s: &str) -> bool {
    s.starts_with("127.")
        || s.starts_with("[::1]")
        || s == "localhost"
        // IPv6 link-local (RFC 4291 fe80::/10).
        || s.starts_with("[fe80")
        // IPv4 link-local (RFC 3927 169.254/16). Same family — packets
        // never cross a router, only the local link.
        || s.starts_with("169.254.")
}

/// True iff `addr` parses to a public-routable internet endpoint.
/// False for wildcards, loopback, link-local, RFC-1918 private,
/// IPv6 unique-local (fc00::/7), multicast, broadcast, unspecified,
/// IPv4-mapped private, and unparseable strings.
///
/// We hand-roll the IPv6 link-local (fe80::/10) and unique-local
/// (fc00::/7) checks because the corresponding `Ipv6Addr` methods
/// (`is_unicast_link_local`, `is_unique_local`) are still nightly-only.
/// Everything else uses the stable `Ipv4Addr` / `Ipv6Addr` classifiers.
fn is_public_routable_remote(addr: &str) -> bool {
    let host = match parse_host_str(addr) {
        Some(h) => h,
        None => return false,
    };
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    !is_non_routable(&ip)
}

fn parse_host_str(addr: &str) -> Option<String> {
    if addr.is_empty() || addr == "*:*" {
        return None;
    }
    // IPv6: `[host]:port` or `[host%zone]:port`.
    if let Some(rest) = addr.strip_prefix('[') {
        let end = rest.find(']')?;
        let inner = &rest[..end];
        // Strip RFC 6874 zone identifier (e.g. `fe80::1%en0`).
        let host = inner.split('%').next().unwrap_or(inner);
        if host.is_empty() || host == "*" {
            return None;
        }
        return Some(host.to_string());
    }
    // IPv4: `host:port`.
    let colon = addr.rfind(':')?;
    let host = &addr[..colon];
    if host.is_empty() || host == "*" {
        return None;
    }
    Some(host.to_string())
}

fn is_non_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_routable_v4(*v4),
        IpAddr::V6(v6) => is_non_routable_v6(*v6),
    }
}

fn is_non_routable_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_unspecified()
}

fn is_non_routable_v6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return true;
    }
    let segs = v6.segments();
    // Link-local fe80::/10 (segs[0] in 0xfe80..=0xfebf).
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Unique-local fc00::/7 (segs[0] in 0xfc00..=0xfdff).
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) — recurse on the embedded v4.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_non_routable_v4(v4);
    }
    false
}

fn is_loopback_addr_or_listener(s: &str) -> bool {
    s == "*:*" || is_loopback_addr(s)
}

fn remote_addr_matches(remote: &str, expected: &str) -> bool {
    // expected is "127.0.0.1:49243"; remote may be "127.0.0.1:49243"
    // or "[::1]:49243" depending on stack family. Compare port-only
    // as a fallback because both halves must be loopback for a match
    // (we already check is_loopback in the caller chain).
    if remote == expected {
        return true;
    }
    let exp_port = expected.rsplit(':').next();
    let rem_port = remote.rsplit(':').next();
    match (exp_port, rem_port) {
        (Some(a), Some(b)) if a == b && is_loopback_addr(remote) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loopback_sam_connection_marks_as_expected() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 TCP 127.0.0.1:50000->127.0.0.1:7656 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert_eq!(c.proto, "TCP");
        assert!(c.is_loopback);
        assert!(c.is_expected);
        assert_eq!(c.state, "ESTABLISHED");
    }

    #[test]
    fn parse_unexpected_external_connection_marked_not_expected() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 TCP 192.168.1.10:55000->203.0.113.5:443 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert!(!c.is_loopback);
        assert!(!c.is_expected);
    }

    #[test]
    fn parse_listener_socket_with_no_remote() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 TCP *:54321 (LISTEN)
";
        let conns = parse_lsof(raw, None);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].state, "LISTEN");
        // LISTEN is passive — never a finding.
        assert!(conns[0].is_expected);
    }

    #[test]
    fn vite_dev_server_loopback_not_flagged() {
        // Regression: dev-mode WebView talking to Vite at [::1]:1420
        // used to count as "unexpected" because is_loopback was
        // computed but never folded into is_expected.
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv6 abcd 0t0 TCP [::1]:53189->[::1]:1420 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_loopback);
        assert!(conns[0].is_expected);
    }

    #[test]
    fn ipv6_link_local_self_loop_not_flagged() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv6 abcd 0t0 TCP [fe80::1%en0]:1024->[fe80::1%en0]:1027 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }

    #[test]
    fn lan_ip_self_loop_not_flagged() {
        // macOS sometimes routes a localhost-style connection via the
        // LAN interface, producing same-IP-both-ends sockets like
        // 192.168.100.109:50017 -> 192.168.100.109:3389. Both ends
        // are the same machine.
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 TCP 192.168.100.109:50017->192.168.100.109:3389 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }

    #[test]
    fn external_lan_peer_no_longer_flagged() {
        // Updated semantics: Whisper has no business reaching out to
        // *any* non-loopback address, but in practice the noise from
        // OS-level RFC-1918 traffic (printers, mDNS, AirPlay, file
        // sharing) is unactionable. The audit's job is to surface
        // public-internet egress; a different LAN host is now treated
        // as expected. (A real attacker exfiltrating via a LAN-resident
        // proxy would still be invisible — but they'd ALSO be invisible
        // to lsof at the bytes-on-the-wire layer, so the audit was
        // never going to catch that case anyway.)
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 TCP 192.168.1.10:55000->192.168.1.20:8080 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }

    #[test]
    fn unbound_udp_wildcard_not_flagged() {
        // `UDP *:* → *:*` rows are macOS resolver / mDNS / IPv6 family-
        // switching sockets — bound but never connected to a peer.
        // They flooded the dashboard with false positives before the
        // public-routable filter landed.
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 UDP *:*->*:*
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }

    #[test]
    fn ipv6_link_local_with_zone_id_not_flagged() {
        // The screenshot's `[fe80::b36e:f547:1410:9f17%en0]:1024`
        // form needs to parse cleanly — earlier string-prefix code
        // missed the zone identifier entirely.
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv6 abcd 0t0 TCP [fe80::b36e:f547:1410:9f17%en0]:1024->[fe80::c644:a192:e91:c5b3%en0]:1024 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }

    #[test]
    fn ipv6_unique_local_not_flagged() {
        // fc00::/7 — Unique Local Addresses. RFC 4193, equivalent in
        // role to RFC-1918 IPv4 private space.
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv6 abcd 0t0 TCP [fd12::1]:50000->[fd12::2]:443 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }

    #[test]
    fn multicast_not_flagged() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 UDP 192.168.1.5:5353->224.0.0.251:5353
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }

    #[test]
    fn public_internet_remote_still_flagged() {
        // The actual case the audit exists to catch: a non-loopback,
        // non-RFC-1918, non-link-local TCP connection going
        // somewhere on the public internet that isn't our SAM bridge.
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 TCP 192.168.1.10:55000->203.0.113.5:443 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(!conns[0].is_expected);
    }

    #[test]
    fn ipv6_public_remote_still_flagged() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv6 abcd 0t0 TCP [2001:db8::1]:55000->[2606:4700::1]:443 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(!conns[0].is_expected);
    }

    #[test]
    fn unexpected_count_is_correct() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv4 abcd 0t0 TCP 127.0.0.1:50000->127.0.0.1:7656 (ESTABLISHED)
whisper 100 me 6u IPv4 abce 0t0 TCP 192.168.1.10:55000->203.0.113.5:443 (ESTABLISHED)
";
        let audit = EgressAudit {
            connections: parse_lsof(raw, Some("127.0.0.1:7656")),
            expected_sam_addr: Some("127.0.0.1:7656".into()),
            unexpected_count: 0,
            ..EgressAudit::default()
        };
        let unexpected = audit.connections.iter().filter(|c| !c.is_expected).count();
        assert_eq!(unexpected, 1);
    }

    #[test]
    fn ipv6_loopback_to_sam_port_matches() {
        let raw = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
whisper 100 me 5u IPv6 abcd 0t0 TCP [::1]:50000->[::1]:7656 (ESTABLISHED)
";
        let conns = parse_lsof(raw, Some("127.0.0.1:7656"));
        assert!(conns[0].is_expected);
    }
}
