// This file contains the enum for the IP packets versions: IPv4 and IPv6.

use super::{ipv4::IPv4Packet, ipv6::IPv6Packet};

/// IP packet version.
pub enum IPPacket {
    IPv4(IPv4Packet),
    IPv6(IPv6Packet),
}

/// Return a string that represents an IP if Some(IP) evaluates to true, or
/// return the provided default value.
pub fn ip_to_string(ip: &Option<String>, default: &str) -> String {
    match ip {
        Some(ip) => ip.to_string(),
        None => default.to_string(),
    }
}

/// Get the local IP address or return the provided default value.
pub fn get_local_ip(default: &str) -> String {
    let local_ip = match local_ipaddress::get() {
        Some(ip) => ip.to_string(),
        None => default.to_string(),
    };

    local_ip
}
