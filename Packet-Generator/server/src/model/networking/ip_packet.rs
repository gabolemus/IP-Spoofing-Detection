// This file contains the enum for the IP packets versions: IPv4 and IPv6.

use super::{ipv4::IPv4Packet, ipv6::IPv6Packet};

pub enum IPPacket {
    IPv4(IPv4Packet),
    IPv6(IPv6Packet),
}
