use super::IPv6Packet;
use crate::model::networking::{IPPacket, TCPPacket};
use std::net::Ipv6Addr;

/// TCP/IP version 6 packet structure.
pub struct TCPIPv6Packet {
    /// IPv6 packet.
    pub ipv6: IPv6Packet,
    /// TCP packet.
    pub tcp: TCPPacket,
    /// Raw packet.
    pub raw: Vec<u8>,
}

// TCP/IP version 6 packet implementations
impl TCPIPv6Packet {
    pub fn new(
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        data: Option<Vec<u8>>,
        options: Option<Vec<u8>>,
        port: u16,
    ) -> TCPIPv6Packet {
        // IPv6 Packet
        let mut ipv6_packet =
            IPv6Packet::new(None, None, None, None, 64, source_ip, destination_ip, None);

        // TCP Packet
        let mut tcp_packet = TCPPacket::new(
            Some(port),
            Some(if rand::random() { 80 } else { 443 }), // Choose either 80 (HTTP) or 443 (HTTPS) as the destination port randomly
            None,
            None,
            None,
            None,
            None,
            options,
            data,
        );

        // This packet will have the wrong total length and checksum, as it only considers the IPv6 header's length
        let raw = [&ipv6_packet.raw[..], &tcp_packet.raw[..]].concat();

        // Set the new total length in the IPv4 header (Fix the total length)
        ipv6_packet.header.payload_length = raw.len() as u16;

        // Fix the total length in the raw packet
        ipv6_packet.raw[4] = (ipv6_packet.header.payload_length >> 8) as u8;
        ipv6_packet.raw[5] = ipv6_packet.header.payload_length as u8;

        // Set the checksum for the TCP header
        tcp_packet.set_checksum(IPPacket::IPv6(ipv6_packet.clone()));

        // Shadow the previous raw packet
        let raw = [&ipv6_packet.raw[..], &tcp_packet.raw[..]].concat();

        // Create the TCP/IP version 4 packet and return it
        TCPIPv6Packet {
            ipv6: ipv6_packet,
            tcp: tcp_packet,
            raw,
        }
    }

    /// Display the packet in hexadecimal format
    pub fn display(&self) {
        // Display the IPv6 header
        self.ipv6.display();

        // Display the TCP packet
        self.tcp.display();
    }
}
