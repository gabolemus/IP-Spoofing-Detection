use super::IPv4Packet;
use crate::model::networking::{IPPacket, TCPPacket};
use std::net::Ipv4Addr;

/// TCP/IP version 4 packet structure.
pub struct TCPIPv4Packet {
    /// IPv4 packet.
    pub ipv4: IPv4Packet,
    /// TCP packet.
    pub tcp: TCPPacket,
    /// Raw packet.
    pub raw: Vec<u8>,
}

// TCP/IP version 4 packet implementations
impl TCPIPv4Packet {
    pub fn new(
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        data: Option<Vec<u8>>,
        options: Option<Vec<u8>>,
        port: u16,
        is_spoofed: bool,
    ) -> TCPIPv4Packet {
        // IPv4 Packet
        let mut ipv4_packet = IPv4Packet::new(
            None,
            None,
            None,
            None,
            None,
            if rand::random() { 64 } else { 128 }, // Simulate common Linux TTL (64) and Windows TTL (128)
            source_ip,
            destination_ip,
            None,
            None,
            is_spoofed,
        );

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

        // This packet will have the wrong total length and checksum, as it only considers the IPv4 header's length
        let raw = [&ipv4_packet.raw[..], &tcp_packet.raw[..]].concat();

        // Set the new total length in the IPv4 header (Fix the total length)
        ipv4_packet.header.total_length = raw.len() as u16;

        // Fix the total length in the raw packet
        ipv4_packet.raw[2] = (ipv4_packet.header.total_length >> 8) as u8;
        ipv4_packet.raw[3] = ipv4_packet.header.total_length as u8;

        ipv4_packet.set_header_checksum();
        tcp_packet.set_checksum(IPPacket::IPv4(ipv4_packet.clone()));

        // Shadow the previous raw packet
        let raw = [&ipv4_packet.raw[..], &tcp_packet.raw[..]].concat();

        // Create the TCP/IP version 4 packet and return it
        TCPIPv4Packet {
            ipv4: ipv4_packet,
            tcp: tcp_packet,
            raw,
        }
    }

    /// Display the packet in hexadecimal format
    pub fn display(&self) {
        // Display the IPv4 header
        self.ipv4.display();

        // Display the TCP packet
        self.tcp.display();
    }
}
