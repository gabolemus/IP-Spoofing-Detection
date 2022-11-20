// This file contains the implementation to create a raw IPv6 packet.

use std::net::Ipv6Addr;

/// IPv6 packet header structure.
pub struct IPv6Header {
    /// IP version.
    pub version: u8,
    /// Traffic class.
    pub traffic_class: u8,
    /// Flow label.
    pub flow_label: u32,
    /// Payload length.
    pub payload_length: u16,
    /// Next header.
    pub next_header: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Source IP Address.
    pub source_address: Ipv6Addr,
    /// Destination IP Address.
    pub destination_address: Ipv6Addr,
}

/// IPv6 packet structure.
pub struct IPv6Packet {
    /// IPv6 header.
    pub header: IPv6Header,
    /// Data.
    pub data: Option<Vec<u8>>,
    /// Raw packet.
    pub raw: Vec<u8>,
}

// IPv6 packet header implementations
impl IPv6Header {
    /// Create a new IPv4 packet header.
    pub fn new(
        version: u8,
        traffic_class: u8,
        flow_label: u32,
        payload_length: u16,
        next_header: u8,
        hop_limit: u8,
        source_address: Ipv6Addr,
        destination_address: Ipv6Addr,
    ) -> IPv6Header {
        IPv6Header {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source_address,
            destination_address,
        }
    }
}

// IPv6 packet implementations
impl IPv6Packet {
    /// Create a new IPv4 packet.
    pub fn new(
        traffic_class: Option<u8>,
        flow_label: Option<u32>,
        payload_length: Option<u16>,
        next_header: Option<u8>,
        hop_limit: u8,
        source_address: Ipv6Addr,
        destination_address: Ipv6Addr,
        data: Option<Vec<u8>>,
    ) -> Self {
        // Save the header values
        let mut header = IPv6Header::new(
            6,                           // Always 6 for IPv6
            traffic_class.unwrap_or(0),  // Default to 0
            flow_label.unwrap_or(0),     // Default to 0
            payload_length.unwrap_or(0), // Calculate later
            next_header.unwrap_or(0),    // Default to 0
            hop_limit,                   // Provided by user; common values are 64 or 255
            source_address,              // Provided by user
            destination_address,         // Provided by user
        );

        // Create the raw packet
        let mut packet: Vec<u8> = Vec::new();

        // Add the header and payload to the packet
        // Version and first 4 bits of traffic class (1 byte - Index 0)
        packet.push((header.version << 4) | (header.traffic_class >> 4));

        // Last 4 bits of traffic class and first 4 bits of flow label (1 byte - Index 1)
        let mut second_byte: u8 = 0;
        second_byte |= (header.traffic_class & 0x0F) << 4;
        second_byte |= (header.flow_label >> 16) as u8;
        packet.push(second_byte);

        // Last 16 bits of flow label (2 bytes - Index 2)
        packet.push((header.flow_label >> 8) as u8);
        packet.push(header.flow_label as u8);

        // Payload length (2 bytes - Index 4)
        packet.push((header.payload_length >> 8) as u8);
        packet.push(header.payload_length as u8);

        // Next header (1 byte - Index 6)
        packet.push(header.next_header);

        // Hop limit (1 byte - Index 7)
        packet.push(header.hop_limit);

        // Source address (16 bytes - Index 8)
        for byte in header.source_address.octets().iter() {
            packet.push(*byte);
        }

        // Destination address (16 bytes - Index 24)
        for byte in header.destination_address.octets().iter() {
            packet.push(*byte);
        }

        // Add the data to the packet
        if let Some(data) = &data {
            // Add the data to the packet
            packet.append(&mut data.clone());

            // Update the payload length
            header.payload_length = data.len() as u16;

            // Update the packet
            packet[4] = (header.payload_length >> 8) as u8;
            packet[5] = header.payload_length as u8;
        }

        // Return the packet
        IPv6Packet {
            header,
            data: data.clone(),
            raw: packet,
        }
    }

    /// Return a copy of the packet.
    ///
    /// Used to clone the package to calculate the TCP checksum.
    pub fn clone(&self) -> IPv6Packet {
        IPv6Packet::new(
            Some(self.header.traffic_class),
            Some(self.header.flow_label),
            Some(self.header.payload_length),
            Some(self.header.next_header),
            self.header.hop_limit,
            self.header.source_address,
            self.header.destination_address,
            self.data.clone(),
        )
    }

    /// Display the packet in hexadecimal
    pub fn display(&self) {
        println!("\nIPv6 Packet:");

        // Display the packet in hexadecimal format
        for (i, byte) in self.raw.iter().enumerate() {
            print!("{:02X} ", byte);

            // Add a new line every 16 bytes
            if (i + 1) % 16 == 0 {
                println!();
            }
        }
    }
}
