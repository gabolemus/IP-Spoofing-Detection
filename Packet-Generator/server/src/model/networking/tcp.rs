// This file contains the implementation to create a raw TCP packet.

use super::IPPacket;
use std::net::IpAddr;

/// TCP packet header structure.
pub struct TCPHeader {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// Sequence number.
    pub sequence_number: u32,
    /// Acknowledgement number.
    pub acknowledgement_number: u32,
    /// Data offset.
    pub data_offset: u8,
    /// Reserved.
    pub reserved: u8,
    /// Flags.
    pub flags: u16,
    /// Window size.
    pub window_size: u16,
    /// Checksum.
    pub checksum: u16,
    /// Urgent pointer.
    pub urgent_pointer: u16,
    /// Options.
    pub options: Option<Vec<u8>>,
}

/// TCP packet structure.
pub struct TCPPacket {
    /// TCP header.
    pub header: TCPHeader,
    /// Data.
    pub data: Option<Vec<u8>>,
    /// Raw packet.
    pub raw: Vec<u8>,
}

// TCP header implementations
impl TCPHeader {
    /// Create a new TCP header
    pub fn new(
        source_port: u16,
        destination_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        data_offset: u8,
        reserved: u8,
        flags: u16,
        window_size: u16,
        checksum: u16,
        urgent_pointer: u16,
        options: Option<Vec<u8>>,
    ) -> TCPHeader {
        TCPHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            data_offset,
            reserved,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
        }
    }
}

// TCP packet implementations
impl TCPPacket {
    /// Create a new TCP packet
    pub fn new(
        source_port: Option<u16>,
        destination_port: Option<u16>,
        data_offset: Option<u8>,
        reserved: Option<u8>,
        flags: Option<u16>,
        window_size: Option<u16>,
        urgent_pointer: Option<u16>,
        options: Option<Vec<u8>>,
        data: Option<Vec<u8>>,
    ) -> TCPPacket {
        // Save the header values
        let header = TCPHeader::new(
            source_port.unwrap_or(80),      // Default to port 80
            destination_port.unwrap_or(80), // Default to port 80
            0,                              // Sequence number
            0,                              // Acknowledgement number
            data_offset.unwrap_or(5),       // Default to 5
            reserved.unwrap_or(0),          // Default to 0
            flags.unwrap_or(2),             // Default to SYN
            window_size.unwrap_or(29200),   // Default to 29200
            0,                              // Will be calculated later
            urgent_pointer.unwrap_or(0),    // Default to 0
            options,                        // Options
        );

        // Create the raw TCP packet
        let mut packet: Vec<u8> = Vec::new();

        // Add the header fields to the raw packet
        // Source port (2 bytes - Index 0)
        packet.push((header.source_port >> 8) as u8); // Shift the first byte into place
        packet.push(header.source_port as u8); // Set the second byte by casting the source port to a u8

        // Destination port (2 bytes - Index 2)
        packet.push((header.destination_port >> 8) as u8); // Shift the first byte into place
        packet.push(header.destination_port as u8); // Set the second byte by casting the destination port to a u8

        // Sequence number (4 bytes - Index 4)
        packet.push((header.sequence_number >> 24) as u8); // Shift the first byte into place
        packet.push((header.sequence_number >> 16) as u8); // Shift the second byte into place
        packet.push((header.sequence_number >> 8) as u8); // Shift the third byte into place
        packet.push(header.sequence_number as u8); // Set the fourth byte by casting the sequence number to a u8

        // Acknowledgement number (4 bytes - Index 8)
        packet.push((header.acknowledgement_number >> 24) as u8); // Shift the first byte into place
        packet.push((header.acknowledgement_number >> 16) as u8); // Shift the second byte into place
        packet.push((header.acknowledgement_number >> 8) as u8); // Shift the third byte into place
        packet.push(header.acknowledgement_number as u8); // Set the fourth byte by casting the acknowledgement number to a u8

        // Data offset, reserved and flags (2 bytes - Index 12)
        let mut data_offset_reserved_flags: u16 = 0; // Create a variable to hold the data offset, reserved and flags
        data_offset_reserved_flags |= (header.data_offset as u16) << 12; // Set the data offset
        data_offset_reserved_flags |= (header.reserved as u16) << 9; // Set the reserved
        data_offset_reserved_flags |= header.flags; // Set the flags

        packet.push((data_offset_reserved_flags >> 8) as u8); // Shift the first byte into place
        packet.push(data_offset_reserved_flags as u8); // Set the second byte by casting the data offset, reserved and flags to a u8

        // Window size (2 bytes - Index 15)
        packet.push((header.window_size >> 8) as u8); // Shift the first byte into place
        packet.push(header.window_size as u8); // Set the second byte by casting the window size to a u8

        // Checksum (2 bytes - Index 17)
        packet.push((header.checksum >> 8) as u8); // Shift the first byte into place
        packet.push(header.checksum as u8); // Set the second byte by casting the checksum to a u8

        // Urgent pointer (2 bytes - Index 19)
        packet.push((header.urgent_pointer >> 8) as u8); // Shift the first byte into place
        packet.push(header.urgent_pointer as u8); // Set the second byte by casting the urgent pointer to a u8

        // Options (0-40 bytes - Index 21)
        if let Some(options) = &header.options {
            packet.extend_from_slice(options);
        }

        // Add the data to the packet
        if let Some(data) = &data {
            packet.extend_from_slice(&data);
        }

        // Create the TCP packet and return it
        TCPPacket {
            header,
            data: data.clone(),
            raw: packet,
        }
    }

    /// Calculate the checksum for the TCP header and the pseudo header
    fn calculate_header_checksum(&self, ip_packet: IPPacket) -> u16 {
        let mut checksum: u64 = 0;
        let src_ip_sum: u64;
        let dst_ip_sum: u64;
        let prot: u64;

        // Caluculate the sum of the source and destination IP addresses
        match ip_packet {
            IPPacket::IPv4(packet) => {
                src_ip_sum = self.get_ip_address_sum(IpAddr::from(packet.header.source_address));
                dst_ip_sum =
                    self.get_ip_address_sum(IpAddr::from(packet.header.destination_address));
                prot = packet.header.protocol as u64;
            }
            IPPacket::IPv6(packet) => {
                src_ip_sum = self.get_ip_address_sum(IpAddr::from(packet.header.source_address));
                dst_ip_sum =
                    self.get_ip_address_sum(IpAddr::from(packet.header.destination_address));
                prot = packet.header.next_header as u64;
            }
        };

        // Add the pseudo header to the checksum
        // Source IP address (4 bytes)
        checksum += src_ip_sum;

        // Destination IP address (4 bytes)
        checksum += dst_ip_sum;

        // Protocol (1 byte)
        checksum += prot;

        // TCP length (2 bytes)
        checksum += self.raw.len() as u64;
        // End of pseudo header

        // Add the TCP header to the checksum
        for i in 0..self.raw.len() {
            if i % 2 == 0 {
                checksum += (self.raw[i] as u64) << 8;
            } else {
                checksum += self.raw[i] as u64;
            }
        }

        // Add the carry bits to the checksum
        while checksum >> 16 != 0 {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        // Test a wrong checksum
        // checksum += 1;

        // Return the checksum
        !checksum as u16
    }

    /// Get the sum of the octets in an IP address
    fn get_ip_address_sum(&self, ip_address: IpAddr) -> u64 {
        // Closure to get the sum of the octets in an IP address
        let get_sum = |ip_address: IpAddr| -> u64 {
            let mut sum: u64 = 0;
            let octets = match ip_address {
                IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
            };

            for i in 0..octets.len() {
                if i % 2 == 0 {
                    sum += (octets[i] as u64) << 8; // For the even octets, shift the octet into place (<< 8) and add it to the sum
                } else {
                    sum += octets[i] as u64; // For the odd octets, just add the octet to the sum
                }
            }

            sum
        };

        get_sum(ip_address)
    }

    /// Set the header's checksum
    pub fn set_checksum(&mut self, ip_packet: IPPacket) {
        // Set the header's checksum
        self.header.checksum = self.calculate_header_checksum(ip_packet);

        // Set the checksum in the raw packet
        self.raw[16] = (self.header.checksum >> 8) as u8;
        self.raw[17] = self.header.checksum as u8;
    }

    /// Display the TCP packet in hexadecimal format
    pub fn display(&self) {
        println!("\n\nPaquete TCP:");

        // Display the packet in hexadecimal
        for (i, byte) in self.raw.iter().enumerate() {
            // Print the byte
            print!("{:02X} ", byte);

            // Print a new line every 16 bytes
            if i % 16 == 15 {
                println!();
            }
        }

        println!();
    }
}
