// This file contains the implementation to create a raw IPv4 packet.

use std::net::Ipv4Addr;

/// IPv4 packet header structure.
pub struct IPv4Header {
    /// IP version.
    pub version: u8,
    /// Internet Header Length.
    pub ihl: u8,
    /// Differentiated Services Code Point.
    pub dscp: u8,
    /// Explicit Congestion Notification.
    pub ecn: u8,
    /// Total length.
    pub total_length: u16,
    /// Identification.
    pub identification: u16,
    /// Flags.
    pub flags: u8,
    /// Fragment offset.
    pub fragment_offset: u16,
    /// Time to live.
    pub ttl: u8,
    /// Protocol.
    pub protocol: u8,
    /// Checksum.
    pub checksum: u16,
    /// Source IP address.
    pub source_address: Ipv4Addr,
    /// Destination IP address.
    pub destination_address: Ipv4Addr,
    /// Options.
    pub options: Option<Vec<u8>>,
    /// Is spoofed. If so, set the 'evil' bit to 1 to easily identify spoofed packets.
    /// This is not a standard feature, but will be used in the training of the NN.
    pub is_spoofed: bool,
}

/// IPv4 packet structure.
pub struct IPv4Packet {
    /// IPv4 header.
    pub header: IPv4Header,
    /// Data.
    pub data: Option<Vec<u8>>,
    /// Raw packet.
    pub raw: Vec<u8>,
}

// IPv4 packet header implementations
impl IPv4Header {
    /// Create a new IPv4 packet header.
    pub fn new(
        version: u8,
        ihl: u8,
        dscp: u8,
        ecn: u8,
        total_length: u16,
        identification: u16,
        flags: u8,
        fragment_offset: u16,
        ttl: u8,
        protocol: u8,
        header_checksum: u16,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        options: Option<Vec<u8>>,
        is_spoofed: bool,
    ) -> Self {
        IPv4Header {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum: header_checksum,
            source_address: source_ip,
            destination_address: destination_ip,
            options,
            is_spoofed,
        }
    }
}

// IPv4 packet implementations
impl IPv4Packet {
    /// Create a new IPv4 packet.
    pub fn new(
        dscp: Option<u8>,
        ecn: Option<u8>,
        identification: Option<u16>,
        flags: Option<u8>,
        fragment_offset: Option<u16>,
        ttl: u8,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        options: Option<Vec<u8>>,
        data: Option<Vec<u8>>,
        is_spoofed: bool,
    ) -> Self {
        // Save the header values
        let mut header = IPv4Header::new(
            4,                                   // Always 4 for IPv4
            5,                                   // Default 5
            dscp.unwrap_or(0),                   // Default 0
            ecn.unwrap_or(0),                    // Default 0
            0,                                   // Will be calculated later
            identification.unwrap_or(0xabcd),    // Default 0xabcd
            get_packet_flags(flags, is_spoofed), // Default 0
            fragment_offset.unwrap_or(0),        // Default 0
            ttl,                                 // Commonly 64; provided by the user
            6,                                   // 6 for TCP (as it's the downstream layer)
            0,                                   // Will be calculated later
            source_ip,                           // Provided by the user
            destination_ip,                      // Provided by the user
            options,                             // Optionally provided by the user
            is_spoofed,                          // Provided by the user
        );

        // Create the raw IPv4 packet
        let mut packet: Vec<u8> = Vec::new();

        // Add the header and payload to the packet
        // Version and IHL (1 byte - Index 0)
        packet.push((header.version << 4) | header.ihl); // The version is the first 4 bits and IHL is the last 4 bits

        // DSCP and ECN (1 byte - Index 1)
        packet.push((header.dscp << 2) | header.ecn); // Shift the DSCP 2 bits to the left and add the ECN

        // Total length (2 bytes - Index 2)
        packet.push((header.total_length >> 8) as u8); // Shift the first byte into place
        packet.push(header.total_length as u8); // Set the second byte by casting the total length to a u8

        // Identification (2 bytes - Index 4)
        packet.push((header.identification >> 8) as u8); // Shift the first byte into place
        packet.push(header.identification as u8); // Set the second byte by casting the identification to a u8

        // Flags and fragment offset (2 bytes - Index 6)
        packet.push((header.flags << 5) | ((header.fragment_offset >> 8) as u8)); // Shift the flags 5 bits to the left and add the first byte of the fragment offset
        packet.push(header.fragment_offset as u8); // Set the last byte of the fragment offset by casting it to a u8

        // TTL (1 byte - Index 8)
        packet.push(header.ttl); // The TTL is already a whole byte

        // Protocol (1 byte - Index 9)
        packet.push(header.protocol); // The protocol is already a whole byte

        // Header checksum (2 bytes - Index 10) - Empty for now
        packet.push((header.checksum >> 8) as u8); // Shift the first byte into place
        packet.push(header.checksum as u8); // Set the second byte by casting the header checksum to a u8

        // Source IP (4 bytes - Index 12)
        let src_ip_octects = header.source_address.octets(); // Get the octects of the source IP
        packet.push(src_ip_octects[0]); // Set the first octect
        packet.push(src_ip_octects[1]); // Set the second octect
        packet.push(src_ip_octects[2]); // Set the third octect
        packet.push(src_ip_octects[3]); // Set the fourth octect

        // Destination IP (4 bytes - Index 16)
        let dst_ip_octects = header.destination_address.octets(); // Get the octects of the destination IP
        packet.push(dst_ip_octects[0]); // Set the first octect
        packet.push(dst_ip_octects[1]); // Set the second octect
        packet.push(dst_ip_octects[2]); // Set the third octect
        packet.push(dst_ip_octects[3]); // Set the fourth octect

        // Options (0-40 bytes - Index 20)
        if let Some(options) = &header.options {
            // If the user provided options, add them to the packet
            packet.extend(options);
        }

        // Data (0-65,535 bytes - Index 20+)
        if let Some(data) = &data {
            // If the user provided data, add it to the packet
            packet.extend(data);
        }

        // Calculate the total length
        header.total_length = packet.len() as u16;

        // Set the total length in the packet
        packet[2] = (header.total_length >> 8) as u8; // Shift the first byte into place
        packet[3] = header.total_length as u8; // Set the second byte by casting the total length to a u8

        // Create the IPv4 packet and return it
        IPv4Packet {
            header,
            data: data.clone(),
            raw: packet,
        }
    }

    /// Calculate the packet's header checksum
    pub fn calculate_header_checksum(&mut self) -> u16 {
        // Initialize the checksum
        let mut checksum: u64 = 0;

        // Add the version and IHL
        checksum += self.raw[0] as u64;

        // Add the DSCP and ECN
        checksum += self.raw[1] as u64;

        // Add the total length
        checksum += (self.raw[2] as u64) << 8; // Shift the first byte into place
        checksum += self.raw[3] as u64; // Add the second byte

        // Add the identification
        checksum += (self.raw[4] as u64) << 8; // Shift the first byte into place
        checksum += self.raw[5] as u64; // Add the second byte

        // Add the flags and fragment offset
        checksum += (self.raw[6] as u64) << 8; // Shift the first byte into place
        checksum += self.raw[7] as u64; // Add the second byte

        // Add the TTL and protocol
        checksum += (self.raw[8] as u64) << 8; // Shift the first byte into place
        checksum += self.raw[9] as u64; // Add the second byte

        // Add the source IP address
        checksum += (self.raw[12] as u64) << 24; // Shift the first byte into place
        checksum += (self.raw[13] as u64) << 16; // Shift the second byte into place
        checksum += (self.raw[14] as u64) << 8; // Shift the third byte into place
        checksum += self.raw[15] as u64; // Add the fourth byte

        // Add the destination IP address
        checksum += (self.raw[16] as u64) << 24; // Shift the first byte into place
        checksum += (self.raw[17] as u64) << 16; // Shift the second byte into place
        checksum += (self.raw[18] as u64) << 8; // Shift the third byte into place
        checksum += self.raw[19] as u64; // Add the fourth byte

        // Add the options
        if let Some(options) = &self.header.options {
            // If the user provided options, add them to the checksum
            for i in 0..options.len() {
                // Loop through the options
                checksum += options[i] as u64; // Add the option to the checksum
            }
        }

        checksum = (checksum >> 16) + (checksum & 0xFFFF); // Add the carry
        checksum += checksum >> 16; // Add the carry again
        checksum = !checksum; // Invert the checksum

        // Test a wrong checksum
        // checksum += 1;

        // Set the header checksum
        self.header.checksum = checksum as u16;

        // Return the header checksum
        self.header.checksum
    }

    /// Set the packet's header checksum
    pub fn set_header_checksum(&mut self) {
        // Set the header checksum
        self.header.checksum = self.calculate_header_checksum();

        // Set the checksum in the packet
        self.raw[10] = (self.header.checksum >> 8) as u8; // Shift the first byte into place
        self.raw[11] = self.header.checksum as u8; // Set the second byte by casting the header checksum to a u8
    }

    /// Return a copy of the packet.
    /// Used to clone the package to calculate the TCP checksum.
    pub fn clone(&self) -> IPv4Packet {
        // Create a new packet
        let mut packet = IPv4Packet::new(
            Some(self.header.dscp),
            Some(self.header.ecn),
            Some(self.header.identification),
            Some(self.header.flags),
            Some(self.header.fragment_offset),
            self.header.ttl,
            self.header.source_address,
            self.header.destination_address,
            self.header.options.clone(),
            self.data.clone(),
            self.header.is_spoofed,
        );

        // Set the header checksum
        packet.header.checksum = self.header.checksum;

        // Return the packet
        packet
    }

    /// Display the packet in hexadecimal
    pub fn display(&self) {
        println!("\nPaquete IPv4:");

        // Display the packet in hexadecimal format
        for (i, byte) in self.raw.iter().enumerate() {
            // Print the byte
            print!("{:02X} ", byte);

            // Print a new line every 16 bytes
            if i % 16 == 15 {
                println!();
            }
        }
    }
}

/// Get the packet flags provided by the user or return the default flags.
/// Also, set the 'evil' bit if spoofed parameter is true.
fn get_packet_flags(flags: Option<u8>, is_spoofed: bool) -> u8 {
    // Get the flags provided by the user or return the default flags
    let flags = match flags {
        Some(flags) => flags,
        None => 0b0000_0000,
    };

    // Set the 'evil' bit if spoofed parameter is true
    if is_spoofed {
        // println!("Flags with evil bit set: {:08b}", flags | 0b0000_0100);
        flags | 0b0000_0100
    } else {
        // println!("Flags without evil bit set: {:08b}", flags);
        flags
    }
}
