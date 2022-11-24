/// This file contains the struct and its implementations for a PCAP packet.
use std::collections::HashMap;

/// Struct that represents a pcap packet
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet number
    pub packet_number: u32,

    /// Wether the packet is spoofed, for the test data, the packets with the
    /// field "ip.flags.rb" (reserved bit) set to 1 are spoofed.
    ///
    /// This does not reflect reality, as this field is not used in real
    /// applications, but will be used for the test data.
    pub is_spoofed: bool,

    /// Hashmap that contains the metadata of the packet
    pub metadata: HashMap<String, String>,

    /// The fields of the packet.
    ///
    /// Not all the packets will have the same fields, so they are stored in a
    /// vector and when the CSV file is created, the packets with missing fields
    /// will have an empty string ("") in these fields.
    pub fields: Vec<String>,
}

/// Packet implementation
impl Packet {
    /// Create a new empty packet
    pub fn new() -> Self {
        Self {
            packet_number: 0,
            is_spoofed: false,
            metadata: HashMap::new(),
            fields: Vec::new(),
        }
    }

    /// Update the packet number
    pub fn update_packet_number(&mut self, packet_number: u32) {
        self.packet_number = packet_number;
    }

    /// Set the vector of fields for the packet
    pub fn set_fields(&mut self, fields: Vec<String>) {
        self.fields = fields;
    }

    /// Add a new metadata value to the corresponding layer
    pub fn add_metadata(&mut self, metadata_name: &str, metadata_value: &str) {
        // If the "ip.flags.rb" field is set to 1, set the "is_spoofed" field to
        // true
        if metadata_name == "ip.flags.rb" && metadata_value == "1" {
            self.is_spoofed = true;
        }

        // If the field is "tcp.payload", remove the new lines and convert the
        // hex field to a string
        if metadata_name == "tcp.payload" {
            self.metadata.insert(
                metadata_name.to_string(),
                remove_new_lines(hex_to_string(metadata_value).as_str()),
            );
        } else {
            self.metadata
                .insert(metadata_name.to_string(), remove_new_lines(metadata_value));
        }

        // Add the field name to the corresponding vector and insert the key-
        // value pair in the hashmap
        self.fields.push(metadata_name.to_string());
    }

    /// Get CSV header
    pub fn get_csv_header(&self) -> String {
        // Initialize a string with the "frame.number" and "is_spoofed" field
        let mut header = "frame.number|is_spoofed|".to_string();

        // Add the rest of the fields; exclude the "frame.number" field
        for field in &self.fields {
            if field != "frame.number" {
                header.push_str(format!("{}|", field).as_str());
            }
        }

        // // Print the count of the fields
        // println!("Fields: {}", self.fields.len());

        // Remove the last comma and return the header
        header.pop();
        header
    }

    /// Get CSV data
    pub fn get_csv_data(&self) -> String {
        // Initialize a string with the "frame.number" and "is_spoofed" field
        let mut data = format!("{}|{}|", self.metadata["frame.number"], self.is_spoofed);

        // Add the rest of the fields
        for field in &self.fields {
            // If the field is not in the packet, add an empty string.
            // Exclude the "frame.number" field

            if self.metadata.contains_key(field) && !field.contains("frame.number") {
                data.push_str(format!("{}|", self.metadata[field]).as_str());
            } else if !field.contains("frame.number") {
                data.push_str("|");
            }
        }

        // Remove the last comma and return the data
        data.pop();
        data
    }
}

/// Convert Hex string to unicode string
/// For example: 22:73:74:61:74:75:73:22:3a:22:73:74:61:72:74:22 -> "status":"start"
/// Skip the colon
fn hex_to_string(hex: &str) -> String {
    let mut result = String::new();
    let mut hex = hex.to_string();

    hex.retain(|c| c != ':');

    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();

        result.push(byte as char);
    }

    result
}

/// Remove new line characters from a string
fn remove_new_lines(string: &str) -> String {
    string
        .replace("\r", "")
        .replace("\n", "")
        .replace("\r\n", "")
}
