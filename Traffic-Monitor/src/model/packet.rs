/// This file contains the struct and its implementations for a PCAP packet.
use std::collections::HashMap;

/// Struct that represents a pcap packet
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet number
    pub packet_number: u32,

    /// Whether the packet is spoofed, for the test data, the packets with the
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

    /// Get an array of all the fields names of the packet to be printed in the CSV
    pub fn get_fields_names(&self) -> Vec<String> {
        // Fields referenced from the Wireshark documentation (https://www.wireshark.org/docs/dfref/)
        let mut fields = Vec::new();

        // Add the metadata fields
        // Packet frame fields
        fields.push("frame.encap_type".to_string());
        fields.push("frame.cap_len".to_string());
        fields.push("frame.len".to_string());
        fields.push("frame.protocols".to_string());
        fields.push("frame.time_delta".to_string());
        fields.push("frame.time_relative".to_string());
        // fields.push("frame.number".to_string());
        // fields.push("frame.time_delta_displayed".to_string());
        // fields.push("frame.time_epoch".to_string());

        // SLL - Linux cooked capture fields
        fields.push("sll.etype".to_string());
        fields.push("sll.ifindex".to_string());
        fields.push("sll.pkttype".to_string());
        fields.push("sll.src.eth".to_string());
        fields.push("sll.unused".to_string());
        // fields.push("sll.halen".to_string());
        // fields.push("sll.hatype".to_string());

        // IPv4 fields
        fields.push("ip.hdr_len".to_string());
        fields.push("ip.len".to_string());
        fields.push("ip.flags.rb".to_string());
        fields.push("ip.flags.df".to_string());
        fields.push("ip.flags.mf".to_string());
        fields.push("ip.frag_offset".to_string());
        fields.push("ip.ttl".to_string());
        fields.push("ip.proto".to_string());
        fields.push("ip.src".to_string());
        fields.push("ip.dst".to_string());
        fields.push("ip.version".to_string());
        // fields.push("ip.addr".to_string());
        // fields.push("ip.checksum".to_string());
        // fields.push("ip.checksum.status".to_string());
        // fields.push("ip.dsfield".to_string());
        // fields.push("ip.dsfield.dscp".to_string());
        // fields.push("ip.dsfield.ecn".to_string());
        // fields.push("ip.dst_host".to_string());
        // fields.push("ip.flags".to_string());
        // fields.push("ip.host".to_string());
        // fields.push("ip.id".to_string());
        // fields.push("ip.src_host".to_string());

        // IPv6 fields
        // fields.push("ipv6.addr".to_string());
        // fields.push("ipv6.dst".to_string());
        // fields.push("ipv6.dst_host".to_string());
        // fields.push("ipv6.flow".to_string());
        // fields.push("ipv6.hlim".to_string());
        // fields.push("ipv6.hopopts.nxt".to_string());
        // fields.push("ipv6.host".to_string());
        // fields.push("ipv6.nxt".to_string());
        // fields.push("ipv6.opt.length".to_string());
        // fields.push("ipv6.opt.router_alert".to_string());
        // fields.push("ipv6.opt.type".to_string());
        // fields.push("ipv6.opt.type.action".to_string());
        // fields.push("ipv6.opt.type.change".to_string());
        // fields.push("ipv6.opt.type.rest".to_string());
        // fields.push("ipv6.plen".to_string());
        // fields.push("ipv6.src".to_string());
        // fields.push("ipv6.src_host".to_string());
        // fields.push("ipv6.tclass".to_string());
        // fields.push("ipv6.tclass.dscp".to_string());
        // fields.push("ipv6.tclass.ecn".to_string());
        // fields.push("ipv6.version".to_string());

        // TCP fields
        fields.push("tcp.srcport".to_string());
        fields.push("tcp.dstport".to_string());
        fields.push("tcp.hdr_len".to_string());
        fields.push("tcp.len".to_string());
        fields.push("tcp.ack".to_string());
        fields.push("tcp.flags.ack".to_string());
        fields.push("tcp.flags.ae".to_string());
        fields.push("tcp.flags.cwr".to_string());
        fields.push("tcp.flags.ece".to_string());
        fields.push("tcp.flags.fin".to_string());
        fields.push("tcp.flags.push".to_string());
        fields.push("tcp.flags.res".to_string());
        fields.push("tcp.flags.reset".to_string());
        fields.push("tcp.flags.syn".to_string());
        fields.push("tcp.flags.urg".to_string());
        fields.push("tcp.window_size".to_string());
        fields.push("tcp.time_delta".to_string());
        // fields.push("tcp.ack_raw".to_string());
        // fields.push("tcp.analysis.ack_rtt".to_string());
        // fields.push("tcp.analysis.acks_frame".to_string());
        // fields.push("tcp.analysis.bytes_in_flight".to_string());
        // fields.push("tcp.analysis.duplicate_ack_frame".to_string());
        // fields.push("tcp.analysis.duplicate_ack_num".to_string());
        // fields.push("tcp.analysis.initial_rtt".to_string());
        // fields.push("tcp.analysis.push_bytes_sent".to_string());
        // fields.push("tcp.analysis.rto".to_string());
        // fields.push("tcp.analysis.rto_frame".to_string());
        // fields.push("tcp.checksum".to_string());
        // fields.push("tcp.checksum.status".to_string());
        // fields.push("tcp.completeness".to_string());
        // fields.push("tcp.flags".to_string());
        // fields.push("tcp.nxtseq".to_string());
        // fields.push("tcp.option_kind".to_string());
        // fields.push("tcp.option_len".to_string());
        // fields.push("tcp.options".to_string());
        // fields.push("tcp.options.mss".to_string());
        // fields.push("tcp.options.mss_val".to_string());
        // fields.push("tcp.options.sack_perm".to_string());
        // fields.push("tcp.options.timestamp.tsecr".to_string());
        // fields.push("tcp.options.timestamp.tsval".to_string());
        // fields.push("tcp.options.wscale".to_string());
        // fields.push("tcp.options.wscale.multiplier".to_string());
        // fields.push("tcp.options.wscale.shift".to_string());
        // fields.push("tcp.payload".to_string());
        // fields.push("tcp.payload_length".to_string());
        // fields.push("tcp.pdu.time".to_string());
        // fields.push("tcp.port".to_string());
        // fields.push("tcp.proc.dstcmd".to_string());
        // fields.push("tcp.proc.dstpid".to_string());
        // fields.push("tcp.proc.dstuid".to_string());
        // fields.push("tcp.proc.dstuname".to_string());
        // fields.push("tcp.proc.srcuname".to_string());
        // fields.push("tcp.segment_data".to_string());
        // fields.push("tcp.seq".to_string());
        // fields.push("tcp.seq_raw".to_string());
        // fields.push("tcp.stream".to_string());
        // fields.push("tcp.time_relative".to_string());
        // fields.push("tcp.urgent_pointer".to_string());
        // fields.push("tcp.urgent_pointer.non_zero".to_string());
        // fields.push("tcp.window_size_scalefactor".to_string());

        // UDP fields
        // fields.push("udp.checksum".to_string());
        // fields.push("udp.dstport".to_string());
        // fields.push("udp.length".to_string());
        // fields.push("udp.length.bad".to_string());
        // fields.push("udp.length.bad_zero".to_string());
        // fields.push("udp.payload".to_string());
        // fields.push("udp.pdu.size".to_string());
        // fields.push("udp.port".to_string());
        // fields.push("udp.possible_traceroute".to_string());
        // fields.push("udp.proc.dstcmd".to_string());
        // fields.push("udp.proc.dstpid".to_string());
        // fields.push("udp.proc.dstuid".to_string());
        // fields.push("udp.proc.dstuname".to_string());
        // fields.push("udp.proc.srccmd".to_string());
        // fields.push("udp.proc.srcpid".to_string());
        // fields.push("udp.proc.srcuid".to_string());
        // fields.push("udp.proc.srcuname".to_string());
        // fields.push("udp.srcport".to_string());
        // fields.push("udp.stream".to_string());
        // fields.push("udp.time_delta".to_string());
        // fields.push("udp.time_relative".to_string());

        // HTTP fields
        // fields.push("http.request.full_uri".to_string());
        // fields.push("http.request".to_string());
        // fields.push("http.request_number".to_string());

        // JSON fields
        // fields.push("json.array".to_string());
        // fields.push("json.array_compact".to_string());
        // fields.push("json.array_item_compact".to_string());
        // fields.push("json.binary_data".to_string());
        // fields.push("json.ignored_leading_bytes".to_string());
        // fields.push("json.key".to_string());
        // fields.push("json.member".to_string());
        // fields.push("json.member_compact".to_string());
        // fields.push("json.member_with_value".to_string());
        // fields.push("json.object".to_string());
        // fields.push("json.object_compact".to_string());
        // fields.push("json.path".to_string());
        // fields.push("json.path_with_value".to_string());
        // fields.push("json.value.false".to_string());
        // fields.push("json.value.nan".to_string());
        // fields.push("json.value.null".to_string());
        // fields.push("json.value.number".to_string());
        // fields.push("json.value.string".to_string());
        // fields.push("json.value.true".to_string());

        // Return the fields
        fields
    }

    /// Get the metadata value for a given field
    pub fn get_metadata(&self, field: &str) -> Option<&str> {
        self.metadata.get(field).map(|s| s.as_str())
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
            // Add the "tcp.payload_length" field
            self.metadata.insert(
                "tcp.payload_length".to_string(),
                metadata_value.len().to_string(),
            );

            self.metadata.insert(
                metadata_name.to_string(),
                remove_new_lines(hex_to_string(metadata_value).as_str()).replace("|", ";"),
            );
        } else {
            self.metadata
                .insert(metadata_name.to_string(), remove_new_lines(metadata_value));
        }

        // Add the field name to the corresponding vector and insert the key-
        // value pair in the hashmap
        self.fields
            .push(metadata_name.to_string().replace("|", "."));
    }

    /// Get CSV header
    pub fn get_csv_header(&self) -> String {
        // Initialize a string with the "frame.number" and "is_spoofed" field
        // let mut header = "frame.number|is_spoofed|".to_string();
        let mut header = "is_spoofed|".to_string();

        // Add the other fields, except the "frame.number" and "is_spoofed"
        // fields
        let fields = &self.get_fields_names();

        for field in fields {
            if field != "frame.number" && field != "is_spoofed" {
                header.push_str(field);
                header.push('|');
            }
        }

        // // Add the rest of the fields; exclude the "frame.number" field
        // for field in &self.fields {
        //     if field != "frame.number" {
        //         header.push_str(format!("{}|", field).as_str());
        //     }
        // }

        // Remove the last comma and return the header
        header.pop();
        header
    }

    /// Get CSV data
    pub fn get_csv_data(&self) -> String {
        // Initialize a string with the "frame.number" and "is_spoofed" field
        // let mut data = format!("{}|{}|", self.metadata["frame.number"], self.is_spoofed);
        let mut data = format!("{}|", self.is_spoofed);

        // Add the rest of the fields
        for field in &self.fields {
            // If the field is not in the packet, add an empty string.
            // Exclude the "frame.number" field
            if self.metadata.contains_key(field) && !field.contains("frame.number") {
                let field_name = field.as_str();

                data.push_str(format!("{}|", self.metadata[field_name]).as_str());

                // if field_name == "frame.protocols" {
                //     // Get the protocols stack
                //     let protocols = handle_protocols_stack_field(self.metadata[field].as_str());

                //     // Add the protocols to the data string
                //     data.push_str(format!("{}|", protocols).as_str());
                // } else if field_name == "sll.etype"
                //     || field_name == "ip.dsfield"
                //     || field_name == "ip.flags"
                //     || field_name == "ip.checksum"
                //     || field_name == "ip.id"
                //     || field_name == "ipv6.flow"
                //     || field_name == "ipv6.opt.type"
                //     || field_name == "ipv6.opt.type.rest"
                //     || field_name == "ipv6.tclass"
                //     || field_name == "tcp.checksum"
                //     || field_name == "tcp.flags"
                // {
                //     // Starts with "0x"
                //     // Hex field to decimal
                //     let etype = hex_to_decimal(self.metadata[field].as_str());

                //     // Add the protocol to the data string
                //     data.push_str(format!("{}|", etype).as_str());
                // } else if field_name == "sll.src.eth"
                //     || field_name == "sll.unused"
                //     || field_name == "ipv6.addr"
                //     || field_name == "ipv6.dst"
                //     || field_name == "ipv6.dst_host"
                //     || field_name == "ipv6.host"
                //     || field_name == "ipv6.src"
                //     || field_name == "ipv6.src_host"
                //     || field_name == "tcp.options"
                //     || field_name == "tcp.options.mss"
                //     || field_name == "tcp.segment_data"
                // {
                //     // Hexadecimals separated by colons
                //     // Convert the MAC address to a string
                //     let mac = hex_colon_to_decimal(self.metadata[field].as_str());

                //     // Add the MAC address to the data string
                //     data.push_str(format!("{}|", mac).as_str());
                // } else if field_name == "ip.addr"
                //     || field_name == "ip.dst"
                //     || field_name == "ip.dst_host"
                //     || field_name == "ip.host"
                //     || field_name == "ip.src"
                //     || field_name == "ip.src_host"
                // {
                //     // 4 octets separated by dots
                //     // Get the IP addresses
                //     let ip_addresses = ipv4_to_decimal(self.metadata[field].as_str());

                //     // Add the IP addresses to the data string
                //     data.push_str(format!("{}|", ip_addresses).as_str());
                // } else if field_name == "tcp.payload"
                //     || field_name == "http.request.full_uri"
                //     || field_name == "json.value.string"
                //     || field_name == "json.path_with_value"
                //     || field_name == "json.path"
                //     || field_name == "json.member_with_value"
                //     || field_name == "json.member"
                //     || field_name == "json.key"
                // {
                //     // If the payload is not empty, append a "1"
                //     if self.metadata[field].len() > 0
                //         && (self.metadata[field] != "" || self.metadata[field] != " ")
                //     {
                //         data.push_str("1|");
                //     } else {
                //         data.push_str("0|");
                //     }
                // } else {
                //     // If the field is empty, return a "0"
                //     if self.metadata[field] == "" || self.metadata[field] == " " {
                //         data.push_str("0|");
                //     } else {
                //         data.push_str(format!("{}|", self.metadata[field]).as_str());
                //     }
                // }
            } else if !field.contains("frame.number") {
                data.push_str("-1|");
            }
        }

        // Remove the last delimiter and return the data
        data.pop();
        data
    }
}

/// Convert Hex string to unicode string
/// For example: 22:73:74:61:74:75:73:22:3a:22:73:74:61:72:74:22 -> "status":"start"
/// Skip the colon
pub fn hex_to_string(hex: &str) -> String {
    let mut result = String::new();
    let mut hex = hex.to_string();

    hex.retain(|c| c != ':');

    let mut chars = hex.chars();

    while let Some(c) = chars.next() {
        let mut s = String::new();
        s.push(c);
        s.push(match chars.next() {
            Some(c) => c,
            None => continue,
        });

        let c = match u8::from_str_radix(&s, 16) {
            Ok(c) => c as char,
            Err(_) => continue,
        };

        result.push(c);
    }

    result
}

/// Convert Hex string to decimal string
/// For example: 0x0800 -> 2048
pub fn hex_to_decimal(hex: &str) -> String {
    let prefix_removed = hex.trim_start_matches("0x");

    i64::from_str_radix(prefix_removed, 16).unwrap().to_string()
}

/// Remove new line characters from a string
fn remove_new_lines(string: &str) -> String {
    string
        .replace("\r", "")
        .replace("\n", "")
        .replace("\r\n", "")
}

/// Handle the value for the `frame.protocols` field
pub fn handle_protocols_stack_field(protocols_stack: &str) -> String {
    match protocols_stack {
        "sll:ethertype:arp" => "0".to_string(),
        "sll:ethertype:ip:tcp" => "1".to_string(),
        "sll:ethertype:ip:tcp:data" => "2".to_string(),
        "sll:ethertype:ip:tcp:http" => "3".to_string(),
        "sll:ethertype:ip:tcp:http:json" => "4".to_string(),
        "sll:ethertype:ip:udp" => "5".to_string(),
        "sll:ethertype:ip6:icmpv6" => "6".to_string(),
        "sll:ethertype:ipv6:ipv6.hopopts:icmpv6" => "7".to_string(),
        &_ => "-1".to_string(),
    }
}

/// Get the default value for a metadata field
pub fn get_default_field_value(field_name: &str) -> String {
    match field_name {
        "frame.protocols" => "".to_string(),
        &_ => "".to_string(),
    }
}

/// Convert a MAC address to a decimal string
/// For example: f6:f4:cb:be:e5:50 -> 271531250738512
pub fn hex_colon_to_decimal(mac: &str) -> String {
    // Remove the colons
    let mut mac = mac.to_string();
    mac.retain(|c| c != ':');

    if mac.len() < 12 {
        return i64::from_str_radix(&mac, 16).unwrap_or(0).to_string();
    }

    // If the MAC address is longer than 12 characters, only use the first 12
    if mac.len() > 12 {
        mac = mac[..12].to_string();
    }

    i64::from_str_radix(&mac, 16).unwrap_or(0).to_string()
}

/// IPv4 to decimal
/// For example: 181.174.107.122 -> 3048106874
pub fn ipv4_to_decimal(ip: &str) -> String {
    let mut ip = ip.to_string();
    ip.retain(|c| c != '.');

    i64::from_str_radix(&ip, 10).unwrap_or(0).to_string()
}
