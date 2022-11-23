/// Struct that represents the SLL layer
///
/// Referenced from the [Wireshark documentation](https://www.wireshark.org/docs/dfref/s/sll.html)
#[derive(Debug)]
pub struct SLL {
    /// Protocol - Unsigned integer (2 bytes) - sll.etype
    pub etype: String,
    /// Protocol - Unsigned integer (2 bytes) - sll.gretype
    pub gretype: String,
    /// Link-layer address length - Unsigned integer (2 bytes) - sll.halen
    pub halen: String,
    /// Link-layer address type - Unsigned integer (2 bytes) - sll.hatype
    pub hatype: String,
    /// Interface index - Unsigned integer (4 bytes) - sll.ifindex
    pub ifindex: String,
    /// Protocol - Unsigned integer (2 bytes) - sll.ltype
    pub ltype: String,
    /// Packet type - Unsigned integer (2 bytes) - sll.pkttype
    pub pkttype: String,
    /// Source - Ethernet or other MAC address - sll.src.eth
    pub src_eth: String,
    /// Source - IPv4 address - sll.src.ipv4
    pub src_ipv4: String,
    /// Source - Byte sequence - sll.src.other
    pub src_other: String,
    /// Trailer - Byte sequence - sll.trailer
    pub trailer: String,
    /// Unused - Byte sequence - sll.unused
    pub unused: String,
}

/// SLL implementation
impl SLL {
    /// Create a new SLL layer
    pub fn new() -> SLL {
        SLL {
            etype: String::new(),
            gretype: String::new(),
            halen: String::new(),
            hatype: String::new(),
            ifindex: String::new(),
            ltype: String::new(),
            pkttype: String::new(),
            src_eth: String::new(),
            src_ipv4: String::new(),
            src_other: String::new(),
            trailer: String::new(),
            unused: String::new(),
        }
    }

    /// Update the SLL layer with a new value
    ///
    /// This function maps the Wireshark/TShark field name to the corresponding
    /// SLL layer field name in the struct.
    pub fn update(&mut self, field: &str, value: &str) {
        match field {
            "sll.etype" => self.etype = value.to_string(),
            "sll.gretype" => self.gretype = value.to_string(),
            "sll.halen" => self.halen = value.to_string(),
            "sll.hatype" => self.hatype = value.to_string(),
            "sll.ifindex" => self.ifindex = value.to_string(),
            "sll.ltype" => self.ltype = value.to_string(),
            "sll.pkttype" => self.pkttype = value.to_string(),
            "sll.src.eth" => self.src_eth = value.to_string(),
            "sll.src.ipv4" => self.src_ipv4 = value.to_string(),
            "sll.src.other" => self.src_other = value.to_string(),
            "sll.trailer" => self.trailer = value.to_string(),
            "sll.unused" => self.unused = value.to_string(),
            &_ => (),
        }
    }

    /// Get the SLL layer header values for the CSV file
    pub fn get_csv_header(delimiter: &str) -> String {
        let mut header = String::new();

        header.push_str(format!("sll.etype{}", delimiter).as_str());
        header.push_str(format!("sll.gretype{}", delimiter).as_str());
        header.push_str(format!("sll.halen{}", delimiter).as_str());
        header.push_str(format!("sll.hatype{}", delimiter).as_str());
        header.push_str(format!("sll.ifindex{}", delimiter).as_str());
        header.push_str(format!("sll.ltype{}", delimiter).as_str());
        header.push_str(format!("sll.pkttype{}", delimiter).as_str());
        header.push_str(format!("sll.src.eth{}", delimiter).as_str());
        header.push_str(format!("sll.src.ipv4{}", delimiter).as_str());
        header.push_str(format!("sll.src.other{}", delimiter).as_str());
        header.push_str(format!("sll.trailer{}", delimiter).as_str());
        header.push_str(format!("sll.unused{}", delimiter).as_str());

        header
    }

    /// Get the CSV data of the SLL layer as a string
    pub fn get_csv_data(&self, delimiter: &str) -> String {
        let mut data = String::new();

        data.push_str(format!("{}{}", self.etype, delimiter).as_str());
        data.push_str(format!("{}{}", self.gretype, delimiter).as_str());
        data.push_str(format!("{}{}", self.halen, delimiter).as_str());
        data.push_str(format!("{}{}", self.hatype, delimiter).as_str());
        data.push_str(format!("{}{}", self.ifindex, delimiter).as_str());
        data.push_str(format!("{}{}", self.ltype, delimiter).as_str());
        data.push_str(format!("{}{}", self.pkttype, delimiter).as_str());
        data.push_str(format!("{}{}", self.src_eth, delimiter).as_str());
        data.push_str(format!("{}{}", self.src_ipv4, delimiter).as_str());
        data.push_str(format!("{}{}", self.src_other, delimiter).as_str());
        data.push_str(format!("{}{}", self.trailer, delimiter).as_str());
        data.push_str(format!("{}{}", self.unused, delimiter).as_str());

        data
    }
}
