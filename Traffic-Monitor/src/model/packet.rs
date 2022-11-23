use crate::{Frame, HTTP, IP, SLL, TCP};

/// Struct that represents a pcap packet
#[derive(Debug)]
pub struct Packet {
    pub layers: Vec<Layer>,
    pub is_spoofed: bool,
}

/// Enum that represents the different types of layers
///
/// Not all the layers are considerd, only the ones that are needed for the
/// training of the NN model
#[derive(Debug)]
pub enum Layer {
    Frame(Frame),
    SLL(SLL),
    IP(IP),
    TCP(TCP),
    HTTP(HTTP),
}

/// Packet implementation
impl Packet {
    /// Create a new empty packet
    pub fn new() -> Self {
        let pkt_frame = Frame::new();
        let pkt_sll = SLL::new();
        let pkt_ip = IP::new();
        let pkt_tcp = TCP::new();
        let pkt_http = HTTP::new();

        Self {
            layers: vec![
                Layer::Frame(pkt_frame),
                Layer::SLL(pkt_sll),
                Layer::IP(pkt_ip),
                Layer::TCP(pkt_tcp),
                Layer::HTTP(pkt_http),
            ],
            is_spoofed: false,
        }
    }

    /// Add a new metadata value to the corresponding layer
    pub fn add_metadata(&mut self, metadata_name: &str, metadata_value: &str) {
        // Layer data mapping:
        // "frame" -> Frame
        // "sll" -> SLL
        // "ip" -> IP
        // "tcp" || "mptcp" -> TCP
        // "http" || "data" -> HTTP
        match metadata_name.split('.').next().unwrap() {
            "frame" => {
                if let Layer::Frame(frame) = &mut self.layers[0] {
                    frame.update(metadata_name, metadata_value);
                }
            }

            "sll" => {
                if let Layer::SLL(sll) = &mut self.layers[1] {
                    sll.update(metadata_name, metadata_value);
                }
            }

            "ip" => {
                if let Layer::IP(ip) = &mut self.layers[2] {
                    ip.update(metadata_name, metadata_value);
                }
            }

            "tcp" | "mptcp" => {
                if let Layer::TCP(tcp) = &mut self.layers[3] {
                    tcp.update(metadata_name, metadata_value);
                }
            }

            "http" | "data" => {
                if let Layer::HTTP(http) = &mut self.layers[4] {
                    http.update(metadata_name, metadata_value);
                }
            }

            _ => (),
        }
    }

    /// Get CSV header
    pub fn get_csv_header(&self) -> String {
        let mut header = "is_spoofed,".to_string();

        for layer in &self.layers {
            match layer {
                Layer::Frame(frame) => header.push_str(&frame.get_csv_header(",")),
                Layer::SLL(sll) => header.push_str(&sll.get_csv_header(",")),
                Layer::IP(ip) => header.push_str(&ip.get_csv_header(",")),
                Layer::TCP(tcp) => header.push_str(&tcp.get_csv_header(",")),
                Layer::HTTP(http) => header.push_str(&http.get_csv_header(",")),
            }
        }

        header
    }

    /// Get CSV data
    pub fn get_csv_data(&self) -> String {
        let mut data = format!("{},", self.is_spoofed);

        for layer in &self.layers {
            match layer {
                Layer::Frame(frame) => data.push_str(&frame.get_csv_data(",")),
                Layer::SLL(sll) => data.push_str(&sll.get_csv_data(",")),
                Layer::IP(ip) => data.push_str(&ip.get_csv_data(",")),
                Layer::TCP(tcp) => data.push_str(&tcp.get_csv_data(",")),
                Layer::HTTP(http) => data.push_str(&http.get_csv_data(",")),
            }
        }

        data
    }    
}
