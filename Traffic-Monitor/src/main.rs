use std::fs::File;
use std::io::Write;

use ip_traffic_monitor::Packet;

fn main() {
    let mut pcap_packets: Vec<Packet> = Vec::new();

    // Todo: improve the way the Wireshark/TShark packet fields are captured to occupy less space.
    // Maybe use a HashMap instead of a struct for each layer.

    // Create a file to write the data to
    let mut txt_file = File::create("network-traffic.txt").unwrap();
    let mut csv_file = File::create("network-traffic.csv").unwrap();

    // Creates a builder with needed tshark parameters
    let builder =
        rtshark::RTSharkBuilder::builder().input_path("/home/gabo/Downloads/network-traffic.pcap");

    // Start a new tshark process
    let mut rtshark = builder
        .spawn()
        .unwrap_or_else(|e| panic!("Error starting tshark: {e}"));

    let mut i = 1;
    let mut is_first_packet = true;

    // Read the packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing tshark output: {e}");
        None
    }) {
        let mut new_packet = Packet::new();

        // If this is not the first packet, check that the last line in the file
        // is a new line. If it's not, write a new line
        if !is_first_packet {
            // Write a new line
            txt_file.write_all("\n".as_bytes()).unwrap();
        }

        if packet.layer_count() > 0 {
            println!("Packet #{} analyzed", i);
        }

        txt_file
            .write_all(format!("Packet #{}\n", i).as_bytes())
            .unwrap();
        i += 1;
        is_first_packet = false;

        for layer in packet {
            for metadata in layer {
                if metadata.name() == "tcp.payload" {
                    // Write the data to the text file
                    txt_file
                        .write_all(
                            format!(
                                "{}: {}\n",
                                metadata.name(),
                                remove_new_lines(hex_to_string(metadata.value().trim()).as_str())
                            )
                            .as_bytes(),
                        )
                        .unwrap();

                    // Add the data to the packet
                    new_packet.add_metadata(metadata.name(), metadata.value());
                } else {
                    // Write the data to the text file
                    txt_file
                        .write_all(
                            format!(
                                "{}: {}\n",
                                metadata.name(),
                                remove_new_lines(metadata.value().trim())
                            )
                            .as_bytes(),
                        )
                        .unwrap();

                    // Add the data to the packet
                    new_packet.add_metadata(metadata.name(), metadata.value());
                }
            }
        }

        pcap_packets.push(new_packet);

        // Write the header to the CSV file
        csv_file
            .write_all(format!("{}\n", pcap_packets[0].get_csv_header()).as_bytes())
            .unwrap();

        // Write the data to the CSV file
        for packet in &pcap_packets {
            csv_file
                .write_all(format!("{}\n", packet.get_csv_data()).as_bytes())
                .unwrap();
        }
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
