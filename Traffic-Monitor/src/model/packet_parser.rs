use clap::Arg;
use slog::o;

/// File that contains the functions to parse the PCAP packets
use crate::Packet;
use std::error::Error;
use std::fs::File;
use std::io::Write;

use super::{hex_to_string, remove_new_lines, Config};

/// Parse the command line arguments and return an `Option<Config>` struct.
pub fn parse_cmd_args() -> Option<Config> {
    // Parse the command line arguments.
    let matches = clap::App::new("traffic-monitor")
        .version("1.0.0")
        .author("Gabriel Lemus <glemus.stuart@gmail.com>")
        .about("Convierte los paquetes de un archivo PCAP a un archivo CSV")
        .arg(
            Arg::with_name("pcap")
                .value_name("PCAP")
                .help("Ruta al archivo PCAP por analizar")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("csv")
                .short('c')
                .long("csv")
                .value_name("CSV")
                .help("Ruta al archivo CSV donde se guardarán los resultados. Si no se especifica, se guardará en el mismo directorio que el archivo PCAP con el mismo nombre y extensión .csv")
                .default_value(".")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("time-interval")
                .short('t')
                .long("time-interval")
                .value_name("TIME_INTERVAL")
                .help("Intervalo de tiempo en segundos para analizar nuevos paquetes en el archivo PCAP. Si no se especifica, se analizará cada 30 segundos.")
                .default_value("30")
                .takes_value(true),
        )
        .get_matches();

    // Assign the values to the config struct.
    Config::new(
        &slog::Logger::root(slog::Discard, o!()),
        matches.value_of("pcap").unwrap(),
        matches.value_of("csv"),
        matches.value_of("time-interval").unwrap().parse().ok(),
    )
}

/// Run the configuration to parse the PCAP packets to a CSV file
pub fn run(config: &Config) -> Result<&'static str, Box<dyn Error>> {
    // Create a vector to store the packets
    let mut pcap_packets: Vec<Packet> = Vec::new();

    // Create a file to write the data to
    let mut txt_file = File::create("network-traffic.txt").unwrap();
    let mut csv_file = File::create("network-traffic.csv").unwrap();

    // Creates a builder with needed tshark parameters
    let builder = rtshark::RTSharkBuilder::builder().input_path(config.pcap_path.as_str());

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
    }

    // Determine the vector with more fields out of all the packets with a closure
    let temp_packets = pcap_packets.clone();
    let all_fields = temp_packets.iter().fold(Vec::new(), |mut acc, packet| {
        if packet.fields.len() > acc.len() {
            acc = packet.fields.clone();
        }
        acc
    });

    // Set the fields for all the packets
    for packet in &mut pcap_packets {
        packet.set_fields(all_fields.clone());
    }

    // Write the CSV header to the file
    let csv_header = pcap_packets[0].get_csv_header();
    csv_file
        .write_all(format!("{}\n", csv_header).as_bytes())
        .unwrap();

    // Write the CSV data to the file
    for packet in &pcap_packets {
        let csv_data = format!("{}\n", packet.get_csv_data());
        csv_file.write_all(csv_data.as_bytes()).unwrap();
    }

    println!("{} paquetes han sido analizados", pcap_packets.len());

    Ok("")
}
