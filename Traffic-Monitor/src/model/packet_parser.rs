/// File that contains the functions to parse the PCAP packets
use crate::Packet;
use clap::Arg;
use slog::error;
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
            Arg::with_name("csv-out")
                .short('o')
                .long("csv-out")
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
        .arg(
            Arg::with_name("no-text-file")
                .short('n')
                .long("no-text-file")
                .help("Evita la creación de un archivo de texto con los datos de los paquetes. Por defecto, se creará un archivo de texto.")
        )
        .get_matches();

    // Assign the values to the config struct.
    Config::new(
        matches.value_of("pcap").unwrap(),
        matches.value_of("csv-out"),
        matches.value_of("time-interval").unwrap().parse().ok(),
        matches.is_present("no-text-file"),
    )
}

/// Run the configuration to parse the PCAP packets to a CSV file
pub fn run(config: &Config) -> Result<&'static str, Box<dyn Error>> {
    // Check that the out path exists
    if !std::path::Path::new(&config.out).exists() {
        error!(config.logger, "El archivo CSV no existe");
        std::process::exit(1);
    }

    // Create a vector to store the packets
    let mut pcap_packets: Vec<Packet> = Vec::new();

    // Check if the text file should be created or overwritten
    let mut txt_file = if !config.no_text_file {
        Some(File::create(format!("{}.txt", &config.out))?)
    } else {
        None
    };

    // Create a file to write the data to
    let mut csv_file = File::create(format!("{}.csv", &config.out))?;

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

        if !config.no_text_file {
            if !is_first_packet {
                // If this is not the first packet, check that the last line in the file
                // is a new line. If it's not, write a new line
                write_to_text_file(&mut txt_file, "\n");
            }

            // Write the packet number to the text file
            write_to_text_file(&mut txt_file, format!("Packet #{}\n", i).as_str());
        }

        if packet.layer_count() > 0 {
            println!("Packet #{} analyzed", i);
        }

        i += 1;
        is_first_packet = false;

        for layer in packet {
            for metadata in layer {
                if metadata.name() == "tcp.payload" {
                    if !config.no_text_file {
                        // Write the data to the text file
                        write_to_text_file(
                            &mut txt_file,
                            format!(
                                "{}: {}\n",
                                metadata.name(),
                                remove_new_lines(hex_to_string(metadata.value().trim()).as_str())
                            )
                            .as_str(),
                        );
                    }

                    // Add the data to the packet
                    new_packet.add_metadata(metadata.name(), metadata.value());
                } else {
                    if !config.no_text_file {
                        // Write the data to the text file
                        write_to_text_file(
                            &mut txt_file,
                            format!(
                                "{}: {}\n",
                                metadata.name(),
                                remove_new_lines(metadata.value().trim())
                            )
                            .as_str(),
                        );
                    }

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

/// Write to text file. Because the user can choose to not create said file, its
/// argument is an Option<File>
fn write_to_text_file(file: &mut Option<File>, data: &str) {
    match file {
        Some(file) => file.write_all(data.as_bytes()).unwrap(),
        None => (),
    }
}
