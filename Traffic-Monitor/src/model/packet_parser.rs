/// File that contains the functions to parse the PCAP packets
use super::{hex_to_string, remove_new_lines, Config};
use crate::Packet;
use indicatif::ProgressBar;
use rtshark::RTSharkBuilderReady;
use slog::error;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Run the configuration to parse the PCAP packets to a CSV file
pub fn run(config: &Config) -> Result<&'static str, Box<dyn Error>> {
    // Get runner configuration
    let (mut pcap_packets, txt_file, csv_file, builder) = match get_runner_config(&config) {
        Ok(tup) => tup,
        Err(err) => return Err(err),
    };

    // If the /traffic-analisis/ directory doesn't exist, create it
    if !Path::new("traffic-analisis").exists() {
        std::fs::create_dir("traffic-analisis")?;
    }

    // Print the working directory
    // AKA: execute the `pwd` command
    println!(
        "Working directory: {}",
        std::env::current_dir().unwrap().display()
    );

    // Print all the files in the local directory
    // AKA: execute the `ls -l` command
    for entry in std::fs::read_dir(".")? {
        let entry = entry?;
        let path = entry.path();
        println!("{:?}", path);
    }

    // Create a progress bar withouth a known end
    let pb = create_progress_bar();

    // Parse the PCAP file
    parse_pcap_file(&config, builder, txt_file, &mut pcap_packets);

    println!("Packets count: {}", pcap_packets.len());

    // Write the packets' data to the CSV file
    write_to_csv_file(pcap_packets, csv_file);

    // Finish the progress bar
    pb.finish_with_message("¡Análisis de paquetes finalizado!");

    // Return the result
    Ok("Análisis finalizado")
}

/// Get the runner configuration
pub fn get_runner_config(
    config: &Config,
) -> Result<(Vec<Packet>, Option<File>, File, RTSharkBuilderReady), Box<dyn Error>> {
    // Check that the out path exists
    if !std::path::Path::new(&config.out).exists() {
        if !config.no_text_file {
            error!(
                config.logger,
                "La ruta para guardar los archivos no existe: {}", config.out
            );
        } else {
            error!(
                config.logger,
                "La ruta para guardar el archivo CSV no existe: {}", config.out
            );
        }

        std::process::exit(1);
    }

    // Create a vector to store the packets
    let pcap_packets: Vec<Packet> = Vec::new();

    // Get the files names
    let file_name = if config.out == "." {
        "network-traffic".to_string()
    } else {
        config.out.clone()
    };

    // Check if the text file should be created or overwritten
    let txt_file = if !config.no_text_file {
        Some(File::create(format!(
            "./traffic-analysis/{}.txt",
            file_name
        ))?)
    } else {
        None
    };

    // Create a file to write the data to
    let csv_file = File::create(format!("./traffic-analysis/{}.csv", file_name))?;

    // Creates a builder with needed tshark parameters
    let builder = rtshark::RTSharkBuilder::builder().input_path(config.pcap_path.as_str());

    // Return the configuration
    Ok((pcap_packets, txt_file, csv_file, builder))
}

/// Create a progress bar
pub fn create_progress_bar() -> ProgressBar {
    // Create a progress bar
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(100);
    pb.set_message("Analizando los paquetes...");
    pb.set_style(
        indicatif::ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.green} {msg}"),
    );

    // Return the progress bar
    pb
}

/// Parse the PCAP file
fn parse_pcap_file(
    config: &Config,
    rtshark_builder: RTSharkBuilderReady,
    mut txt_file: Option<File>,
    pcap_packets: &mut Vec<Packet>,
) {
    // Start a new tshark process
    let mut rtshark = rtshark_builder
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

        // if packet.layer_count() > 0 {
        //     println!("Packet #{} analyzed", i);
        // }

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
}

/// Write packet data to the CSV file
fn write_to_csv_file(mut pcap_packets: Vec<Packet>, mut csv_file: File) {
    if pcap_packets.len() > 0 {
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
    }
}

/// Write to text file. Because the user can choose to not create said file, its
/// argument is an Option<File>
fn write_to_text_file(file: &mut Option<File>, data: &str) {
    match file {
        Some(file) => file.write_all(data.as_bytes()).unwrap(),
        None => (),
    }
}

// /// Write packet metadata to the text file
// fn write_metadata(config: &Config, mut txt_file: Option<File>, metadata: &Metadata, value: &str) {
//     if !config.no_text_file {
//         // Write the data to the text file
//         write_to_text_file(
//             &mut txt_file,
//             format!("{}: {}\n", metadata.name(), value).as_str(),
//         );
//     }
// }
