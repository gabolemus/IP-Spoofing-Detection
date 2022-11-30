/// File that contains the functions to parse the PCAP packets
use super::{hex_to_string, remove_new_lines, Config};
use crate::Packet;
use indicatif::ProgressBar;
use rtshark::RTSharkBuilderReady;
use slog::error;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;

/// Run the configuration to parse the PCAP packets to a CSV file
pub fn run(config: &Config) -> Result<&'static str, Box<dyn Error>> {
    // Initially, no packets have been parsed. After the first iteration, this
    // value is used to skip the packets that have already been parsed
    let mut parsed_packets: u32 = 0;
    let mut iter = 1;
    let mut write_header = true;

    loop {
        // Get runner configuration
        let (mut pcap_packets, txt_file, csv_file, builder) = match get_runner_config(&config, iter)
        {
            Ok(tup) => tup,
            Err(err) => return Err(err),
        };

        // Create a spinner to signify that the program is running
        let pb = create_spinner();

        // Parse the PCAP file
        parse_pcap_file(
            &config,
            builder,
            txt_file,
            &mut pcap_packets,
            &parsed_packets,
            &iter,
        );

        // Write the packets' data to the CSV file
        write_to_csv_file(
            pcap_packets,
            csv_file,
            &mut write_header,
            &mut parsed_packets,
        );

        // Finish the progress bar
        let finish_msg = format!("¡Análisis de paquetes #{} finalizado!", iter);
        pb.finish_with_message(finish_msg.clone());

        // Increment the iteration counter
        iter += 1;

        // Sleep for the amount of time specified in the configuration
        let sleep_time = config.time_interval.unwrap_or_else(|| 30);
        std::thread::sleep(std::time::Duration::from_secs(sleep_time));
    }
}

/// Get the runner configuration
pub fn get_runner_config(
    config: &Config,
    iteration: u32,
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
        format!("{}/network-traffic", config.out)
    };

    // Check if the text file should be created or overwritten
    let txt_file = if !config.no_text_file {
        // If it's the first iteration, create or overwrite the file
        if iteration == 1 {
            Some(File::create(format!("{}.txt", file_name))?)
        } else {
            // Open the file in append mode if it already exists
            Some(
                OpenOptions::new()
                    .append(true)
                    .open(format!("{}.txt", file_name))?,
            )
        }
    } else {
        None
    };

    // If it's the first iteration, create or overwrite the file
    let csv_file = if iteration == 1 {
        let mut file = File::create(format!("{}.csv", file_name)).unwrap();

        // Write the separator to the file
        file.write_all("sep=|\n".as_bytes())
            .unwrap_or_else(|e| panic!("Error writing to file: {e}"));

        // Return the created file
        file
    } else {
        // If the file already exists, don't overwrite it
        OpenOptions::new()
            .append(true)
            .open(format!("{}.csv", file_name))?
    };

    // Creates a builder with needed tshark parameters
    let builder = rtshark::RTSharkBuilder::builder().input_path(&config.pcap_path);

    // Return the configuration
    Ok((pcap_packets, txt_file, csv_file, builder))
}

/// Create a progress bar
pub fn create_spinner() -> ProgressBar {
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
    parsed_packets: &u32,
    iter: &u32,
) {
    // Start a new tshark process
    let mut rtshark = rtshark_builder
        .spawn()
        .unwrap_or_else(|e| panic!("Error starting tshark: {e}"));

    let mut i: u32 = 1;
    let mut is_first_packet = true;

    // Read the packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing tshark output: {e}");
        None
    }) {
        if *iter != 1 && i <= *parsed_packets {
            i += 1;
            continue;
        }

        println!("Paquete #{} analizado", i);

        let mut new_packet = Packet::new();
        new_packet.update_packet_number(i);

        if !config.no_text_file {
            if !is_first_packet {
                // If this is not the first packet, check that the last line in the file
                // is a new line. If it's not, write a new line
                write_to_text_file(&mut txt_file, "\n");
            }

            // Write the packet number to the text file
            write_to_text_file(&mut txt_file, format!("Packet #{}\n", i).as_str());
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
                            &format!(
                                "{}: {}\n",
                                metadata.name(),
                                remove_new_lines(&hex_to_string(metadata.value().trim()))
                            ),
                        );
                    }

                    // Add the data to the packet while replacing "|" with ";"
                    new_packet.add_metadata(metadata.name(), &metadata.value().replace("|", ";"));
                } else {
                    if !config.no_text_file {
                        // Write the data to the text file
                        write_to_text_file(
                            &mut txt_file,
                            &format!(
                                "{}: {}\n",
                                metadata.name(),
                                remove_new_lines(metadata.value())
                            ),
                        );
                    }

                    // Add the data to the packet while replacing the CSV delimiter "|"
                    new_packet.add_metadata(metadata.name(), &metadata.value());
                }
            }
        }

        pcap_packets.push(new_packet);
    }

    // Close the tshark process
    rtshark.kill();
}

/// Write packet data to the CSV file
fn write_to_csv_file(
    mut pcap_packets: Vec<Packet>,
    mut csv_file: File,
    write_header: &mut bool,
    parsed_packets: &mut u32,
) {
    if pcap_packets.len() > 0 {
        // Determine the vector with more fields out of all the packets with a closure
        let all_fields = pcap_packets[0].get_fields_names();

        // Set the fields for all the packets
        for packet in &mut pcap_packets {
            packet.set_fields(all_fields.clone());
        }

        // Write the CSV header to the file if the file doesn't exist and if it
        // has been written to yet
        if *write_header {
            // Write the header to the file
            let csv_header = pcap_packets[0].get_csv_header();
            csv_file
                .write_all(format!("{}\n", csv_header).as_bytes())
                .unwrap();

            // Set the write header flag to false
            *write_header = false;
        }

        let mut written_packets = 0;

        // Write the CSV data to the file
        for packet in &pcap_packets {
            written_packets += 1;

            let csv_data = format!("{}\n", packet.get_csv_data());
            csv_file.write_all(csv_data.as_bytes()).unwrap();
        }

        // Update the number of parsed packets
        *parsed_packets += written_packets;
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
