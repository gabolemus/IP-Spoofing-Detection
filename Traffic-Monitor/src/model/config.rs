// This file contains the configuration struct used by the program.

use slog::{error, o};

/// Configuration passed to the `run` function.
pub struct Config {
    /// Logger
    pub logger: slog::Logger,
    /// Path to the PCAP file
    pub pcap_path: String,
    /// Path to the CSV file
    /// If `None`, the CSV file will be saved in the current directory.
    pub csv_path: Option<String>,
    /// Time interval in seconds to check for new packets
    /// If `None`, the program will check for new packets every 30 seconds.
    pub time_interval: Option<u64>,
    /// Prevent the creation of a text file with the data of the packets.
    /// By default, the file will be created.
    pub no_text_file: bool,
}

// Config implementations
impl Config {
    pub fn new(logger: &slog::Logger, pcap_path: &str, csv_path: Option<&str>, time_interval: Option<u64>, no_text_file: bool) -> Option<Self> {
        if pcap_path.is_empty() {
            error!(logger, "El path al archivo PCAP no puede estar vacío");
            return None;
        }
        
        // Create a new logger
        let logger = logger.new(o!("module" => "config"));

        // Check if the PCAP file exists
        if !std::path::Path::new(pcap_path).exists() {
            error!(logger, "El archivo PCAP no existe");
            std::process::exit(1);
        }

        // If the CSV file already exists, create a new one and append a number to the end
        let mut csv_path = csv_path.map(|path| path.to_string());
        if let Some(path) = &csv_path {
            if std::path::Path::new(path).exists() {
                let mut i = 1;
                loop {
                    let new_path = format!("{}-{}", path, i);
                    if !std::path::Path::new(&new_path).exists() {
                        csv_path = Some(new_path);
                        break;
                    }
                    i += 1;
                }
            }
        }

        Some(Self {
            logger,
            pcap_path: pcap_path.to_string(),
            csv_path,
            time_interval,
            no_text_file,
        })
    }
}
