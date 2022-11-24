// This file contains the configuration struct used by the program.

use slog::{error, o, Drain, Logger};
use std::sync::Mutex;

/// Configuration passed to the `run` function.
pub struct Config {
    /// Logger
    pub logger: slog::Logger,
    /// Path to the PCAP file
    pub pcap_path: String,
    /// Path to the CSV file
    /// If `None`, the CSV file will be saved in the current directory.
    pub out: String,
    /// Time interval in seconds to check for new packets
    /// If `None`, the program will check for new packets every 30 seconds.
    pub time_interval: Option<u64>,
    /// Prevent the creation of a text file with the data of the packets.
    /// By default, the file will be created.
    pub no_text_file: bool,
}

// Config implementations
impl Config {
    pub fn new(
        pcap_path: &str,
        out: Option<&str>,
        time_interval: Option<u64>,
        no_text_file: bool,
    ) -> Option<Self> {
        // Create the logger
        let decorator = slog_term::TermDecorator::new().build();
        let drain = Mutex::new(slog_term::FullFormat::new(decorator).build()).fuse();
        let logger = Logger::root(drain, o!());

        // Check if the PCAP file was provided
        if pcap_path.is_empty() {
            error!(logger, "El path al archivo PCAP no puede estar vacío");
            return None;
        }

        // Check if the PCAP file exists
        if !std::path::Path::new(pcap_path).exists() {
            error!(logger, "El archivo PCAP no existe");
            std::process::exit(1);
        }

        // If the CSV file already exists, create a new one and append a number to the end
        let csv_path = match out {
            Some(path) => path.to_string(),
            None => ".".to_string(),
        };

        // Return the configuration
        Some(Self {
            logger,
            pcap_path: pcap_path.to_string(),
            out: csv_path,
            time_interval,
            no_text_file,
        })
    }
}
