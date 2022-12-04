// This file contains the configuration struct used by the program.

use clap::{App, Arg};
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
        let out = match out {
            Some(path) => path.to_string(),
            None => ".".to_string(),
        };

        // Return the configuration
        Some(Self {
            logger,
            pcap_path: pcap_path.to_string(),
            out,
            time_interval,
            no_text_file,
        })
    }
}

/// Parse the command line arguments and return an `Option<Config>` struct.
pub fn parse_cmd_args() -> Option<Config> {
    // Parse the command line arguments.
    let matches = App::new("traffic-monitor")
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
                .value_name("NO_TEXT_FILE")
                .help("Evita la creación de un archivo de texto con los datos de los paquetes. Por defecto, se creará un archivo de texto.")
                .default_value("false")
                .takes_value(true),
        )
        .get_matches();

    // Assign the values to the config struct.
    Config::new(
        matches.value_of("pcap").unwrap(),
        matches.value_of("csv-out"),
        matches.value_of("time-interval").unwrap().parse().ok(),
        matches
            .value_of("no-text-file")
            .unwrap()
            .parse()
            .ok()
            .unwrap(),
    )
}
