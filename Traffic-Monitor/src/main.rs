use ip_traffic_monitor::{parse_cmd_args, run};
use slog::error;
use std::{env, process::exit};

fn main() {
    // Enable backtraces for debugging purposes
    env::set_var("RUST_BACKTRACE", "1");

    // Todos:
    // - Rewrite the csv file in case a new packet has extra fields
    // - Read only the last part of the pcap file after the first run
    // - Make sure that the header is printed always
    // - Specify the fields to be printed in the csv file and ignore the rest

    // Parse the command line argumets into an `Option<Config>` struct
    if let Some(config) = parse_cmd_args() {
        // Run the program with the given configuration
        match run(&config) {
            Ok(_) => 0,
            Err(err) => {
                error!(config.logger, "Ocurrió un error: {}", err);
                1
            }
        };
    } else {
        // Exit the program with an error code
        exit(1);
    }
}
