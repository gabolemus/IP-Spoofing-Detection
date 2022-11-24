use ip_traffic_monitor::{parse_cmd_args, run};
use slog::error;
use std::{env, process::exit};

fn main() {
    // Enable backtraces for debugging purposes
    env::set_var("RUST_BACKTRACE", "1");

    // Todo: execute the run function infinitely
    // Todo: once the file has been written once, append the new data to it
    // instead of overwriting it

    // Parse the command line argumets into an `Option<Config>` struct
    if let Some(config) = parse_cmd_args() {
        let mut loop_count = 1;

        loop {
            if loop_count == 3 {
                break;
            }

            loop_count += 1;

            // Run the program with the given configuration
            match run(&config) {
                Ok(_) => 0,
                Err(err) => {
                    error!(config.logger, "Ocurrió un error: {}", err);
                    1
                }
            };

            // Sleep for 15 seconds
            std::thread::sleep(std::time::Duration::from_secs(5));
        }

        exit(0);
    } else {
        // Exit the program with an error code
        exit(1);
    }
}
