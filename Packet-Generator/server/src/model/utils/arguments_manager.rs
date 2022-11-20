// This file contains the helpers for managing the arguments provided by the user.

use super::package_creator::Config;
use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Ask the user for the source and destination IP addresses
pub fn get_addresses(
    mut source_ip: String,
    mut destination_ip: String,
    ip_version: Option<u8>,
    port: u16,
    data: Vec<u8>,
) -> Config {
    // Prompt the user to enter the source IP address
    source_ip = get_ip_address(source_ip, "origen", None);

    // Determine the IP version of the source IP address
    let ip_version = if ip_version.is_none() {
        if source_ip.parse::<Ipv4Addr>().is_ok() {
            4
        } else {
            6
        }
    } else {
        ip_version.unwrap()
    };

    // Prompt the user to enter the destination IP address
    destination_ip = get_ip_address(destination_ip, "destino", Some(ip_version));

    // Return the configuration
    Config {
        source_ip: source_ip.parse().unwrap(),
        destination_ip: destination_ip.parse().unwrap(),
        ip_version,
        port,
        data,
    }
}

/// Get a valid destination IP address from the standard input
pub fn get_destination_ip(
    args: Vec<String>,
    source_ip: String,
    mut destination_ip: String,
    port: u16,
    data: Vec<u8>,
) -> Config {
    let ip_version: u8;

    // Check that both IP addresses are of the same version
    if args[1].parse::<Ipv4Addr>().is_ok() && args[2].parse::<Ipv4Addr>().is_ok() {
        ip_version = 4; // Both IP addresses are IPv4
    } else if args[1].parse::<Ipv6Addr>().is_ok() && args[2].parse::<Ipv6Addr>().is_ok() {
        ip_version = 6; // Both IP addresses are IPv6
    } else {
        // Ask for the destination IP address to be the same version as the source IP address
        if source_ip.parse::<Ipv4Addr>().is_ok() {
            // The source IP address is IPv4
            ip_version = 4;
            destination_ip = get_ip_address(destination_ip, "destino", Some(4));
        } else {
            // The source IP address is IPv6
            ip_version = 6;
            destination_ip = get_ip_address(destination_ip, "destino", Some(6));
        }
    }

    // Return the configuration
    Config {
        source_ip: args[1].parse().unwrap(),
        destination_ip: destination_ip.parse().unwrap_or(args[2].parse().unwrap()),
        ip_version,
        port,
        data,
    }
}

/// Get IP address from the standard input
fn get_ip_address(mut ip: String, address_type: &str, version: Option<u8>) -> String {
    let mut invalid_ip = true;

    print!("Por favor, ingresa la dirección IP {}: ", address_type);
    io::stdout().flush().unwrap();

    while invalid_ip {
        ip = String::new();
        io::stdin().read_line(&mut ip).unwrap();
        ip = ip.trim().to_string();

        match version {
            Some(4) => {
                // Check if the string can be parsed as an IPv4 address
                if ip.parse::<Ipv4Addr>().is_ok() {
                    invalid_ip = false;
                } else {
                    show_invalid_ip_msg(address_type, Some(4));
                }
            }
            Some(6) => {
                // Check if the string can be parsed as an IPv6 address
                if ip.parse::<Ipv6Addr>().is_ok() {
                    invalid_ip = false;
                } else {
                    show_invalid_ip_msg(address_type, Some(6));
                }
            }
            _ => {
                // Check if the string can be parsed as an IPv4 or IPv6 address
                if ip.parse::<IpAddr>().is_ok() {
                    invalid_ip = false;
                } else {
                    show_invalid_ip_msg(address_type, None);
                }
            }
        }
    }

    ip
}

/// Display a message indicating that the IP address is invalid
fn show_invalid_ip_msg(address_type: &str, version: Option<u8>) {
    match version {
        Some(x) => print!(
            "\nLa dirección IP ingresada no es válida. Por favor, ingresa una dirección IPv{} de {}: ",
            x, address_type
        ),
        None => print!(
            "\nLa dirección IP ingresada no es válida. Por favor, ingresa una dirección IP de {}: ",
            address_type
        ),
    }
    io::stdout().flush().unwrap();
}
