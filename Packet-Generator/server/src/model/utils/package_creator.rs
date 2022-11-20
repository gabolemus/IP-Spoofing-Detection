// This file contains the helpers for creating the spoofed TCP/IP packets.

use super::arguments_manager::{get_addresses, get_destination_ip};
use crate::{IPSocket, model::networking::{TCPIPv4Packet, TCPIPv6Packet}};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Program arguments.
///
/// This structure is used to store the program arguments.
/// If no arguments are provided, the user will be prompted to enter them.
pub struct Config {
    /// Source IP address.
    pub source_ip: IpAddr,
    /// Destination IP address.
    pub destination_ip: IpAddr,
    /// IP version.
    pub ip_version: u8,
    /// Port the packet will be sent to.
    pub port: u16,
    /// The data to be sent.
    pub data: Vec<u8>,
}

/// Run the configuration to create and send the TCP/IP packet.
pub fn run(args: Vec<String>) -> Result<&'static str, Box<dyn Error>> {
    // Parse the arguments
    let config = parse_args(args);

    // Create the packet
    let packet = create_packet(&config);

    // Send the packet
    send_packet(&config, &packet)
}

/// Parse the program arguments.
fn parse_args(args: Vec<String>) -> Config {
    // Default values
    let source_ip = String::new();
    let destination_ip = String::new();
    let ip_version = 4;
    let port = 80;
    let data = "Este es un paquete TCP/IP spoofeado y enviado desde Rust!"
        .as_bytes()
        .to_vec();

    // Check that at least the source and destination IP addresses were provided
    if args.len() < 3 {
        get_addresses(source_ip, destination_ip, None, port, data)
    } else {
        // Check if the IP address provided are valid
        if args[1].parse::<IpAddr>().is_ok() && args[2].parse::<IpAddr>().is_ok() {
            get_destination_ip(args.clone(), args[1].clone(), destination_ip, port, data)
        } else {
            get_addresses(source_ip, destination_ip, Some(ip_version), port, data)
        }
    }
}

/// Create the TCP/IP packet
fn create_packet(config: &Config) -> Vec<u8> {
    // Print the addresses
    println!("Source IP address: {}", config.source_ip);
    println!("Destination IP address: {}", config.destination_ip);

    if config.ip_version == 4 {
        // Create the TCP/IP v4 packet
        let packet = TCPIPv4Packet::new(
            get_ipv4_addr(config.source_ip),
            get_ipv4_addr(config.destination_ip),
            Some(config.data.clone()), // Payload to be sent
            // None, // Send no payload
            None,
            config.port,
        );

        // Display the raw packet in hex
        packet.display();

        // Return the packet
        packet.raw
    } else {
        // Create the TCP/IP v6 packet
        let packet = TCPIPv6Packet::new(
            get_ipv6_addr(config.source_ip),
            get_ipv6_addr(config.destination_ip),
            Some(config.data.clone()), // Payload to be sent
            // None, // Send no payload
            None,
            config.port,
        );

        // Display the raw packet in hex
        packet.display();

        // Return the packet
        packet.raw
    }
}

/// Get Ipv4Addr from IpAddr
fn get_ipv4_addr(ip: IpAddr) -> Ipv4Addr {
    let str_addr = ip.to_string();
    str_addr.parse().unwrap()
}

/// Get Ipv6Addr from IpAddr
fn get_ipv6_addr(ip: IpAddr) -> Ipv6Addr {
    let str_addr = ip.to_string();
    str_addr.parse().unwrap()
}

/// Send the TCP/IP packet
fn send_packet(config: &Config, packet: &Vec<u8>) -> Result<&'static str, Box<dyn Error>> {
    let socket: Socket;

    // Attempt to create the raw socket
    if config.ip_version == 4 {
        socket = IPSocket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    } else {
        socket = IPSocket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))?;
    }

    // Send the packet
    IPSocket::send_to(&socket, &packet, config.destination_ip, config.port)?;

    // Packet sent successfully
    Ok("\nEl paquete ha sido enviado exitosamente.")
}
