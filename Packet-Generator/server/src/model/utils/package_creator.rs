// This file contains the helpers for creating the spoofed TCP/IP packets.

use crate::{
    model::networking::{TCPIPv4Packet, TCPIPv6Packet},
    IPSocket,
};
use actix_web::web;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
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

#[derive(Serialize, Debug, Deserialize)]
pub struct SingleRequestParams {
    #[serde(rename = "isSpoofed")]
    pub is_spoofed: Option<bool>,
    #[serde(rename = "sourceIP")]
    pub source_ip: Option<String>,
    #[serde(rename = "destinationIP")]
    pub destination_ip: Option<String>,
    #[serde(rename = "IPVersion")]
    pub ip_version: Option<u8>,
    pub port: Option<u16>,
    pub data: Option<String>,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct MultipleRequestParams {
    #[serde(rename = "isSpoofed")]
    pub is_spoofed: Option<bool>,
    #[serde(rename = "sourceIP")]
    pub source_ip: Option<String>,
    #[serde(rename = "destinationIP")]
    pub destination_ip: Option<String>,
    #[serde(rename = "IPVersion")]
    pub ip_version: Option<u8>,
    pub port: Option<u16>,
    pub data: Option<String>,
    // The packet count will determine the number of packets to send
    // If it's -1, then send packets until a post request is made to /stop
    #[serde(rename = "packetCount")]
    pub packet_count: Option<u32>,
}

/// Send a single TCP/IP packet.
pub fn send_single_packet(
    params: web::Json<SingleRequestParams>,
) -> Result<&'static str, Box<dyn Error>> {
    // Parse the arguments
    let config = parse_args(params);

    // Create the packet
    let packet = create_packet(&config);

    // Send the packet
    send_packet(&config, &packet)
}

/// Parse the program arguments.
fn parse_args(params: web::Json<SingleRequestParams>) -> Config {
    // Default values
    let source_ip = String::from("127.0.0.1");
    let destination_ip = String::from("8.8.8.8");
    let ip_version = params.ip_version.unwrap_or(4);
    let port = params.port.unwrap_or(80);
    let data_msg = params
        .data
        .clone()
        .unwrap_or(String::from("Este es un paquete TCP/IP spoofeado!"));
    let data = data_msg.as_bytes().to_vec();

    if ip_version == 4 || ip_version == 6 {
        Config {
            source_ip: IpAddr::from_str(&params.source_ip.clone().unwrap_or(source_ip)).unwrap(),
            destination_ip: IpAddr::from_str(
                &params.destination_ip.clone().unwrap_or(destination_ip),
            )
            .unwrap(),
            ip_version,
            port,
            data,
        }
    } else {
        panic!("Invalid IP version");
    }
}

/// Create the TCP/IP packet
fn create_packet(config: &Config) -> Vec<u8> {
    // println!("Source IP address: {}", config.source_ip);
    // println!("Destination IP address: {}", config.destination_ip);

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
        // packet.display();

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
        // packet.display();

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
