// This file contains the helpers for creating the spoofed TCP/IP packets.

use crate::{
    api::{routes::DUMMY_MESSAGE, DESTINATION_IP_ADDRESS, STOP_INFINITE_PACKETS},
    model::networking::{TCPIPv4Packet, TCPIPv6Packet},
    IPSocket, SOURCE_IP_ADDRESS,
};
use actix_web::web;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    thread,
    time::Duration,
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
    /// Packet count.
    pub packet_count: i32,
    /// The data to be sent.
    pub data: Vec<u8>,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
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

/// Single request parameters implementation.
impl SingleRequestParams {
    /// Creates a new instance of the SingleRequestParams struct.
    pub fn new(
        is_spoofed: Option<bool>,
        source_ip: Option<String>,
        destination_ip: Option<String>,
        ip_version: Option<u8>,
        port: Option<u16>,
        data: Option<String>,
    ) -> Self {
        Self {
            is_spoofed,
            source_ip,
            destination_ip,
            ip_version,
            port,
            data,
        }
    }

    /// Create a packet with default values.
    pub fn get_default_packet() -> Self {
        Self {
            is_spoofed: Some(false),
            source_ip: Some(SOURCE_IP_ADDRESS.to_string()),
            destination_ip: Some(DESTINATION_IP_ADDRESS.to_string()),
            ip_version: Some(4),
            port: Some(80),
            data: Some(DUMMY_MESSAGE.to_string()),
        }
    }

    /// Clones the SingleRequestParams struct.
    pub fn clone(&self) -> Self {
        Self {
            is_spoofed: self.is_spoofed,
            source_ip: self.source_ip.clone(),
            destination_ip: self.destination_ip.clone(),
            ip_version: self.ip_version,
            port: self.port,
            data: self.data.clone(),
        }
    }
}

#[derive(Serialize, Debug, Deserialize)]
pub struct MultipleRequestParams {
    #[serde(rename = "packetData")]
    pub packet_data: Option<SingleRequestParams>,
    // The packet count will determine the number of packets to send
    // If it's -1, then send packets until a post request is made to /stop
    #[serde(rename = "packetCount")]
    pub packet_count: Option<i32>,
}

/// Multiple request parameters implementation.
impl MultipleRequestParams {
    /// Creates a new instance of the MultipleRequestParams struct.
    pub fn new(packet_data: Option<SingleRequestParams>, packet_count: Option<i32>) -> Self {
        Self {
            packet_data,
            packet_count,
        }
    }

    /// Clones the MultipleRequestParams struct.
    pub fn clone(&self) -> Self {
        Self {
            packet_data: match &self.packet_data {
                Some(packet_data) => Some(packet_data.clone()),
                None => None,
            },
            packet_count: self.packet_count,
        }
    }
}

/// Send a single TCP/IP packet.
pub fn send_single_packet(
    params: web::Json<SingleRequestParams>,
) -> Result<&'static str, Box<dyn Error>> {
    // Parse the arguments
    let config = parse_single_req_params(params);

    // Create the packet
    let packet = create_packet(&config);

    // Send the packet
    send_packet(&config, &packet)
}

/// Send multiple TCP/IP packets.
pub async fn send_multiple_packets(
    params: web::Json<SingleRequestParams>,
    packet_count: i32,
) -> Result<&'static str, Box<dyn Error>> {
    // Parse the arguments
    let config = parse_multiple_req_params(params);

    // Send the specified number of packets in a separate async thread
    send_multiple_packets_thread(config, packet_count);

    Ok("Packets sent")
}

/// Parse the parameters for a single request.
fn parse_single_req_params(params: web::Json<SingleRequestParams>) -> Config {
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
            packet_count: 1,
            data,
        }
    } else {
        panic!("Invalid IP version");
    }
}

/// Parse the parameters for a multiple request.
fn parse_multiple_req_params(params: web::Json<SingleRequestParams>) -> Config {
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
            packet_count: 1,
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

/// Send multiple TCP/IP packets in a separate async thread
fn send_multiple_packets_thread(config: Config, packet_count: i32) {
    // Create a new thread
    thread::spawn(move || {
        let mut i = 0;

        // If the packet count is -1, send packets indefinitely every 1 second
        if packet_count == -1 {
            loop {
                unsafe {
                    if STOP_INFINITE_PACKETS {
                        break;
                    }
                }

                i = i + 1;

                // Create the packet
                let packet = create_packet(&config);

                // Send the packet
                send_packet(&config, &packet).unwrap();
                println!(
                    "Paquete #{}: {} --> {}",
                    i, config.source_ip, config.destination_ip
                );

                // Wait 1 second
                thread::sleep(Duration::from_secs(1));
            }
        } else {
            // Send the specified number of packets
            for _ in 0..packet_count {
                i = i + 1;

                // Create the packet
                let packet = create_packet(&config);

                // Send the packet
                send_packet(&config, &packet).unwrap();
                println!(
                    "Paquete #{}: {} --> {}",
                    i, config.source_ip, config.destination_ip
                );

                // Wait 1 second
                thread::sleep(Duration::from_secs(1));
            }

            println!("{} paquetes han sido enviados.", i);
        }
    });
}
