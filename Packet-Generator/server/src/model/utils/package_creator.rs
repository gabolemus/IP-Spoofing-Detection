// This file contains the helpers for creating the spoofed TCP/IP packets.

use crate::{
    api::{routes::DUMMY_MESSAGE, DESTINATION_IP_ADDRESS, STOP_INFINITE_PACKETS},
    model::networking::{get_local_ip, TCPIPv4Packet, TCPIPv6Packet},
    IPSocket, API_IP_ADDRESS,
};
use actix_web::web;
use rand::Rng;
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
    /// Wait time between packets in milliseconds.
    pub wait_time: Option<u64>,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct SingleRequestParams {
    #[serde(rename = "sourceIP")]
    pub source_ip: Option<String>,
    #[serde(rename = "destinationIP")]
    pub destination_ip: Option<String>,
    #[serde(rename = "IPVersion")]
    pub ip_version: Option<u8>,
    pub port: Option<u16>,
    pub data: Option<String>,
    #[serde(rename = "setEvilBit")]
    pub set_evil_bit: Option<bool>,
}

/// Single request parameters implementation.
impl SingleRequestParams {
    /// Creates a new instance of the SingleRequestParams struct.
    pub fn new(
        source_ip: Option<String>,
        destination_ip: Option<String>,
        ip_version: Option<u8>,
        port: Option<u16>,
        data: Option<String>,
        set_evil_bit: Option<bool>,
    ) -> Self {
        Self {
            source_ip,
            destination_ip,
            ip_version,
            port,
            data,
            set_evil_bit,
        }
    }

    /// Create a packet with default values.
    pub fn get_default_packet() -> Self {
        Self {
            source_ip: Some(API_IP_ADDRESS.to_string()),
            destination_ip: Some(DESTINATION_IP_ADDRESS.to_string()),
            ip_version: Some(4),
            port: Some(80),
            data: Some(DUMMY_MESSAGE.to_string()),
            set_evil_bit: Some(true),
        }
    }

    /// Clones the SingleRequestParams struct.
    pub fn clone(&self) -> Self {
        Self {
            source_ip: self.source_ip.clone(),
            destination_ip: self.destination_ip.clone(),
            ip_version: self.ip_version,
            port: self.port,
            data: self.data.clone(),
            set_evil_bit: self.set_evil_bit,
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
    /// Wait time between packets in milliseconds.
    #[serde(rename = "waitTime")]
    pub wait_time: Option<u64>,
    /// Wether to randomize the source IP address.
    #[serde(rename = "randomSourceIP")]
    pub random_source_ip: Option<bool>,
}

/// Multiple request parameters implementation.
impl MultipleRequestParams {
    /// Creates a new instance of the MultipleRequestParams struct.
    pub fn new(
        packet_data: Option<SingleRequestParams>,
        packet_count: Option<i32>,
        wait_time: Option<u64>,
        random_source_ip: Option<bool>,
    ) -> Self {
        Self {
            packet_data,
            packet_count,
            wait_time,
            random_source_ip,
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
            wait_time: self.wait_time,
            random_source_ip: self.random_source_ip,
        }
    }
}

/// Send a single TCP/IP packet.
pub fn send_single_packet(
    params: web::Json<SingleRequestParams>,
    spoof_packet: bool,
) -> Result<&'static str, Box<dyn Error>> {
    // Parse the arguments
    let config = parse_single_req_params(params);

    // Create the packet
    let packet = create_packet(&config, spoof_packet, false);

    // Send the packet
    send_packet(&config, &packet)
}

/// Send multiple TCP/IP packets.
pub async fn send_multiple_packets(
    params: web::Json<SingleRequestParams>,
    packet_count: i32,
    wait_time: Option<u64>,
    spoof_packet: bool,
    randomize_source_ip: bool,
) -> Result<&'static str, Box<dyn Error>> {
    // Parse the arguments
    let config = parse_multiple_req_params(params, packet_count, wait_time);

    // Send the specified number of packets in a separate async thread
    send_multiple_packets_thread(config, packet_count, spoof_packet, randomize_source_ip);

    Ok("Packets sent")
}

/// Parse the parameters for a single request.
fn parse_single_req_params(params: web::Json<SingleRequestParams>) -> Config {
    Config {
        source_ip: string_to_ipaddr(&params.source_ip, &get_local_ip("127.0.0.1")),
        destination_ip: string_to_ipaddr(&params.destination_ip, DESTINATION_IP_ADDRESS),
        ip_version: params.ip_version.unwrap_or(4),
        port: params.port.unwrap_or(80),
        packet_count: 1,
        data: generate_data(&params.data, DUMMY_MESSAGE),
        wait_time: None,
    }
}

/// Get the provided IP address or provide a default one.
fn string_to_ipaddr(ip: &Option<String>, default: &str) -> IpAddr {
    IpAddr::from_str(&ip.clone().unwrap_or(String::from(default))).unwrap()
}

/// Generate a byte vector from the provided message or the default one.
fn generate_data(message: &Option<String>, default: &str) -> Vec<u8> {
    message
        .clone()
        .unwrap_or(String::from(default))
        .as_bytes()
        .to_vec()
}

/// Parse the parameters for a multiple request.
fn parse_multiple_req_params(
    params: web::Json<SingleRequestParams>,
    packet_count: i32,
    wait_time: Option<u64>,
) -> Config {
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
            packet_count,
            data,
            wait_time,
        }
    } else {
        panic!("Invalid IP version");
    }
}

/// Create the TCP/IP packet
fn create_packet(config: &Config, spoof_packet: bool, randomize_source_ip: bool) -> Vec<u8> {
    // println!("Source IP address: {}", config.source_ip);
    // println!("Destination IP address: {}", config.destination_ip);

    if config.ip_version == 4 {
        // Create the TCP/IP v4 packet
        let packet = TCPIPv4Packet::new(
            get_ipv4_addr(if randomize_source_ip {
                get_random_ip_addr(4)
            } else {
                config.source_ip
            }),
            get_ipv4_addr(config.destination_ip),
            Some(config.data.clone()), // Payload to be sent
            // None, // Send no payload
            None,
            config.port,
            spoof_packet,
        );

        // Display the raw packet in hex
        // packet.display();

        // Return the packet
        packet.raw
    } else {
        // Create the TCP/IP v6 packet
        let packet = TCPIPv6Packet::new(
            get_ipv6_addr(if randomize_source_ip {
                get_random_ip_addr(6)
            } else {
                config.source_ip
            }),
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

/// Generate a random IP address.
fn get_random_ip_addr(version: u8) -> IpAddr {
    let mut rng = rand::thread_rng();

    // Return a random IPv4 address if the version is 4
    if version == 4 {
        IpAddr::V4(Ipv4Addr::new(
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
        ))
    } else if version == 6 {
        // Return a random IPv6 address if the version is 6
        IpAddr::V6(Ipv6Addr::new(
            rng.gen_range(0..=65535),
            rng.gen_range(0..=65535),
            rng.gen_range(0..=65535),
            rng.gen_range(0..=65535),
            rng.gen_range(0..=65535),
            rng.gen_range(0..=65535),
            rng.gen_range(0..=65535),
            rng.gen_range(0..=65535),
        ))
    } else {
        panic!("Invalid IP version");
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
fn send_multiple_packets_thread(
    config: Config,
    packet_count: i32,
    spoof_packet: bool,
    randomize_source_ip: bool,
) {
    // Create a new thread
    thread::spawn(move || {
        // If the packet count is -1, send packets indefinitely every 1 second
        if packet_count == -1 {
            let mut i = 0;

            loop {
                unsafe {
                    if STOP_INFINITE_PACKETS {
                        println!("Envío de paquetes interrumpido");
                        break;
                    }
                }

                i = i + 1;

                // Create and send the packet
                create_and_send_packet(&config, i, spoof_packet, randomize_source_ip);
            }
        } else {
            // Send the specified number of packets
            for count in 1..packet_count + 1 {
                // Create and send the packet
                create_and_send_packet(&config, count, spoof_packet, randomize_source_ip);
            }

            println!("{} paquetes han sido enviados.", packet_count);
        }
    });
}

/// Create and send packet with the provided configuration
fn create_and_send_packet(
    config: &Config,
    packet_number: i32,
    spoof_packet: bool,
    randomize_source_ip: bool,
) {
    // Create the packet
    let packet = create_packet(&config, spoof_packet, randomize_source_ip);
    // Todo: fix the previous line; also, add an option to randomize the spoofed addresses when sending multiple packets

    // Send the packet
    send_packet(&config, &packet).unwrap();

    // Print packet info
    println!(
        "Paquete #{}: {} --> {}",
        packet_number, config.source_ip, config.destination_ip
    );

    // Wait the specified time
    thread::sleep(Duration::from_millis(config.wait_time.unwrap_or(500)));
}
