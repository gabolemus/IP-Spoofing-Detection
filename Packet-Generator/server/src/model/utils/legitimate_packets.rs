/// This file contains the methods used to generate legitimate packets.
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use packet_builder::payload::PayloadData;
use packet_builder::*;
use pnet::datalink::Channel::Ethernet;
use pnet::util::MacAddr;
use pnet::{datalink, packet::tcp::TcpOption};
use pnet::{datalink::NetworkInterface as NetInt, packet::Packet};
use rand::Rng;
use std::io;

use crate::api::DESTINATION_IP_ADDRESS;

/// Send a single legitimate packet
pub fn send_single_legitimate_packet(
    destination_ip: Option<&str>,
    randomize_source_ip: bool,
) -> Option<io::Result<()>> {
    // Get the default network interface
    let default_interface = get_default_network_interface();
    let interface = datalink::interfaces()
        .into_iter()
        .filter(|iface: &NetInt| iface.name == default_interface)
        .next()
        .unwrap_or_else(|| {
            panic!(
                "Ninguna interfaz fue encontrada con el nombre {}",
                default_interface
            )
        });

    // Get the data link sender and receiver
    let (mut sender, mut _receiver) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Packet dump: tipo de canal no soportado"),
        Err(e) => panic!("Packet dump: no fue posible crear el canal. Error: {}", e),
    };

    // Get the source and destination IP addresses
    let src_ip = if randomize_source_ip {
        get_random_ip(4)
    } else {
        datalink::interfaces()
            .into_iter()
            .filter(|iface: &NetInt| iface.name == default_interface)
            .next()
            .unwrap_or_else(|| {
                panic!(
                    "Ninguna interfaz fue encontrada con el nombre {}",
                    default_interface
                )
            })
            .ips
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                panic!(
                    "Ninguna interfaz fue encontrada con el nombre {}",
                    default_interface
                )
            })
            .ip()
            .to_string()
    };
    let dest_ip = match destination_ip {
        Some(ip) => ip,
        None => DESTINATION_IP_ADDRESS,
        // None => "142.250.64.142",
    };

    // Create the packet
    let mut packet_buffer = [0u8; 1500];
    let packet = packet_builder!(
        packet_buffer,
            ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) /
        vlan({set_vlan_identifier => 10}) /
        ipv4({set_source => ipv4addr!(src_ip), set_destination => ipv4addr!(dest_ip) }) /
        tcp({set_source => get_random_tcp(), set_destination => 80, set_options => &[TcpOption::mss(1200), TcpOption::wscale(2)]}) /
        // tcp({set_source => 49859, set_destination => 80, set_options => &[TcpOption::mss(1200), TcpOption::wscale(2)]}) /
        payload({[0; 0]})
    );

    // Log the packet
    println!("Paquete único legítimo: {} --> {}", src_ip, dest_ip);

    // Send the packet
    sender.send_to(packet.packet(), None)
}

/// Get the default network interface
fn get_default_network_interface() -> String {
    let network_interfaces = NetworkInterface::show().unwrap();

    let default_network_interface = network_interfaces
        .iter()
        // Filter eth* interfaces, docker interfaces, and loopback interfaces
        .filter(|network_interface| {
            !network_interface.name.starts_with("eth")
                && !network_interface.name.starts_with("docker")
                && !network_interface.name.starts_with("lo")
        })
        // Filter IPv6 interfaces
        .filter(|network_interface| {
            // 'network_interface' has a 'addr' field that is Option<Versions>
            // Match only if the 'addr' field is Some(Versions)
            match network_interface.addr {
                Some(versions) => versions.ip().is_ipv4(),
                None => false,
            }
        })
        // Get the first interface as the default network interface
        .next();

    // If there is no default network interface, return an empty string
    match default_network_interface {
        Some(network_interface) => network_interface.name.clone(),
        None => String::new(),
    }
}

/// Get a random IP address
fn get_random_ip(ip_version: i8) -> String {
    if ip_version == 4 {
        // Generate 4 random numbers between 0 and 255
        let mut random_ip = String::new();

        for _ in 0..4 {
            let random_number = rand::thread_rng().gen_range(0..255);
            random_ip.push_str(random_number.to_string().as_str());
            random_ip.push_str(".");
        }

        random_ip.pop();

        random_ip
    } else if ip_version == 6 {
        // Generate 8 random numbers between 0 and 65535
        let mut random_ip = String::new();

        for _ in 0..8 {
            let random_number = rand::thread_rng().gen_range(0..65535);
            random_ip.push_str(random_number.to_string().as_str());
            random_ip.push_str(":");
        }

        random_ip.pop();

        random_ip
    } else {
        panic!("La versión de IP no es válida");
    }
}

/// Get a random TCP port
fn get_random_tcp() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1024..65535)
}
