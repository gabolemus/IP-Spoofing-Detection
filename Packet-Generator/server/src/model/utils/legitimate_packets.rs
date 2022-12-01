/// This file contains the methods used to generate legitimate packets.
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use packet_builder::payload::PayloadData;
use packet_builder::*;
use pnet::datalink::Channel::Ethernet;
use pnet::util::MacAddr;
use pnet::{datalink, packet::tcp::TcpOption};
use pnet::{datalink::NetworkInterface as NetInt, packet::Packet};
use rand::Rng;
use std::error::Error;
use std::thread;
use std::time::Duration;

use crate::api::routes::THREAD_COUNT;
use crate::api::{DESTINATION_IP_ADDRESS, STOP_INFINITE_PACKETS};

/// Send a single legitimate packet
pub fn send_single_legitimate_packet(
    destination_ip: &String,
    randomize_source_ip: bool,
    packet_count: Option<u32>,
    thread_number: u32,
) -> Result<&'static str, Box<dyn Error>> {
    // Get the default network interface
    let default_interface = get_default_network_interface();

    // If the default interface is empty, return 'eth0' as the default interface
    let default_interface = if default_interface.is_empty() {
        "eth0".to_string()
    } else {
        default_interface
    };
    
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
    let dest_ip = if destination_ip.is_empty() {
        DESTINATION_IP_ADDRESS.to_string()
    } else {
        destination_ip.to_string()
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
    match packet_count {
        Some(count) => println!(
            "Paquete legítimo #{} - Hilo #{}: {} --> {}",
            count, thread_number, src_ip, dest_ip
        ),
        None => println!("Paquete único legítimo: {} --> {}", src_ip, dest_ip),
    }

    // Send the packet
    sender.send_to(packet.packet(), None);

    Ok("Paquete legítimo enviado")
}

/// Send multiple legitimate packets
/// This funcion calls `send_single_legitimate_packet` multiple times
pub fn send_multiple_legitimate_packets(
    destination_ip: String,
    randomize_source_ip: bool,
    packet_count: i32,
) -> Result<&'static str, Box<dyn Error>> {
    // Create a new thread
    thread::spawn(move || {
        unsafe {
            THREAD_COUNT += 1;
        }

        let mut i = 0;

        // If the packet count is -1, send packets indefinitely every 1 second
        if packet_count == -1 {
            loop {
                unsafe {
                    if STOP_INFINITE_PACKETS {
                        println!("Envío de paquetes interrumpido");
                        println!("{} paquetes han sido enviados.", i);
                        break;
                    }
                }

                i += 1;

                send_single_legitimate_packet(
                    &destination_ip,
                    randomize_source_ip,
                    Some(i),
                    // Todo: fix showing wrong thread number when creating multiple threads
                    unsafe { THREAD_COUNT },
                )
                .unwrap();

                // Wait 500 milliseconds
                thread::sleep(Duration::from_millis(500));
            }
        } else {
            // Send the specified number of packets
            for _ in 1..packet_count + 1 {
                unsafe {
                    if STOP_INFINITE_PACKETS {
                        println!(
                            "Envío de paquetes interrumpido en el hilo #{}",
                            THREAD_COUNT
                        );
                        break;
                    }
                }

                i += 1;

                send_single_legitimate_packet(
                    &destination_ip,
                    randomize_source_ip,
                    Some(i),
                    // Todo: fix showing wrong thread number when creating multiple threads
                    unsafe { THREAD_COUNT },
                )
                .unwrap();

                // Wait 500 milliseconds
                thread::sleep(Duration::from_millis(500));
            }

            println!("{} paquetes han sido enviados en el hilo #{}", i, unsafe {
                THREAD_COUNT
            });
        }

        unsafe {
            THREAD_COUNT -= 1;
        }
    });

    Ok("Hilo de envío de paquetes legítimos iniciado")
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
