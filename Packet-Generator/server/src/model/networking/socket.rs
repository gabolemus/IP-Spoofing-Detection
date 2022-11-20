// This file contains the implementation of the IP socket structure.

use socket2::{Domain, Protocol, Socket, Type};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

pub enum SocketError {
    SocketCreationError,
    SetHeaderError,
}

/// The IP socket structure.
///
/// This structure is used to create and manage IP sockets.
pub struct IPSocket {}

// IP socket methods
impl IPSocket {
    // Create a new IP socket.
    pub fn new(
        domain: Domain,
        type_: Type,
        protocol: Option<Protocol>,
    ) -> Result<Socket, SocketError> {
        let socket = Socket::new(domain, type_, protocol); // Attempt to create the socket

        // Check if the socket was created successfully
        match socket {
            Ok(socket) => {
                // Attempt to set the header
                match socket.set_header_included(true) {
                    Ok(_) => Ok(socket),
                    Err(_) => Err(SocketError::SetHeaderError),
                }
            }
            Err(_) => Err(SocketError::SocketCreationError),
        }
    }

    // Send data to the socket.
    pub fn send_to(
        socket: &Socket,
        data: &[u8],
        address: IpAddr,
        port: u16,
    ) -> Result<usize, std::io::Error> {
        socket.send_to(data, &SocketAddr::new(address, port).into())
    }
}

// Implementation of the debug trait for the SocketError enum
impl fmt::Debug for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketError::SocketCreationError => write!(f, "SocketCreationError"),
            SocketError::SetHeaderError => write!(f, "SetHeaderError"),
        }
    }
}

// Implementation of the display trait for the SocketError enum
impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketError::SocketCreationError => write!(f, "SocketCreationError"),
            SocketError::SetHeaderError => write!(f, "SetHeaderError"),
        }
    }
}

// Implementation of the error trait for the SocketError enum
impl std::error::Error for SocketError {}
