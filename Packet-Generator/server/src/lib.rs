pub mod api;
pub mod model;

pub use api::{index, multiple_requests, single_request, API_IP_ADDRESS, PORT};
pub use model::{send_single_packet, IPSocket};
