pub mod packet_req_res;
pub mod routes;

pub use packet_req_res::{ErrorResponse, GeneralResponse, SentPacket, SpoofingResponse};
pub use routes::{index, multiple_requests, single_request, IP_ADDRESS, PORT};
