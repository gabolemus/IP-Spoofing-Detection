pub mod packet_req_res;
pub mod routes;

pub use packet_req_res::{ErrorResponse, GeneralResponse, GenericResponse, SpoofingResponse};
pub use routes::{
    index, multiple_requests, single_request, DESTINATION_IP_ADDRESS, PORT, API_IP_ADDRESS,
    STOP_INFINITE_PACKETS,
};
