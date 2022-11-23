pub mod packet_req_res;
pub mod routes;

pub use packet_req_res::{ErrorResponse, GeneralResponse, GenericResponse, SpoofingResponse};
pub use routes::{
    index, multiple_legitimate_requests, multiple_requests, single_legitimate_request, single_request,
    API_IP_ADDRESS, DESTINATION_IP_ADDRESS, PORT, SENDING_INFINITE_PACKETS, STOP_INFINITE_PACKETS,
};
