/// Struct that represents the HTTP layer
///
/// Referenced from the [Wireshark documentation](https://www.wireshark.org/docs/dfref/h/http.html)
#[derive(Debug)]
pub struct HTTP {
    /// Accept - Character string - http.accept
    pub accept: String,
    /// Accept Encoding - Character string - http.accept_encoding
    pub accept_encoding: String,
    /// Accept-Language - Character string - http.accept_language
    pub accept_language: String,
    /// Credentials - Character string - http.authbasic
    pub authbasic: String,
    /// Citrix AG Auth - Boolean - http.authcitrix
    pub authcitrix: String,
    /// Citrix AG Domain - Character string - http.authcitrix.domain
    pub authcitrix_domain: String,
    /// Citrix AG Password - Character string - http.authcitrix.password
    pub authcitrix_password: String,
    /// Citrix AG Session ID - Character string - http.authcitrix.session
    pub authcitrix_session: String,
    /// Citrix AG Username - Character string - http.authcitrix.user
    pub authcitrix_user: String,
    /// Authorization - Character string - http.authorization
    pub authorization: String,
    /// Illegal characters found in header name - Label - http.bad_header_name
    pub bad_header_name: String,
    /// Cache-Control - Character string - http.cache_control
    pub cache_control: String,
    /// Formatted text - Label - http.chat
    pub chat: String,
    /// Chunk boundary - Byte sequence - http.chunk_boundary
    pub chunk_boundary: String,
    /// Chunk data - Byte sequence - http.chunk_data
    pub chunk_data: String,
    /// Chunk size - Unsigned integer (4 bytes) - http.chunk_size
    pub chunk_size: String,
    /// Expert Info - Label - http.chunkd_and_length
    pub chunkd_and_length: String,
    /// trailer-part - Character string - http.chunked_trailer_part
    pub chunked_trailer_part: String,
    /// Connection - Character string - http.connection
    pub connection: String,
    /// Content-Encoding - Character string - http.content_encoding
    pub content_encoding: String,
    /// Content length - Unsigned integer (8 bytes) - http.content_length
    pub content_length: String,
    /// Content-Length - Character string - http.content_length_header
    pub content_length_header: String,
    /// Content-Type - Character string - http.content_type
    pub content_type: String,
    /// Cookie - Character string - http.cookie
    pub cookie: String,
    /// Cookie pair - Character string - http.cookie_pair
    pub cookie_pair: String,
    /// Date - Character string - http.date
    pub date: String,
    /// Decompression disabled - Label - http.decompression_disabled
    pub decompression_disabled: String,
    /// Decompression failed - Label - http.decompression_failed
    pub decompression_failed: String,
    /// File Data - Character string - http.file_data
    pub file_data: String,
    /// Host - Character string - http.host
    pub host: String,
    /// HTTP2-Settings - Character string - http.http2_settings
    pub http2_settings: String,
    /// HTTP2 Settings URI - Byte sequence - http.http2_settings_uri
    pub http2_settings_uri: String,
    /// Last-Modified - Character string - http.last_modified
    pub last_modified: String,
    /// Leading CRLF previous message in the stream may have extra CRLF - Label - http.leading_crlf
    pub leading_crlf: String,
    /// Location - Character string - http.location
    pub location: String,
    /// Next request in frame - Frame number - http.next_request_in
    pub next_request_in: String,
    /// Next response in frame - Frame number - http.next_response_in
    pub next_response_in: String,
    /// Notification - Boolean - http.notification
    pub notification: String,
    /// Path segment - Character string - http.path_segment
    pub path_segment: String,
    /// Path sub segment - Character string - http.path_sub_segment
    pub path_sub_segment: String,
    /// Prev request in frame - Frame number - http.prev_request_in
    pub prev_request_in: String,
    /// Prev response in frame - Frame number - http.prev_response_in
    pub prev_response_in: String,
    /// Proxy-Authenticate - Character string - http.proxy_authenticate
    pub proxy_authenticate: String,
    /// Proxy-Authorization - Character string - http.proxy_authorization
    pub proxy_authorization: String,
    /// Proxy-Connect-Hostname - Character string - http.proxy_connect_host
    pub proxy_connect_host: String,
    /// Proxy-Connect-Port - Unsigned integer (2 bytes) - http.proxy_connect_port
    pub proxy_connect_port: String,
    /// Referer - Character string - http.referer
    pub referer: String,
    /// Request - Boolean - http.request
    pub request: String,
    /// Full request URI - Character string - http.request.full_uri
    pub request_full_uri: String,
    /// Request line - Character string - http.request.line
    pub request_line: String,
    /// Request Method - Character string - http.request.method
    pub request_method: String,
    /// Request URI - Character string - http.request.uri
    pub request_uri: String,
    /// Request URI Path - Character string - http.request.uri.path
    pub request_uri_path: String,
    /// Request URI Query - Character string - http.request.uri.query
    pub request_uri_query: String,
    /// Request URI Query Parameter - Character string - http.request.uri.query.parameter
    pub request_uri_query_parameter: String,
    /// Request Version - Character string - http.request.version
    pub request_version: String,
    /// Request in frame - Frame number - http.request_in
    pub request_in: String,
    /// Request number - Unsigned integer (4 bytes) - http.request_number
    pub request_number: String,
    /// Response - Boolean - http.response
    pub response: String,
    /// Status Code - Unsigned integer (2 bytes) - http.response.code
    pub response_code: String,
    /// Status Code Description - Character string - http.response.code.desc
    pub response_code_desc: String,
    /// Response line - Character string - http.response.line
    pub response_line: String,
    /// Response Phrase - Character string - http.response.phrase
    pub response_phrase: String,
    /// Response Version - Character string - http.response.version
    pub response_version: String,
    /// Request URI - Character string - http.response_for.uri
    pub response_for_uri: String,
    /// Response in frame - Frame number - http.response_in
    pub response_in: String,
    /// Response number - Unsigned integer (4 bytes) - http.response_number
    pub response_number: String,
    /// Sec-WebSocket-Accept - Character string - http.sec_websocket_accept
    pub sec_websocket_accept: String,
    /// Sec-WebSocket-Extensions - Character string - http.sec_websocket_extensions
    pub sec_websocket_extensions: String,
    /// Sec-WebSocket-Key - Character string - http.sec_websocket_key
    pub sec_websocket_key: String,
    /// Sec-WebSocket-Protocol - Character string - http.sec_websocket_protocol
    pub sec_websocket_protocol: String,
    /// Sec-WebSocket-Version - Character string - http.sec_websocket_version
    pub sec_websocket_version: String,
    /// Server - Character string - http.server
    pub server: String,
    /// Set-Cookie - Character string - http.set_cookie
    pub set_cookie: String,
    /// Unencrypted HTTP protocol detected over encrypted port, could indicate a dangerous misconfiguration. - Label - http.ssl_port
    pub ssl_port: String,
    /// HTTP body subdissector failed, trying heuristic subdissector - Label - http.subdissector_failed
    pub subdissector_failed: String,
    /// The Content-Length and Transfer-Encoding header must not be set together - Label - http.te_and_length
    pub te_and_length: String,
    /// Unknown transfer coding name in Transfer-Encoding header - Label - http.te_unknown
    pub te_unknown: String,
    /// Time since request - Time offset - http.time
    pub time: String,
    /// Unencrypted HTTP protocol detected over encrypted port, could indicate a dangerous misconfiguration. - Label - http.tls_port
    pub tls_port: String,
    /// Transfer-Encoding - Character string - http.transfer_encoding
    pub transfer_encoding: String,
    /// Unknown header - Character string - http.unknown_header
    pub unknown_header: String,
    /// Upgrade - Character string - http.upgrade
    pub upgrade: String,
    /// User-Agent - Character string - http.user_agent
    pub user_agent: String,
    /// WWW-Authenticate - Character string - http.www_authenticate
    pub www_authenticate: String,
    /// X-Forwarded-For - Character string - http.x_forwarded_for
    pub x_forwarded_for: String,
}

/// HTTP implementation
impl HTTP {
    /// Create a new HTTP layer
    pub fn new() -> HTTP {
        HTTP {
            accept: String::new(),
            accept_encoding: String::new(),
            accept_language: String::new(),
            authbasic: String::new(),
            authcitrix: String::new(),
            authcitrix_domain: String::new(),
            authcitrix_password: String::new(),
            authcitrix_session: String::new(),
            authcitrix_user: String::new(),
            authorization: String::new(),
            bad_header_name: String::new(),
            cache_control: String::new(),
            chat: String::new(),
            chunk_boundary: String::new(),
            chunk_data: String::new(),
            chunk_size: String::new(),
            chunkd_and_length: String::new(),
            chunked_trailer_part: String::new(),
            connection: String::new(),
            content_encoding: String::new(),
            content_length: String::new(),
            content_length_header: String::new(),
            content_type: String::new(),
            cookie: String::new(),
            cookie_pair: String::new(),
            date: String::new(),
            decompression_disabled: String::new(),
            decompression_failed: String::new(),
            file_data: String::new(),
            host: String::new(),
            http2_settings: String::new(),
            http2_settings_uri: String::new(),
            last_modified: String::new(),
            leading_crlf: String::new(),
            location: String::new(),
            next_request_in: String::new(),
            next_response_in: String::new(),
            notification: String::new(),
            path_segment: String::new(),
            path_sub_segment: String::new(),
            prev_request_in: String::new(),
            prev_response_in: String::new(),
            proxy_authenticate: String::new(),
            proxy_authorization: String::new(),
            proxy_connect_host: String::new(),
            proxy_connect_port: String::new(),
            referer: String::new(),
            request: String::new(),
            request_full_uri: String::new(),
            request_line: String::new(),
            request_method: String::new(),
            request_uri: String::new(),
            request_uri_path: String::new(),
            request_uri_query: String::new(),
            request_uri_query_parameter: String::new(),
            request_version: String::new(),
            request_in: String::new(),
            request_number: String::new(),
            response: String::new(),
            response_code: String::new(),
            response_code_desc: String::new(),
            response_line: String::new(),
            response_phrase: String::new(),
            response_version: String::new(),
            response_for_uri: String::new(),
            response_in: String::new(),
            response_number: String::new(),
            sec_websocket_accept: String::new(),
            sec_websocket_extensions: String::new(),
            sec_websocket_key: String::new(),
            sec_websocket_protocol: String::new(),
            sec_websocket_version: String::new(),
            server: String::new(),
            set_cookie: String::new(),
            ssl_port: String::new(),
            subdissector_failed: String::new(),
            te_and_length: String::new(),
            te_unknown: String::new(),
            time: String::new(),
            tls_port: String::new(),
            transfer_encoding: String::new(),
            unknown_header: String::new(),
            upgrade: String::new(),
            user_agent: String::new(),
            www_authenticate: String::new(),
            x_forwarded_for: String::new(),
        }
    }

    /// Update the HTTP layer with a new value
    ///
    /// This function maps the Wireshark/TShark field name to the corresponding
    /// HTTP layer field name in the struct.
    pub fn update(&mut self, field: &str, value: &str) {
        match field {
            "http.accept" => self.accept = value.to_string(),
            "http.accept_encoding" => self.accept_encoding = value.to_string(),
            "http.accept_language" => self.accept_language = value.to_string(),
            "http.authbasic" => self.authbasic = value.to_string(),
            "http.authcitrix" => self.authcitrix = value.to_string(),
            "http.authcitrix.domain" => self.authcitrix_domain = value.to_string(),
            "http.authcitrix.password" => self.authcitrix_password = value.to_string(),
            "http.authcitrix.session" => self.authcitrix_session = value.to_string(),
            "http.authcitrix.user" => self.authcitrix_user = value.to_string(),
            "http.authorization" => self.authorization = value.to_string(),
            "http.bad_header_name" => self.bad_header_name = value.to_string(),
            "http.cache_control" => self.cache_control = value.to_string(),
            "http.chat" => self.chat = value.to_string(),
            "http.chunk_boundary" => self.chunk_boundary = value.to_string(),
            "http.chunk_data" => self.chunk_data = value.to_string(),
            "http.chunk_size" => self.chunk_size = value.to_string(),
            "http.chunkd_and_length" => self.chunkd_and_length = value.to_string(),
            "http.chunked_trailer_part" => self.chunked_trailer_part = value.to_string(),
            "http.connection" => self.connection = value.to_string(),
            "http.content_encoding" => self.content_encoding = value.to_string(),
            "http.content_length" => self.content_length = value.to_string(),
            "http.content_length_header" => self.content_length_header = value.to_string(),
            "http.content_type" => self.content_type = value.to_string(),
            "http.cookie" => self.cookie = value.to_string(),
            "http.cookie_pair" => self.cookie_pair = value.to_string(),
            "http.date" => self.date = value.to_string(),
            "http.decompression_disabled" => self.decompression_disabled = value.to_string(),
            "http.decompression_failed" => self.decompression_failed = value.to_string(),
            "http.file_data" => self.file_data = value.to_string(),
            "http.host" => self.host = value.to_string(),
            "http.http2_settings" => self.http2_settings = value.to_string(),
            "http.http2_settings_uri" => self.http2_settings_uri = value.to_string(),
            "http.last_modified" => self.last_modified = value.to_string(),
            "http.leading_crlf" => self.leading_crlf = value.to_string(),
            "http.location" => self.location = value.to_string(),
            "http.next_request_in" => self.next_request_in = value.to_string(),
            "http.next_response_in" => self.next_response_in = value.to_string(),
            "http.notification" => self.notification = value.to_string(),
            "http.path_segment" => self.path_segment = value.to_string(),
            "http.path_sub_segment" => self.path_sub_segment = value.to_string(),
            "http.prev_request_in" => self.prev_request_in = value.to_string(),
            "http.prev_response_in" => self.prev_response_in = value.to_string(),
            "http.proxy_authenticate" => self.proxy_authenticate = value.to_string(),
            "http.proxy_authorization" => self.proxy_authorization = value.to_string(),
            "http.proxy_connect_host" => self.proxy_connect_host = value.to_string(),
            "http.proxy_connect_port" => self.proxy_connect_port = value.to_string(),
            "http.referer" => self.referer = value.to_string(),
            "http.request" => self.request = value.to_string(),
            "http.request.full_uri" => self.request_full_uri = value.to_string(),
            "http.request.line" => self.request_line = value.to_string(),
            "http.request.method" => self.request_method = value.to_string(),
            "http.request.uri" => self.request_uri = value.to_string(),
            "http.request.uri.path" => self.request_uri_path = value.to_string(),
            "http.request.uri.query" => self.request_uri_query = value.to_string(),
            "http.request.uri.query.parameter" => {
                self.request_uri_query_parameter = value.to_string()
            }
            "http.request.version" => self.request_version = value.to_string(),
            "http.request_in" => self.request_in = value.to_string(),
            "http.request_number" => self.request_number = value.to_string(),
            "http.response" => self.response = value.to_string(),
            "http.response.code" => self.response_code = value.to_string(),
            "http.response.code.desc" => self.response_code_desc = value.to_string(),
            "http.response.line" => self.response_line = value.to_string(),
            "http.response.phrase" => self.response_phrase = value.to_string(),
            "http.response.version" => self.response_version = value.to_string(),
            "http.response_for.uri" => self.response_for_uri = value.to_string(),
            "http.response_in" => self.response_in = value.to_string(),
            "http.response_number" => self.response_number = value.to_string(),
            "http.sec_websocket_accept" => self.sec_websocket_accept = value.to_string(),
            "http.sec_websocket_extensions" => self.sec_websocket_extensions = value.to_string(),
            "http.sec_websocket_key" => self.sec_websocket_key = value.to_string(),
            "http.sec_websocket_protocol" => self.sec_websocket_protocol = value.to_string(),
            "http.sec_websocket_version" => self.sec_websocket_version = value.to_string(),
            "http.server" => self.server = value.to_string(),
            "http.set_cookie" => self.set_cookie = value.to_string(),
            "http.ssl_port" => self.ssl_port = value.to_string(),
            "http.subdissector_failed" => self.subdissector_failed = value.to_string(),
            "http.te_and_length" => self.te_and_length = value.to_string(),
            "http.te_unknown" => self.te_unknown = value.to_string(),
            "http.time" => self.time = value.to_string(),
            "http.tls_port" => self.tls_port = value.to_string(),
            "http.transfer_encoding" => self.transfer_encoding = value.to_string(),
            "http.unknown_header" => self.unknown_header = value.to_string(),
            "http.upgrade" => self.upgrade = value.to_string(),
            "http.user_agent" => self.user_agent = value.to_string(),
            "http.www_authenticate" => self.www_authenticate = value.to_string(),
            "http.x_forwarded_for" => self.x_forwarded_for = value.to_string(),
            &_ => (),
        }
    }

    /// Get the HTTP layer header values for the CSV file
    pub fn get_csv_header(delimiter: &str) -> String {
        let mut header = String::new();

        header.push_str(format!("http.accept{}", delimiter).as_str());
        header.push_str(format!("http.accept_encoding{}", delimiter).as_str());
        header.push_str(format!("http.accept_language{}", delimiter).as_str());
        header.push_str(format!("http.authbasic{}", delimiter).as_str());
        header.push_str(format!("http.authcitrix{}", delimiter).as_str());
        header.push_str(format!("http.authcitrix.domain{}", delimiter).as_str());
        header.push_str(format!("http.authcitrix.password{}", delimiter).as_str());
        header.push_str(format!("http.authcitrix.session{}", delimiter).as_str());
        header.push_str(format!("http.authcitrix.user{}", delimiter).as_str());
        header.push_str(format!("http.authorization{}", delimiter).as_str());
        header.push_str(format!("http.bad_header_name{}", delimiter).as_str());
        header.push_str(format!("http.cache_control{}", delimiter).as_str());
        header.push_str(format!("http.chat{}", delimiter).as_str());
        header.push_str(format!("http.chunk_boundary{}", delimiter).as_str());
        header.push_str(format!("http.chunk_data{}", delimiter).as_str());
        header.push_str(format!("http.chunk_size{}", delimiter).as_str());
        header.push_str(format!("http.chunkd_and_length{}", delimiter).as_str());
        header.push_str(format!("http.chunked_trailer_part{}", delimiter).as_str());
        header.push_str(format!("http.connection{}", delimiter).as_str());
        header.push_str(format!("http.content_encoding{}", delimiter).as_str());
        header.push_str(format!("http.content_length{}", delimiter).as_str());
        header.push_str(format!("http.content_length_header{}", delimiter).as_str());
        header.push_str(format!("http.content_type{}", delimiter).as_str());
        header.push_str(format!("http.cookie{}", delimiter).as_str());
        header.push_str(format!("http.cookie_pair{}", delimiter).as_str());
        header.push_str(format!("http.date{}", delimiter).as_str());
        header.push_str(format!("http.decompression_disabled{}", delimiter).as_str());
        header.push_str(format!("http.decompression_failed{}", delimiter).as_str());
        header.push_str(format!("http.file_data{}", delimiter).as_str());
        header.push_str(format!("http.host{}", delimiter).as_str());
        header.push_str(format!("http.http2_settings{}", delimiter).as_str());
        header.push_str(format!("http.http2_settings_uri{}", delimiter).as_str());
        header.push_str(format!("http.last_modified{}", delimiter).as_str());
        header.push_str(format!("http.leading_crlf{}", delimiter).as_str());
        header.push_str(format!("http.location{}", delimiter).as_str());
        header.push_str(format!("http.next_request_in{}", delimiter).as_str());
        header.push_str(format!("http.next_response_in{}", delimiter).as_str());
        header.push_str(format!("http.notification{}", delimiter).as_str());
        header.push_str(format!("http.path_segment{}", delimiter).as_str());
        header.push_str(format!("http.path_sub_segment{}", delimiter).as_str());
        header.push_str(format!("http.prev_request_in{}", delimiter).as_str());
        header.push_str(format!("http.prev_response_in{}", delimiter).as_str());
        header.push_str(format!("http.proxy_authenticate{}", delimiter).as_str());
        header.push_str(format!("http.proxy_authorization{}", delimiter).as_str());
        header.push_str(format!("http.proxy_connect_host{}", delimiter).as_str());
        header.push_str(format!("http.proxy_connect_port{}", delimiter).as_str());
        header.push_str(format!("http.referer{}", delimiter).as_str());
        header.push_str(format!("http.request{}", delimiter).as_str());
        header.push_str(format!("http.request.full_uri{}", delimiter).as_str());
        header.push_str(format!("http.request.line{}", delimiter).as_str());
        header.push_str(format!("http.request.method{}", delimiter).as_str());
        header.push_str(format!("http.request.uri{}", delimiter).as_str());
        header.push_str(format!("http.request.uri.path{}", delimiter).as_str());
        header.push_str(format!("http.request.uri.query{}", delimiter).as_str());
        header.push_str(format!("http.request.uri.query.parameter{}", delimiter).as_str());
        header.push_str(format!("http.request.version{}", delimiter).as_str());
        header.push_str(format!("http.request_in{}", delimiter).as_str());
        header.push_str(format!("http.request_number{}", delimiter).as_str());
        header.push_str(format!("http.response{}", delimiter).as_str());
        header.push_str(format!("http.response.code{}", delimiter).as_str());
        header.push_str(format!("http.response.code.desc{}", delimiter).as_str());
        header.push_str(format!("http.response.line{}", delimiter).as_str());
        header.push_str(format!("http.response.phrase{}", delimiter).as_str());
        header.push_str(format!("http.response.version{}", delimiter).as_str());
        header.push_str(format!("http.response_for.uri{}", delimiter).as_str());
        header.push_str(format!("http.response_in{}", delimiter).as_str());
        header.push_str(format!("http.response_number{}", delimiter).as_str());
        header.push_str(format!("http.sec_websocket_accept{}", delimiter).as_str());
        header.push_str(format!("http.sec_websocket_extensions{}", delimiter).as_str());
        header.push_str(format!("http.sec_websocket_key{}", delimiter).as_str());
        header.push_str(format!("http.sec_websocket_protocol{}", delimiter).as_str());
        header.push_str(format!("http.sec_websocket_version{}", delimiter).as_str());
        header.push_str(format!("http.server{}", delimiter).as_str());
        header.push_str(format!("http.set_cookie{}", delimiter).as_str());
        header.push_str(format!("http.ssl_port{}", delimiter).as_str());
        header.push_str(format!("http.subdissector_failed{}", delimiter).as_str());
        header.push_str(format!("http.te_and_length{}", delimiter).as_str());
        header.push_str(format!("http.te_unknown{}", delimiter).as_str());
        header.push_str(format!("http.time{}", delimiter).as_str());
        header.push_str(format!("http.tls_port{}", delimiter).as_str());
        header.push_str(format!("http.transfer_encoding{}", delimiter).as_str());
        header.push_str(format!("http.unknown_header{}", delimiter).as_str());
        header.push_str(format!("http.upgrade{}", delimiter).as_str());
        header.push_str(format!("http.user_agent{}", delimiter).as_str());
        header.push_str(format!("http.www_authenticate{}", delimiter).as_str());
        header.push_str(format!("http.x_forwarded_for{}", delimiter).as_str());

        header
    }

    /// Get the CSV data of the HTTP layer as a string
    pub fn get_csv_data(&self, delimiter: &str) -> String {
        let mut data = String::new();

        data.push_str(format!("{}{}", self.accept, delimiter).as_str());
        data.push_str(format!("{}{}", self.accept_encoding, delimiter).as_str());
        data.push_str(format!("{}{}", self.accept_language, delimiter).as_str());
        data.push_str(format!("{}{}", self.authbasic, delimiter).as_str());
        data.push_str(format!("{}{}", self.authcitrix, delimiter).as_str());
        data.push_str(format!("{}{}", self.authcitrix_domain, delimiter).as_str());
        data.push_str(format!("{}{}", self.authcitrix_password, delimiter).as_str());
        data.push_str(format!("{}{}", self.authcitrix_session, delimiter).as_str());
        data.push_str(format!("{}{}", self.authcitrix_user, delimiter).as_str());
        data.push_str(format!("{}{}", self.authorization, delimiter).as_str());
        data.push_str(format!("{}{}", self.bad_header_name, delimiter).as_str());
        data.push_str(format!("{}{}", self.cache_control, delimiter).as_str());
        data.push_str(format!("{}{}", self.chat, delimiter).as_str());
        data.push_str(format!("{}{}", self.chunk_boundary, delimiter).as_str());
        data.push_str(format!("{}{}", self.chunk_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.chunk_size, delimiter).as_str());
        data.push_str(format!("{}{}", self.chunkd_and_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.chunked_trailer_part, delimiter).as_str());
        data.push_str(format!("{}{}", self.connection, delimiter).as_str());
        data.push_str(format!("{}{}", self.content_encoding, delimiter).as_str());
        data.push_str(format!("{}{}", self.content_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.content_length_header, delimiter).as_str());
        data.push_str(format!("{}{}", self.content_type, delimiter).as_str());
        data.push_str(format!("{}{}", self.cookie, delimiter).as_str());
        data.push_str(format!("{}{}", self.cookie_pair, delimiter).as_str());
        data.push_str(format!("{}{}", self.date, delimiter).as_str());
        data.push_str(format!("{}{}", self.decompression_disabled, delimiter).as_str());
        data.push_str(format!("{}{}", self.decompression_failed, delimiter).as_str());
        data.push_str(format!("{}{}", self.file_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.host, delimiter).as_str());
        data.push_str(format!("{}{}", self.http2_settings, delimiter).as_str());
        data.push_str(format!("{}{}", self.http2_settings_uri, delimiter).as_str());
        data.push_str(format!("{}{}", self.last_modified, delimiter).as_str());
        data.push_str(format!("{}{}", self.leading_crlf, delimiter).as_str());
        data.push_str(format!("{}{}", self.location, delimiter).as_str());
        data.push_str(format!("{}{}", self.next_request_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.next_response_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.notification, delimiter).as_str());
        data.push_str(format!("{}{}", self.path_segment, delimiter).as_str());
        data.push_str(format!("{}{}", self.path_sub_segment, delimiter).as_str());
        data.push_str(format!("{}{}", self.prev_request_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.prev_response_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.proxy_authenticate, delimiter).as_str());
        data.push_str(format!("{}{}", self.proxy_authorization, delimiter).as_str());
        data.push_str(format!("{}{}", self.proxy_connect_host, delimiter).as_str());
        data.push_str(format!("{}{}", self.proxy_connect_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.referer, delimiter).as_str());
        data.push_str(format!("{}{}", self.request, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_full_uri, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_line, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_method, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_uri, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_uri_path, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_uri_query, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_uri_query_parameter, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_version, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.request_number, delimiter).as_str());
        data.push_str(format!("{}{}", self.response, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_code, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_code_desc, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_line, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_phrase, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_version, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_for_uri, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.response_number, delimiter).as_str());
        data.push_str(format!("{}{}", self.sec_websocket_accept, delimiter).as_str());
        data.push_str(format!("{}{}", self.sec_websocket_extensions, delimiter).as_str());
        data.push_str(format!("{}{}", self.sec_websocket_key, delimiter).as_str());
        data.push_str(format!("{}{}", self.sec_websocket_protocol, delimiter).as_str());
        data.push_str(format!("{}{}", self.sec_websocket_version, delimiter).as_str());
        data.push_str(format!("{}{}", self.server, delimiter).as_str());
        data.push_str(format!("{}{}", self.set_cookie, delimiter).as_str());
        data.push_str(format!("{}{}", self.ssl_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.subdissector_failed, delimiter).as_str());
        data.push_str(format!("{}{}", self.te_and_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.te_unknown, delimiter).as_str());
        data.push_str(format!("{}{}", self.time, delimiter).as_str());
        data.push_str(format!("{}{}", self.tls_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.transfer_encoding, delimiter).as_str());
        data.push_str(format!("{}{}", self.unknown_header, delimiter).as_str());
        data.push_str(format!("{}{}", self.upgrade, delimiter).as_str());
        data.push_str(format!("{}{}", self.user_agent, delimiter).as_str());
        data.push_str(format!("{}{}", self.www_authenticate, delimiter).as_str());
        data.push_str(format!("{}{}", self.x_forwarded_for, delimiter).as_str());

        data
    }
}
