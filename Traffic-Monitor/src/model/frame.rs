/// Struct that represents a frame layer
///
/// Referenced from the [Wireshark documentation](https://www.wireshark.org/docs/dfref/f/frame.html)
#[derive(Debug)]
pub struct Frame {
    /// Comment - Character string - comment
    pub comment: String,
    /// Black Box Log - Character string - frame.bblog
    pub bblog: String,
    /// Serial Number - Unsigned integer (4 bytes) - frame.bblog.serial_nr
    pub bblog_serial_nr: String,
    /// Ticks - Unsigned integer (4 bytes) - frame.bblog.ticks
    pub bblog_ticks: String,
    /// Frame length stored into the capture file - Unsigned integer (4 bytes) - frame.cap_len
    pub cap_len: String,
    /// Copying - Boolean - frame.cb_copy
    pub cb_copy: String,
    /// Private Enterprise Number - Unsigned integer (4 bytes) - frame.cb_pen
    pub cb_pen: String,
    /// Coloring Rule Name - Character string - frame.coloring_rule.name
    pub coloring_rule_name: String,
    /// Coloring Rule String - Character string - frame.coloring_rule.string
    pub coloring_rule_string: String,
    /// Comment - Character string - frame.comment
    pub frame_comment: String,
    /// Formatted comment - Label - frame.comment.expert
    pub comment_expert: String,
    /// WTAP_ENCAP - Signed integer (2 bytes) - frame.dlt
    pub dlt: String,
    /// Drop Count - Unsigned integer (8 bytes) - frame.drop_count
    pub drop_count: String,
    /// Encapsulation type - Signed integer (2 bytes) - frame.encap_type
    pub encap_type: String,
    /// File Offset - Signed integer (8 bytes) - frame.file_off
    pub file_off: String,
    /// Frame is ignored - Boolean - frame.ignored
    pub ignored: String,
    /// Incomplete dissector - Label - frame.incomplete
    pub incomplete: String,
    /// Interface description - Character string - frame.interface_description
    pub interface_description: String,
    /// Interface id - Unsigned integer (4 bytes) - frame.interface_id
    pub interface_id: String,
    /// Interface name - Character string - frame.interface_name
    pub interface_name: String,
    /// Interface queue - Unsigned integer (4 bytes) - frame.interface_queue
    pub interface_queue: String,
    /// Frame length on the wire - Unsigned integer (4 bytes) - frame.len
    pub len: String,
    /// Frame length is less than captured length - Label - frame.len_lt_caplen
    pub len_lt_caplen: String,
    /// Link Number - Unsigned integer (2 bytes) - frame.link_nr
    pub link_nr: String,
    /// Frame is marked - Boolean - frame.marked
    pub marked: String,
    /// Frame MD5 Hash - Character string - frame.md5_hash
    pub md5_hash: String,
    /// Frame Number - Unsigned integer (4 bytes) - frame.number
    pub number: String,
    /// Time shift for self packet - Time offset - frame.offset_shift
    pub offset_shift: String,
    /// Point-to-Point Direction - Signed integer (1 byte) - frame.p2p_dir
    pub p2p_dir: String,
    /// Number of per-protocol-data - Unsigned integer (4 bytes) - frame.p_prot_data
    pub p_prot_data: String,
    /// Packet flags - Unsigned integer (4 bytes) - frame.packet_flags
    pub packet_flags: String,
    /// CRC error - Boolean - frame.packet_flags_crc_error
    pub packet_flags_crc_error: String,
    /// Direction - Unsigned integer (4 bytes) - frame.packet_flags_direction
    pub packet_flags_direction: String,
    /// FCS length - Unsigned integer (4 bytes) - frame.packet_flags_fcs_length
    pub packet_flags_fcs_length: String,
    /// Packet too long error - Boolean - frame.packet_flags_packet_too_error
    pub packet_flags_packet_too_error: String,
    /// Packet too short error - Boolean - frame.packet_flags_packet_too_short_error
    pub packet_flags_packet_too_short_error: String,
    /// Preamble error - Boolean - frame.packet_flags_preamble_error
    pub packet_flags_preamble_error: String,
    /// Reception type - Unsigned integer (4 bytes) - frame.packet_flags_reception_type
    pub packet_flags_reception_type: String,
    /// Reserved - Unsigned integer (4 bytes) - frame.packet_flags_reserved
    pub packet_flags_reserved: String,
    /// Start frame delimiter error - Boolean - frame.packet_flags_start_frame_delimiter_error
    pub packet_flags_start_frame_delimiter_error: String,
    /// Symbol error - Boolean - frame.packet_flags_symbol_error
    pub packet_flags_symbol_error: String,
    /// Unaligned frame error - Boolean - frame.packet_flags_unaligned_frame_error
    pub packet_flags_unaligned_frame_error: String,
    /// Wrong interframe gap error - Boolean - frame.packet_flags_wrong_inter_frame_gap_error
    pub packet_flags_wrong_inter_frame_gap_error: String,
    /// Packet id - Unsigned integer (8 bytes) - frame.packet_id
    pub packet_id: String,
    /// Data - Byte sequence - frame.pcaplog.data
    pub pcaplog_data: String,
    /// Data Length - Unsigned integer (4 bytes) - frame.pcaplog.data_length
    pub pcaplog_data_length: String,
    /// Date Type - Unsigned integer (4 bytes) - frame.pcaplog.data_type
    pub pcaplog_data_type: String,
    /// Frame length on the wire - Unsigned integer (4 bytes) - frame.pkt_len
    pub pkt_len: String,
    /// Protocols in frame - Character string - frame.protocols
    pub protocols: String,
    /// self is a Time Reference frame - Label - frame.ref_time
    pub ref_time: String,
    /// Section number - Unsigned integer (4 bytes) - frame.section_number
    pub section_number: String,
    /// Arrival Time - Date and time - frame.time
    pub time: String,
    /// Time delta from previous captured frame - Time offset - frame.time_delta
    pub time_delta: String,
    /// Time delta from previous displayed frame - Time offset - frame.time_delta_displayed
    pub time_delta_displayed: String,
    /// Epoch Time - Time offset - frame.time_epoch
    pub time_epoch: String,
    /// Arrival Time: Fractional second out of range (0-1000000000) - Label - frame.time_invalid
    pub time_invalid: String,
    /// Time since reference or first frame - Time offset - frame.time_relative
    pub time_relative: String,
    /// Verdict - Character string - frame.verdict
    pub verdict: String,
    /// eBPF TC - Signed integer (8 bytes) - frame.verdict.ebpf_tc
    pub verdict_ebpf_tc: String,
    /// eBPF XDP - Signed integer (8 bytes) - frame.verdict.ebpf_xdp
    pub verdict_ebpf_xdp: String,
    /// Hardware - Byte sequence - frame.verdict.hw
    pub verdict_hw: String,
    /// Unknown - Byte sequence - frame.verdict.unknown
    pub verdict_unknown: String,
}

/// Frame implementation
impl Frame {
    /// Create a new Frame
    pub fn new() -> Frame {
        Frame {
            comment: String::new(),
            bblog: String::new(),
            bblog_serial_nr: String::new(),
            bblog_ticks: String::new(),
            cap_len: String::new(),
            cb_copy: String::new(),
            cb_pen: String::new(),
            coloring_rule_name: String::new(),
            coloring_rule_string: String::new(),
            frame_comment: String::new(),
            comment_expert: String::new(),
            dlt: String::new(),
            drop_count: String::new(),
            encap_type: String::new(),
            ignored: String::new(),
            file_off: String::new(),
            interface_description: String::new(),
            incomplete: String::new(),
            interface_name: String::new(),
            interface_id: String::new(),
            len: String::new(),
            interface_queue: String::new(),
            link_nr: String::new(),
            len_lt_caplen: String::new(),
            md5_hash: String::new(),
            marked: String::new(),
            offset_shift: String::new(),
            number: String::new(),
            p_prot_data: String::new(),
            p2p_dir: String::new(),
            packet_flags_crc_error: String::new(),
            packet_flags: String::new(),
            packet_flags_fcs_length: String::new(),
            packet_flags_direction: String::new(),
            packet_flags_packet_too_short_error: String::new(),
            packet_flags_packet_too_error: String::new(),
            packet_flags_reception_type: String::new(),
            packet_flags_preamble_error: String::new(),
            packet_flags_start_frame_delimiter_error: String::new(),
            packet_flags_reserved: String::new(),
            packet_flags_unaligned_frame_error: String::new(),
            packet_flags_symbol_error: String::new(),
            packet_id: String::new(),
            packet_flags_wrong_inter_frame_gap_error: String::new(),
            pcaplog_data_length: String::new(),
            pcaplog_data: String::new(),
            pkt_len: String::new(),
            pcaplog_data_type: String::new(),
            ref_time: String::new(),
            protocols: String::new(),
            time: String::new(),
            section_number: String::new(),
            time_delta_displayed: String::new(),
            time_delta: String::new(),
            time_invalid: String::new(),
            time_epoch: String::new(),
            verdict: String::new(),
            time_relative: String::new(),
            verdict_ebpf_xdp: String::new(),
            verdict_ebpf_tc: String::new(),
            verdict_unknown: String::new(),
            verdict_hw: String::new(),
        }
    }

    /// Update a Frame with a new value
    ///
    /// This function maps the Wireshark/TShark field name to the corresponding
    /// Frame field name in the struct.
    pub fn update(&mut self, field: &str, value: &str) {
        match field {
            "comment" => self.comment = value.to_string(),
            "frame.bblog" => self.bblog = value.to_string(),
            "frame.bblog.serial_nr" => self.bblog_serial_nr = value.to_string(),
            "frame.bblog.ticks" => self.bblog_ticks = value.to_string(),
            "frame.cap_len" => self.cap_len = value.to_string(),
            "frame.cb_copy" => self.cb_copy = value.to_string(),
            "frame.cb_pen" => self.cb_pen = value.to_string(),
            "frame.coloring_rule.name" => self.coloring_rule_name = value.to_string(),
            "frame.coloring_rule.string" => self.coloring_rule_string = value.to_string(),
            "frame.comment" => self.frame_comment = value.to_string(),
            "frame.comment.expert" => self.comment_expert = value.to_string(),
            "frame.dlt" => self.dlt = value.to_string(),
            "frame.drop_count" => self.drop_count = value.to_string(),
            "frame.encap_type" => self.encap_type = value.to_string(),
            "frame.file_off" => self.file_off = value.to_string(),
            "frame.ignored" => self.ignored = value.to_string(),
            "frame.incomplete" => self.incomplete = value.to_string(),
            "frame.interface_description" => self.interface_description = value.to_string(),
            "frame.interface_id" => self.interface_id = value.to_string(),
            "frame.interface_name" => self.interface_name = value.to_string(),
            "frame.interface_queue" => self.interface_queue = value.to_string(),
            "frame.len" => self.len = value.to_string(),
            "frame.len_lt_caplen" => self.len_lt_caplen = value.to_string(),
            "frame.link_nr" => self.link_nr = value.to_string(),
            "frame.marked" => self.marked = value.to_string(),
            "frame.md5_hash" => self.md5_hash = value.to_string(),
            "frame.number" => self.number = value.to_string(),
            "frame.offset_shift" => self.offset_shift = value.to_string(),
            "frame.p2p_dir" => self.p2p_dir = value.to_string(),
            "frame.p_prot_data" => self.p_prot_data = value.to_string(),
            "frame.packet_flags" => self.packet_flags = value.to_string(),
            "frame.packet_flags_crc_error" => self.packet_flags_crc_error = value.to_string(),
            "frame.packet_flags_direction" => self.packet_flags_direction = value.to_string(),
            "frame.packet_flags_fcs_length" => self.packet_flags_fcs_length = value.to_string(),
            "frame.packet_flags_packet_too_error" => {
                self.packet_flags_packet_too_error = value.to_string()
            }
            "frame.packet_flags_packet_too_short_error" => {
                self.packet_flags_packet_too_short_error = value.to_string()
            }
            "frame.packet_flags_preamble_error" => {
                self.packet_flags_preamble_error = value.to_string()
            }
            "frame.packet_flags_reception_type" => {
                self.packet_flags_reception_type = value.to_string()
            }
            "frame.packet_flags_reserved" => self.packet_flags_reserved = value.to_string(),
            "frame.packet_flags_start_frame_delimiter_error" => {
                self.packet_flags_start_frame_delimiter_error = value.to_string()
            }
            "frame.packet_flags_symbol_error" => self.packet_flags_symbol_error = value.to_string(),
            "frame.packet_flags_unaligned_frame_error" => {
                self.packet_flags_unaligned_frame_error = value.to_string()
            }
            "frame.packet_flags_wrong_inter_frame_gap_error" => {
                self.packet_flags_wrong_inter_frame_gap_error = value.to_string()
            }
            "frame.packet_id" => self.packet_id = value.to_string(),
            "frame.pcaplog.data" => self.pcaplog_data = value.to_string(),
            "frame.pcaplog.data_length" => self.pcaplog_data_length = value.to_string(),
            "frame.pcaplog.data_type" => self.pcaplog_data_type = value.to_string(),
            "frame.pkt_len" => self.pkt_len = value.to_string(),
            "frame.protocols" => self.protocols = value.to_string(),
            "frame.ref_time" => self.ref_time = value.to_string(),
            "frame.section_number" => self.section_number = value.to_string(),
            "frame.time" => self.time = value.to_string(),
            "frame.time_delta" => self.time_delta = value.to_string(),
            "frame.time_delta_displayed" => self.time_delta_displayed = value.to_string(),
            "frame.time_epoch" => self.time_epoch = value.to_string(),
            "frame.time_invalid" => self.time_invalid = value.to_string(),
            "frame.time_relative" => self.time_relative = value.to_string(),
            "frame.verdict" => self.verdict = value.to_string(),
            "frame.verdict.ebpf_tc" => self.verdict_ebpf_tc = value.to_string(),
            "frame.verdict.ebpf_xdp" => self.verdict_ebpf_xdp = value.to_string(),
            "frame.verdict.hw" => self.verdict_hw = value.to_string(),
            "frame.verdict.unknown" => self.verdict_unknown = value.to_string(),
            &_ => (),
        }
    }

    /// Get the Frame header values for the CSV file
    pub fn get_csv_header(&self, delimiter: &str) -> String {
        let mut header = String::new();

        header.push_str(format!("comment{}", delimiter).as_str());
        header.push_str(format!("frame.bblog{}", delimiter).as_str());
        header.push_str(format!("frame.bblog.serial_nr{}", delimiter).as_str());
        header.push_str(format!("frame.bblog.ticks{}", delimiter).as_str());
        header.push_str(format!("frame.cap_len{}", delimiter).as_str());
        header.push_str(format!("frame.cb_copy{}", delimiter).as_str());
        header.push_str(format!("frame.cb_pen{}", delimiter).as_str());
        header.push_str(format!("frame.coloring_rule.name{}", delimiter).as_str());
        header.push_str(format!("frame.coloring_rule.string{}", delimiter).as_str());
        header.push_str(format!("frame.comment{}", delimiter).as_str());
        header.push_str(format!("frame.comment.expert{}", delimiter).as_str());
        header.push_str(format!("frame.dlt{}", delimiter).as_str());
        header.push_str(format!("frame.drop_count{}", delimiter).as_str());
        header.push_str(format!("frame.encap_type{}", delimiter).as_str());
        header.push_str(format!("frame.file_off{}", delimiter).as_str());
        header.push_str(format!("frame.ignored{}", delimiter).as_str());
        header.push_str(format!("frame.incomplete{}", delimiter).as_str());
        header.push_str(format!("frame.interface_description{}", delimiter).as_str());
        header.push_str(format!("frame.interface_id{}", delimiter).as_str());
        header.push_str(format!("frame.interface_name{}", delimiter).as_str());
        header.push_str(format!("frame.interface_queue{}", delimiter).as_str());
        header.push_str(format!("frame.len{}", delimiter).as_str());
        header.push_str(format!("frame.len_lt_caplen{}", delimiter).as_str());
        header.push_str(format!("frame.link_nr{}", delimiter).as_str());
        header.push_str(format!("frame.marked{}", delimiter).as_str());
        header.push_str(format!("frame.md5_hash{}", delimiter).as_str());
        header.push_str(format!("frame.number{}", delimiter).as_str());
        header.push_str(format!("frame.offset_shift{}", delimiter).as_str());
        header.push_str(format!("frame.p2p_dir{}", delimiter).as_str());
        header.push_str(format!("frame.p_prot_data{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_crc_error{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_direction{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_fcs_length{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_packet_too_error{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_packet_too_short_error{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_preamble_error{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_reception_type{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_reserved{}", delimiter).as_str());
        header.push_str(
            format!(
                "frame.packet_flags_start_frame_delimiter_error{}",
                delimiter
            )
            .as_str(),
        );
        header.push_str(format!("frame.packet_flags_symbol_error{}", delimiter).as_str());
        header.push_str(format!("frame.packet_flags_unaligned_frame_error{}", delimiter).as_str());
        header.push_str(
            format!(
                "frame.packet_flags_wrong_inter_frame_gap_error{}",
                delimiter
            )
            .as_str(),
        );
        header.push_str(format!("frame.packet_id{}", delimiter).as_str());
        header.push_str(format!("frame.pcaplog.data{}", delimiter).as_str());
        header.push_str(format!("frame.pcaplog.data_length{}", delimiter).as_str());
        header.push_str(format!("frame.pcaplog.data_type{}", delimiter).as_str());
        header.push_str(format!("frame.pkt_len{}", delimiter).as_str());
        header.push_str(format!("frame.protocols{}", delimiter).as_str());
        header.push_str(format!("frame.ref_time{}", delimiter).as_str());
        header.push_str(format!("frame.section_number{}", delimiter).as_str());
        header.push_str(format!("frame.time{}", delimiter).as_str());
        header.push_str(format!("frame.time_delta{}", delimiter).as_str());
        header.push_str(format!("frame.time_delta_displayed{}", delimiter).as_str());
        header.push_str(format!("frame.time_epoch{}", delimiter).as_str());
        header.push_str(format!("frame.time_invalid{}", delimiter).as_str());
        header.push_str(format!("frame.time_relative{}", delimiter).as_str());
        header.push_str(format!("frame.verdict{}", delimiter).as_str());
        header.push_str(format!("frame.verdict.ebpf_tc{}", delimiter).as_str());
        header.push_str(format!("frame.verdict.ebpf_xdp{}", delimiter).as_str());
        header.push_str(format!("frame.verdict.hw{}", delimiter).as_str());
        header.push_str(format!("frame.verdict.unknown{}", delimiter).as_str());

        header
    }

    /// Get the CSV data of the frame as a string
    pub fn get_csv_data(&self, delimiter: &str) -> String {
        let mut data = String::new();

        data.push_str(format!("{}{}", self.comment, delimiter).as_str());
        data.push_str(format!("{}{}", self.bblog, delimiter).as_str());
        data.push_str(format!("{}{}", self.bblog_serial_nr, delimiter).as_str());
        data.push_str(format!("{}{}", self.bblog_ticks, delimiter).as_str());
        data.push_str(format!("{}{}", self.cap_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.cb_copy, delimiter).as_str());
        data.push_str(format!("{}{}", self.cb_pen, delimiter).as_str());
        data.push_str(format!("{}{}", self.coloring_rule_name, delimiter).as_str());
        data.push_str(format!("{}{}", self.coloring_rule_string, delimiter).as_str());
        data.push_str(format!("{}{}", self.frame_comment, delimiter).as_str());
        data.push_str(format!("{}{}", self.comment_expert, delimiter).as_str());
        data.push_str(format!("{}{}", self.dlt, delimiter).as_str());
        data.push_str(format!("{}{}", self.drop_count, delimiter).as_str());
        data.push_str(format!("{}{}", self.encap_type, delimiter).as_str());
        data.push_str(format!("{}{}", self.file_off, delimiter).as_str());
        data.push_str(format!("{}{}", self.ignored, delimiter).as_str());
        data.push_str(format!("{}{}", self.incomplete, delimiter).as_str());
        data.push_str(format!("{}{}", self.interface_description, delimiter).as_str());
        data.push_str(format!("{}{}", self.interface_id, delimiter).as_str());
        data.push_str(format!("{}{}", self.interface_name, delimiter).as_str());
        data.push_str(format!("{}{}", self.interface_queue, delimiter).as_str());
        data.push_str(format!("{}{}", self.len, delimiter).as_str());
        data.push_str(format!("{}{}", self.len_lt_caplen, delimiter).as_str());
        data.push_str(format!("{}{}", self.link_nr, delimiter).as_str());
        data.push_str(format!("{}{}", self.marked, delimiter).as_str());
        data.push_str(format!("{}{}", self.md5_hash, delimiter).as_str());
        data.push_str(format!("{}{}", self.number, delimiter).as_str());
        data.push_str(format!("{}{}", self.offset_shift, delimiter).as_str());
        data.push_str(format!("{}{}", self.p2p_dir, delimiter).as_str());
        data.push_str(format!("{}{}", self.p_prot_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags_crc_error, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags_direction, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags_fcs_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags_packet_too_error, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.packet_flags_packet_too_short_error, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.packet_flags_preamble_error, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags_reception_type, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags_reserved, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.packet_flags_start_frame_delimiter_error, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.packet_flags_symbol_error, delimiter).as_str());
        data.push_str(format!("{}{}", self.packet_flags_unaligned_frame_error, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.packet_flags_wrong_inter_frame_gap_error, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.packet_id, delimiter).as_str());
        data.push_str(format!("{}{}", self.pcaplog_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.pcaplog_data_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.pcaplog_data_type, delimiter).as_str());
        data.push_str(format!("{}{}", self.pkt_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.protocols, delimiter).as_str());
        data.push_str(format!("{}{}", self.ref_time, delimiter).as_str());
        data.push_str(format!("{}{}", self.section_number, delimiter).as_str());
        data.push_str(format!("{}{}", self.time, delimiter).as_str());
        data.push_str(format!("{}{}", self.time_delta, delimiter).as_str());
        data.push_str(format!("{}{}", self.time_delta_displayed, delimiter).as_str());
        data.push_str(format!("{}{}", self.time_epoch, delimiter).as_str());
        data.push_str(format!("{}{}", self.time_invalid, delimiter).as_str());
        data.push_str(format!("{}{}", self.time_relative, delimiter).as_str());
        data.push_str(format!("{}{}", self.verdict, delimiter).as_str());
        data.push_str(format!("{}{}", self.verdict_ebpf_tc, delimiter).as_str());
        data.push_str(format!("{}{}", self.verdict_ebpf_xdp, delimiter).as_str());
        data.push_str(format!("{}{}", self.verdict_hw, delimiter).as_str());
        data.push_str(format!("{}{}", self.verdict_unknown, delimiter).as_str());

        data
    }
}
