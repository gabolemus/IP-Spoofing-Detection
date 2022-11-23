/// Struct that represents the TCP layer
///
/// Referenced from the [Wireshark documentation](https://www.wireshark.org/docs/dfref/t/tcp.html)
#[derive(Debug)]
pub struct TCP {
    /// Expert Info - Label - mptcp.analysis.echoed_key_mismatch
    pub mptcp_analysis_echoed_key_mismatch: String,
    /// Expert Info - Label - mptcp.analysis.missing_algorithm
    pub mptcp_analysis_missing_algorithm: String,
    /// Expert Info - Label - mptcp.analysis.unexpected_idsn
    pub mptcp_analysis_unexpected_idsn: String,
    /// Expert Info - Label - mptcp.analysis.unsupported_algorithm
    pub mptcp_analysis_unsupported_algorithm: String,
    /// The echoed key in the ACK of the MPTCP handshake does not match the key of the SYN/ACK - Label - mptcp.connection.echoed_key_mismatch
    pub mptcp_connection_echoed_key_mismatch: String,
    /// No crypto algorithm specified - Label - mptcp.connection.missing_algorithm
    pub mptcp_connection_missing_algorithm: String,
    /// Unsupported algorithm - Label - mptcp.connection.unsupported_algorithm
    pub mptcp_connection_unsupported_algorithm: String,
    /// Fallback to infinite mapping - Label - mptcp.dss.infinite_mapping
    pub mptcp_dss_infinite_mapping: String,
    /// No mapping available - Label - mptcp.dss.missing_mapping
    pub mptcp_dss_missing_mapping: String,
    /// Acknowledgment Number - Unsigned integer (4 bytes) - tcp.ack
    pub tcp_ack: String,
    /// The acknowledgment number field is nonzero while the ACK flag is not set - Label - tcp.ack.nonzero
    pub tcp_ack_nonzero: String,
    /// Acknowledgment number (raw) - Unsigned integer (4 bytes) - tcp.ack_raw
    pub tcp_ack_raw: String,
    /// SEQ/ACK analysis - Label - tcp.analysis
    pub tcp_analysis: String,
    /// ACKed segment that wasn't captured (common at capture start) - Label - tcp.analysis.ack_lost_segment
    pub tcp_analysis_ack_lost_segment: String,
    /// The RTT to ACK the segment was - Time offset - tcp.analysis.ack_rtt
    pub tcp_analysis_ack_rtt: String,
    /// This is an ACK to the segment in frame - Frame number - tcp.analysis.acks_frame
    pub tcp_analysis_acks_frame: String,
    /// Bytes in flight - Unsigned integer (4 bytes) - tcp.analysis.bytes_in_flight
    pub tcp_analysis_bytes_in_flight: String,
    /// Duplicate ACK - Label - tcp.analysis.duplicate_ack
    pub tcp_analysis_duplicate_ack: String,
    /// Duplicate to the ACK in frame - Frame number - tcp.analysis.duplicate_ack_frame
    pub tcp_analysis_duplicate_ack_frame: String,
    /// Duplicate ACK # - Unsigned integer (4 bytes) - tcp.analysis.duplicate_ack_num
    pub tcp_analysis_duplicate_ack_num: String,
    /// This frame is a (suspected) fast retransmission - Label - tcp.analysis.fast_retransmission
    pub tcp_analysis_fast_retransmission: String,
    /// TCP Analysis Flags - Label - tcp.analysis.flags
    pub tcp_analysis_flags: String,
    /// iRTT - Time offset - tcp.analysis.initial_rtt
    pub tcp_analysis_initial_rtt: String,
    /// TCP keep-alive segment - Label - tcp.analysis.keep_alive
    pub tcp_analysis_keep_alive: String,
    /// ACK to a TCP keep-alive segment - Label - tcp.analysis.keep_alive_ack
    pub tcp_analysis_keep_alive_ack: String,
    /// Previous segment(s) not captured (common at capture start) - Label - tcp.analysis.lost_segment
    pub tcp_analysis_lost_segment: String,
    /// This frame is a (suspected) out-of-order segment - Label - tcp.analysis.out_of_order
    pub tcp_analysis_out_of_order: String,
    /// Bytes sent since last PSH flag - Unsigned integer (4 bytes) - tcp.analysis.push_bytes_sent
    pub tcp_analysis_push_bytes_sent: String,
    /// This frame is a (suspected) retransmission - Label - tcp.analysis.retransmission
    pub tcp_analysis_retransmission: String,
    /// A new tcp session is started with the same ports as an earlier session in this trace - Label - tcp.analysis.reused_ports
    pub tcp_analysis_reused_ports: String,
    /// The RTO for this segment was - Time offset - tcp.analysis.rto
    pub tcp_analysis_rto: String,
    /// RTO based on delta from frame - Frame number - tcp.analysis.rto_frame
    pub tcp_analysis_rto_frame: String,
    /// This frame is a (suspected) spurious retransmission - Label - tcp.analysis.spurious_retransmission
    pub tcp_analysis_spurious_retransmission: String,
    /// TCP SYN-ACK accepting TFO data - Label - tcp.analysis.tfo_ack
    pub tcp_analysis_tfo_ack: String,
    /// TCP SYN-ACK ignoring TFO data - Label - tcp.analysis.tfo_ignored
    pub tcp_analysis_tfo_ignored: String,
    /// TCP SYN with TFO Cookie - Label - tcp.analysis.tfo_syn
    pub tcp_analysis_tfo_syn: String,
    /// TCP window specified by the receiver is now completely full - Label - tcp.analysis.window_full
    pub tcp_analysis_window_full: String,
    /// TCP window update - Label - tcp.analysis.window_update
    pub tcp_analysis_window_update: String,
    /// TCP Zero Window segment - Label - tcp.analysis.zero_window
    pub tcp_analysis_zero_window: String,
    /// TCP Zero Window Probe - Label - tcp.analysis.zero_window_probe
    pub tcp_analysis_zero_window_probe: String,
    /// ACK to a TCP Zero Window Probe - Label - tcp.analysis.zero_window_probe_ack
    pub tcp_analysis_zero_window_probe_ack: String,
    /// Bogus TCP Header length - Label - tcp.bogus_header_length
    pub tcp_bogus_header_length: String,
    /// Checksum - Unsigned integer (2 bytes) - tcp.checksum
    pub tcp_checksum: String,
    /// TCP Checksum 0xffff instead of 0x0000 (see RFC 1624) - Label - tcp.checksum.ffff
    pub tcp_checksum_ffff: String,
    /// Checksum Status - Unsigned integer (1 byte) - tcp.checksum.status
    pub tcp_checksum_status: String,
    /// Bad Checksum - Boolean - tcp.checksum_bad
    pub tcp_checksum_bad: String,
    /// Bad checksum - Label - tcp.checksum_bad.expert
    pub tcp_checksum_bad_expert: String,
    /// Calculated Checksum - Unsigned integer (2 bytes) - tcp.checksum_calculated
    pub tcp_checksum_calculated: String,
    /// Good Checksum - Boolean - tcp.checksum_good
    pub tcp_checksum_good: String,
    /// Conversation completeness - Unsigned integer (1 byte) - tcp.completeness
    pub tcp_completeness: String,
    /// Connection finish (FIN) - Label - tcp.connection.fin
    pub tcp_connection_fin: String,
    /// This frame initiates the connection closing - Label - tcp.connection.fin_active
    pub tcp_connection_fin_active: String,
    /// This frame undergoes the connection closing - Label - tcp.connection.fin_passive
    pub tcp_connection_fin_passive: String,
    /// Connection reset (RST) - Label - tcp.connection.rst
    pub tcp_connection_rst: String,
    /// Connection establish acknowledge (SYN+ACK) - Label - tcp.connection.sack
    pub tcp_connection_sack: String,
    /// Connection establish request (SYN) - Label - tcp.connection.syn
    pub tcp_connection_syn: String,
    /// Connection establish acknowledge (SYN+ACK) - Label - tcp.connection.synack
    pub tcp_connection_synack: String,
    /// This is a continuation to the PDU in frame - Frame number - tcp.continuation_to
    pub tcp_continuation_to: String,
    /// TCP segment data - Byte sequence - tcp.data
    pub tcp_data: String,
    /// Destination Port - Unsigned integer (2 bytes) - tcp.dstport
    pub tcp_dstport: String,
    /// Retransmission of FIN from frame - Frame number - tcp.fin_retransmission
    pub tcp_fin_retransmission: String,
    /// Flags - Unsigned integer (2 bytes) - tcp.flags
    pub tcp_flags: String,
    /// ACE - Unsigned integer (1 byte) - tcp.flags.ace
    pub tcp_flags_ace: String,
    /// Acknowledgment - Boolean - tcp.flags.ack
    pub tcp_flags_ack: String,
    /// Accurate ECN - Boolean - tcp.flags.ae
    pub tcp_flags_ae: String,
    /// Congestion Window Reduced - Boolean - tcp.flags.cwr
    pub tcp_flags_cwr: String,
    /// ECN-Echo - Boolean - tcp.flags.ece
    pub tcp_flags_ece: String,
    /// ECN-Echo - Boolean - tcp.flags.ecn
    pub tcp_flags_ecn: String,
    /// Fin - Boolean - tcp.flags.fin
    pub tcp_flags_fin: String,
    /// Nonce - Boolean - tcp.flags.ns
    pub tcp_flags_ns: String,
    /// Push - Boolean - tcp.flags.push
    pub tcp_flags_push: String,
    /// Reserved - Boolean - tcp.flags.res
    pub tcp_flags_res: String,
    /// Reset - Boolean - tcp.flags.reset
    pub tcp_flags_reset: String,
    /// TCP Flags - Character string - tcp.flags.str
    pub tcp_flags_str: String,
    /// Syn - Boolean - tcp.flags.syn
    pub tcp_flags_syn: String,
    /// Urgent - Boolean - tcp.flags.urg
    pub tcp_flags_urg: String,
    /// Header Length - Unsigned integer (1 byte) - tcp.hdr_len
    pub tcp_hdr_len: String,
    /// TCP Segment Len - Unsigned integer (4 bytes) - tcp.len
    pub tcp_len: String,
    /// Non zero bytes in option space after EOL option - Label - tcp.non_zero_bytes_after_eol
    pub tcp_non_zero_bytes_after_eol: String,
    /// 4 NOP in a row - a router may have removed some options - Label - tcp.nop
    pub tcp_nop: String,
    /// Next Sequence Number - Unsigned integer (4 bytes) - tcp.nxtseq
    pub tcp_nxtseq: String,
    /// Invalid length for option - Label - tcp.option.len.invalid
    pub tcp_option_len_invalid: String,
    /// Kind - Unsigned integer (1 byte) - tcp.option_kind
    pub tcp_option_kind: String,
    /// Length - Unsigned integer (1 byte) - tcp.option_len
    pub tcp_option_len: String,
    /// TCP Options - Byte sequence - tcp.options
    pub tcp_options: String,
    /// Accurate ECN Echo CE Byte Counter - Unsigned integer (3 bytes) - tcp.options.acc_ecn.eceb
    pub tcp_options_acc_ecn_eceb: String,
    /// Accurate ECN Echo ECT(0) Byte Counter - Unsigned integer (3 bytes) - tcp.options.acc_ecn.ee0b
    pub tcp_options_acc_ecn_ee0b: String,
    /// Accurate ECN Echo ECT(1) Byte Counter - Unsigned integer (3 bytes) - tcp.options.acc_ecn.ee1b
    pub tcp_options_acc_ecn_ee1b: String,
    /// AO KeyID - Unsigned integer (1 byte) - tcp.options.ao.keyid
    pub tcp_options_ao_keyid: String,
    /// AO MAC - Byte sequence - tcp.options.ao.mac
    pub tcp_options_ao_mac: String,
    /// AO RNextKeyID - Unsigned integer (1 byte) - tcp.options.ao.rnextkeyid
    pub tcp_options_ao_rnextkeyid: String,
    /// TCP CC Option - Boolean - tcp.options.cc
    pub tcp_options_cc: String,
    /// TCP CC Option - Unsigned integer (4 bytes) - tcp.options.cc_value
    pub tcp_options_cc_value: String,
    /// TCP CC Echo Option - Boolean - tcp.options.ccecho
    pub tcp_options_ccecho: String,
    /// TCP CC New Option - Boolean - tcp.options.ccnew
    pub tcp_options_ccnew: String,
    /// TCP Echo Option - Boolean - tcp.options.echo
    pub tcp_options_echo: String,
    /// TCP Echo Reply Option - Boolean - tcp.options.echo_reply
    pub tcp_options_echo_reply: String,
    /// TCP Echo Option - Unsigned integer (4 bytes) - tcp.options.echo_value
    pub tcp_options_echo_value: String,
    /// TCP Option - Experimental - Byte sequence - tcp.options.experimental
    pub tcp_options_experimental: String,
    /// Data - Byte sequence - tcp.options.experimental.data
    pub tcp_options_experimental_data: String,
    /// Experiment Identifier - Unsigned integer (2 bytes) - tcp.options.experimental.exid
    pub tcp_options_experimental_exid: String,
    /// Magic Number - Unsigned integer (2 bytes) - tcp.options.experimental.magic_number
    pub tcp_options_experimental_magic_number: String,
    /// TCP MD5 Option - Boolean - tcp.options.md5
    pub tcp_options_md5: String,
    /// MD5 digest - Byte sequence - tcp.options.md5.digest
    pub tcp_options_md5_digest: String,
    /// TCP Mood Option - Boolean - tcp.options.mood
    pub tcp_options_mood: String,
    /// TCP Mood Option Value - Character string - tcp.options.mood_val
    pub tcp_options_mood_val: String,
    /// Truncated HMAC - Unsigned integer (8 bytes) - tcp.options.mptcp.addaddrtrunchmac
    pub tcp_options_mptcp_addaddrtrunchmac: String,
    /// Address ID - Unsigned integer (1 byte) - tcp.options.mptcp.addrid
    pub tcp_options_mptcp_addrid: String,
    /// Backup flag - Unsigned integer (1 byte) - tcp.options.mptcp.backup.flag
    pub tcp_options_mptcp_backup_flag: String,
    /// Checksum - Unsigned integer (2 bytes) - tcp.options.mptcp.checksum
    pub tcp_options_mptcp_checksum: String,
    /// Checksum required - Unsigned integer (1 byte) - tcp.options.mptcp.checksumreq.flags
    pub tcp_options_mptcp_checksumreq_flags: String,
    /// Multipath TCP Data ACK - Unsigned integer (8 bytes) - tcp.options.mptcp.dataack
    pub tcp_options_mptcp_dataack: String,
    /// Data ACK is 8 octets - Unsigned integer (1 byte) - tcp.options.mptcp.dataack8.flag
    pub tcp_options_mptcp_dataack8_flag: String,
    /// Data ACK is present - Unsigned integer (1 byte) - tcp.options.mptcp.dataackpresent.flag
    pub tcp_options_mptcp_dataackpresent_flag: String,
    /// DATA_FIN - Unsigned integer (1 byte) - tcp.options.mptcp.datafin.flag
    pub tcp_options_mptcp_datafin_flag: String,
    /// Data-level Length - Unsigned integer (2 bytes) - tcp.options.mptcp.datalvllen
    pub tcp_options_mptcp_datalvllen: String,
    /// Multipath TCP Data Sequence Number - Unsigned integer (8 bytes) - tcp.options.mptcp.dataseqno
    pub tcp_options_mptcp_dataseqno: String,
    /// Data Sequence Number is 8 octets - Unsigned integer (1 byte) - tcp.options.mptcp.dseqn8.flag
    pub tcp_options_mptcp_dseqn8_flag: String,
    /// Data Sequence Number, Subflow Sequence Number, Data-level Length, Checksum present - Unsigned integer (1 byte) - tcp.options.mptcp.dseqnpresent.flag
    pub tcp_options_mptcp_dseqnpresent_flag: String,
    /// Echo - Unsigned integer (1 byte) - tcp.options.mptcp.echo
    pub tcp_options_mptcp_echo: String,
    /// Extensibility - Unsigned integer (1 byte) - tcp.options.mptcp.extensibility.flag
    pub tcp_options_mptcp_extensibility_flag: String,
    /// Transient - Boolean - tcp.options.mptcp.flag_T.flag
    pub tcp_options_mptcp_flag_t_flag: String,
    /// Flag U - Boolean - tcp.options.mptcp.flag_U.flag
    pub tcp_options_mptcp_flag_u_flag: String,
    /// Flag V - Boolean - tcp.options.mptcp.flag_V.flag
    pub tcp_options_mptcp_flag_v_flag: String,
    /// Flag W - Boolean - tcp.options.mptcp.flag_W.flag
    pub tcp_options_mptcp_flag_w_flag: String,
    /// Multipath TCP flags - Unsigned integer (1 byte) - tcp.options.mptcp.flags
    pub tcp_options_mptcp_flags: String,
    /// Advertised IPv4 Address - IPv4 address - tcp.options.mptcp.ipv4
    pub tcp_options_mptcp_ipv4: String,
    /// Advertised IPv6 Address - IPv6 address - tcp.options.mptcp.ipv6
    pub tcp_options_mptcp_ipv6: String,
    /// IP version - Unsigned integer (1 byte) - tcp.options.mptcp.ipver
    pub tcp_options_mptcp_ipver: String,
    /// Do not attempt to establish new subflows to this address and port - Unsigned integer (1 byte) - tcp.options.mptcp.nomoresubflows.flag
    pub tcp_options_mptcp_nomoresubflows_flag: String,
    /// Advertised port - Unsigned integer (2 bytes) - tcp.options.mptcp.port
    pub tcp_options_mptcp_port: String,
    /// Original MPTCP Data ACK - Unsigned integer (8 bytes) - tcp.options.mptcp.rawdataack
    pub tcp_options_mptcp_rawdataack: String,
    /// Data Sequence Number - Unsigned integer (8 bytes) - tcp.options.mptcp.rawdataseqno
    pub tcp_options_mptcp_rawdataseqno: String,
    /// Receiver's Key - Unsigned integer (8 bytes) - tcp.options.mptcp.recvkey
    pub tcp_options_mptcp_recvkey: String,
    /// Receiver's Token - Unsigned integer (4 bytes) - tcp.options.mptcp.recvtok
    pub tcp_options_mptcp_recvtok: String,
    /// Reserved - Unsigned integer (2 bytes) - tcp.options.mptcp.reserved
    pub tcp_options_mptcp_reserved: String,
    /// Reserved - Unsigned integer (1 byte) - tcp.options.mptcp.reserved.flag
    pub tcp_options_mptcp_reserved_flag: String,
    /// TCPRST Reason - Unsigned integer (1 byte) - tcp.options.mptcp.rst_reason
    pub tcp_options_mptcp_rst_reason: String,
    /// Sender's HMAC - Byte sequence - tcp.options.mptcp.sendhmac
    pub tcp_options_mptcp_sendhmac: String,
    /// Sender's Key - Unsigned integer (8 bytes) - tcp.options.mptcp.sendkey
    pub tcp_options_mptcp_sendkey: String,
    /// Multipath TCP Sender's MAC - Unsigned integer (4 bytes) - tcp.options.mptcp.sendmac
    pub tcp_options_mptcp_sendmac: String,
    /// Sender's Random Number - Unsigned integer (4 bytes) - tcp.options.mptcp.sendrand
    pub tcp_options_mptcp_sendrand: String,
    /// Sender's Truncated HMAC - Unsigned integer (8 bytes) - tcp.options.mptcp.sendtrunchmac
    pub tcp_options_mptcp_sendtrunchmac: String,
    /// Multipath TCP Sender's Truncated MAC - Unsigned integer (8 bytes) - tcp.options.mptcp.sendtruncmac
    pub tcp_options_mptcp_sendtruncmac: String,
    /// Use HMAC-SHA1 - Unsigned integer (1 byte) - tcp.options.mptcp.sha1.flag
    pub tcp_options_mptcp_sha1_flag: String,
    /// Use HMAC-SHA256 - Unsigned integer (1 byte) - tcp.options.mptcp.sha256.flag
    pub tcp_options_mptcp_sha256_flag: String,
    /// Subflow Sequence Number - Unsigned integer (4 bytes) - tcp.options.mptcp.subflowseqno
    pub tcp_options_mptcp_subflowseqno: String,
    /// Multipath TCP subtype - Unsigned integer (1 byte) - tcp.options.mptcp.subtype
    pub tcp_options_mptcp_subtype: String,
    /// Multipath TCP version - Unsigned integer (1 byte) - tcp.options.mptcp.version
    pub tcp_options_mptcp_version: String,
    /// TCP MSS Option - Label - tcp.options.mss
    pub tcp_options_mss: String,
    /// The SYN packet does not contain a MSS option - Label - tcp.options.mss.absent
    pub tcp_options_mss_absent: String,
    /// The non-SYN packet does contain a MSS option - Label - tcp.options.mss.present
    pub tcp_options_mss_present: String,
    /// MSS Value - Unsigned integer (2 bytes) - tcp.options.mss_val
    pub tcp_options_mss_val: String,
    /// TCP QS Option - Boolean - tcp.options.qs
    pub tcp_options_qs: String,
    /// QS Rate - Unsigned integer (1 byte) - tcp.options.qs.rate
    pub tcp_options_qs_rate: String,
    /// QS Rate - Unsigned integer (1 byte) - tcp.options.qs.ttl_diff
    pub tcp_options_qs_ttl_diff: String,
    /// Riverbed Probe - Boolean - tcp.options.rvbd.probe
    pub tcp_options_rvbd_probe: String,
    /// Application Version - Unsigned integer (2 bytes) - tcp.options.rvbd.probe.appli_ver
    pub tcp_options_rvbd_probe_appli_ver: String,
    /// Client IP - IPv4 address - tcp.options.rvbd.probe.client.ip
    pub tcp_options_rvbd_probe_client_ip: String,
    /// Probe Flags - Unsigned integer (1 byte) - tcp.options.rvbd.probe.flags
    pub tcp_options_rvbd_probe_flags: String,
    /// Last Notify - Boolean - tcp.options.rvbd.probe.flags.last
    pub tcp_options_rvbd_probe_flags_last: String,
    /// Not CFE - Boolean - tcp.options.rvbd.probe.flags.notcfe
    pub tcp_options_rvbd_probe_flags_notcfe: String,
    /// Disable Probe Cache on CSH - Boolean - tcp.options.rvbd.probe.flags.probe
    pub tcp_options_rvbd_probe_flags_probe: String,
    /// SSH outer to server established - Boolean - tcp.options.rvbd.probe.flags.server
    pub tcp_options_rvbd_probe_flags_server: String,
    /// SSL Enabled - Boolean - tcp.options.rvbd.probe.flags.ssl
    pub tcp_options_rvbd_probe_flags_ssl: String,
    /// Length - Unsigned integer (1 byte) - tcp.options.rvbd.probe.len
    pub tcp_options_rvbd_probe_len: String,
    /// CSH IP - IPv4 address - tcp.options.rvbd.probe.prober
    pub tcp_options_rvbd_probe_prober: String,
    /// SSH IP - IPv4 address - tcp.options.rvbd.probe.proxy.ip
    pub tcp_options_rvbd_probe_proxy_ip: String,
    /// SSH Port - Unsigned integer (2 bytes) - tcp.options.rvbd.probe.proxy.port
    pub tcp_options_rvbd_probe_proxy_port: String,
    /// Reserved - Unsigned integer (1 byte) - tcp.options.rvbd.probe.reserved
    pub tcp_options_rvbd_probe_reserved: String,
    /// CFE Store ID - Unsigned integer (4 bytes) - tcp.options.rvbd.probe.storeid
    pub tcp_options_rvbd_probe_storeid: String,
    /// Type - Unsigned integer (1 byte) - tcp.options.rvbd.probe.type1
    pub tcp_options_rvbd_probe_type1: String,
    /// Type - Unsigned integer (1 byte) - tcp.options.rvbd.probe.type2
    pub tcp_options_rvbd_probe_type2: String,
    /// Version - Unsigned integer (1 byte) - tcp.options.rvbd.probe.version
    pub tcp_options_rvbd_probe_version: String,
    /// Version - Unsigned integer (1 byte) - tcp.options.rvbd.probe.version_raw
    pub tcp_options_rvbd_probe_version_raw: String,
    /// Riverbed Transparency - Boolean - tcp.options.rvbd.trpy
    pub tcp_options_rvbd_trpy: String,
    /// Out of band connection Client Port - Unsigned integer (2 bytes) - tcp.options.rvbd.trpy.client.port
    pub tcp_options_rvbd_trpy_client_port: String,
    /// Dst SH IP Addr - IPv4 address - tcp.options.rvbd.trpy.dst.ip
    pub tcp_options_rvbd_trpy_dst_ip: String,
    /// Dst SH Inner Port - Unsigned integer (2 bytes) - tcp.options.rvbd.trpy.dst.port
    pub tcp_options_rvbd_trpy_dst_port: String,
    /// Transparency Options - Unsigned integer (2 bytes) - tcp.options.rvbd.trpy.flags
    pub tcp_options_rvbd_trpy_flags: String,
    /// Reserved - Boolean - tcp.options.rvbd.trpy.flags.chksum
    pub tcp_options_rvbd_trpy_flags_chksum: String,
    /// Enable Transparency FW feature on All FWs - Boolean - tcp.options.rvbd.trpy.flags.fw_rst
    pub tcp_options_rvbd_trpy_flags_fw_rst: String,
    /// Enable Inner FW feature on All FWs - Boolean - tcp.options.rvbd.trpy.flags.fw_rst_inner
    pub tcp_options_rvbd_trpy_flags_fw_rst_inner: String,
    /// Enable FW traversal feature - Boolean - tcp.options.rvbd.trpy.flags.fw_rst_probe
    pub tcp_options_rvbd_trpy_flags_fw_rst_probe: String,
    /// Transparency Mode - Boolean - tcp.options.rvbd.trpy.flags.mode
    pub tcp_options_rvbd_trpy_flags_mode: String,
    /// Out of band connection - Boolean - tcp.options.rvbd.trpy.flags.oob
    pub tcp_options_rvbd_trpy_flags_oob: String,
    /// Src SH IP Addr - IPv4 address - tcp.options.rvbd.trpy.src.ip
    pub tcp_options_rvbd_trpy_src_ip: String,
    /// Src SH Inner Port - Unsigned integer (2 bytes) - tcp.options.rvbd.trpy.src.port
    pub tcp_options_rvbd_trpy_src_port: String,
    /// TCP SACK Option - Boolean - tcp.options.sack
    pub tcp_options_sack: String,
    /// TCP SACK Count - Unsigned integer (1 byte) - tcp.options.sack.count
    pub tcp_options_sack_count: String,
    /// D-SACK Sequence - Label - tcp.options.sack.dsack
    pub tcp_options_sack_dsack: String,
    /// TCP D-SACK Left Edge - Unsigned integer (4 bytes) - tcp.options.sack.dsack_le
    pub tcp_options_sack_dsack_le: String,
    /// TCP D-SACK Right Edge - Unsigned integer (4 bytes) - tcp.options.sack.dsack_re
    pub tcp_options_sack_dsack_re: String,
    /// TCP SACK Left Edge - Unsigned integer (4 bytes) - tcp.options.sack_le
    pub tcp_options_sack_le: String,
    /// TCP SACK Permitted Option - Boolean - tcp.options.sack_perm
    pub tcp_options_sack_perm: String,
    /// TCP SACK Right Edge - Unsigned integer (4 bytes) - tcp.options.sack_re
    pub tcp_options_sack_re: String,
    /// TCP SCPS Capabilities Option - Boolean - tcp.options.scps
    pub tcp_options_scps: String,
    /// Connection ID - Unsigned integer (1 byte) - tcp.options.scps.binding
    pub tcp_options_scps_binding: String,
    /// Binding Space Data - Byte sequence - tcp.options.scps.binding.data
    pub tcp_options_scps_binding_data: String,
    /// Binding Space (Community) ID - Unsigned integer (1 byte) - tcp.options.scps.binding.id
    pub tcp_options_scps_binding_id: String,
    /// Extended Capability Length - Unsigned integer (1 byte) - tcp.options.scps.binding.len
    pub tcp_options_scps_binding_len: String,
    /// TCP SCPS Capabilities Vector - Unsigned integer (1 byte) - tcp.options.scps.vector
    pub tcp_options_scps_vector: String,
    /// Partial Reliability Capable (BETS) - Boolean - tcp.options.scpsflags.bets
    pub tcp_options_scpsflags_bets: String,
    /// Lossless Header Compression (COMP) - Boolean - tcp.options.scpsflags.compress
    pub tcp_options_scpsflags_compress: String,
    /// Network Layer Timestamp (NLTS) - Boolean - tcp.options.scpsflags.nlts
    pub tcp_options_scpsflags_nlts: String,
    /// Reserved - Unsigned integer (1 byte) - tcp.options.scpsflags.reserved
    pub tcp_options_scpsflags_reserved: String,
    /// Reserved Bit 1 - Boolean - tcp.options.scpsflags.reserved1
    pub tcp_options_scpsflags_reserved1: String,
    /// Reserved Bit 2 - Boolean - tcp.options.scpsflags.reserved2
    pub tcp_options_scpsflags_reserved2: String,
    /// Reserved Bit 3 - Boolean - tcp.options.scpsflags.reserved3
    pub tcp_options_scpsflags_reserved3: String,
    /// Short Form SNACK Capable (SNACK1) - Boolean - tcp.options.scpsflags.snack1
    pub tcp_options_scpsflags_snack1: String,
    /// Long Form SNACK Capable (SNACK2) - Boolean - tcp.options.scpsflags.snack2
    pub tcp_options_scpsflags_snack2: String,
    /// TCP Selective Negative Acknowledgment Option - Boolean - tcp.options.snack
    pub tcp_options_snack: String,
    /// TCP SNACK Left Edge - Unsigned integer (2 bytes) - tcp.options.snack.le
    pub tcp_options_snack_le: String,
    /// TCP SNACK Offset - Unsigned integer (2 bytes) - tcp.options.snack.offset
    pub tcp_options_snack_offset: String,
    /// TCP SNACK Right Edge - Unsigned integer (2 bytes) - tcp.options.snack.re
    pub tcp_options_snack_re: String,
    /// SNACK Sequence - Label - tcp.options.snack.sequence
    pub tcp_options_snack_sequence: String,
    /// TCP SNACK Size - Unsigned integer (2 bytes) - tcp.options.snack.size
    pub tcp_options_snack_size: String,
    /// TARR Reserved - Unsigned integer (1 byte) - tcp.options.tar.reserved
    pub tcp_options_tar_reserved: String,
    /// TARR Rate - Unsigned integer (1 byte) - tcp.options.tarr.rate
    pub tcp_options_tarr_rate: String,
    /// Fast Open Cookie - Label - tcp.options.tfo
    pub tcp_options_tfo: String,
    /// Fast Open Cookie - Byte sequence - tcp.options.tfo.cookie
    pub tcp_options_tfo_cookie: String,
    /// Fast Open Cookie Request - Label - tcp.options.tfo.request
    pub tcp_options_tfo_request: String,
    /// TCP Time Stamp Option - Boolean - tcp.options.time_stamp
    pub tcp_options_time_stamp: String,
    /// Timestamp echo reply - Unsigned integer (4 bytes) - tcp.options.timestamp.tsecr
    pub tcp_options_timestamp_tsecr: String,
    /// Timestamp value - Unsigned integer (4 bytes) - tcp.options.timestamp.tsval
    pub tcp_options_timestamp_tsval: String,
    /// SYN Cookie ECN - Boolean - tcp.options.timestamp.tsval.syncookie.ecn
    pub tcp_options_timestamp_tsval_syncookie_ecn: String,
    /// SYN Cookie SACK - Boolean - tcp.options.timestamp.tsval.syncookie.sack
    pub tcp_options_timestamp_tsval_syncookie_sack: String,
    /// SYN Cookie Timestamp - Unsigned integer (4 bytes) - tcp.options.timestamp.tsval.syncookie.timestamp
    pub tcp_options_timestamp_tsval_syncookie_timestamp: String,
    /// SYN Cookie WScale - Unsigned integer (1 byte) - tcp.options.timestamp.tsval.syncookie.wscale
    pub tcp_options_timestamp_tsval_syncookie_wscale: String,
    /// Type - Unsigned integer (1 byte) - tcp.options.type
    pub tcp_options_type: String,
    /// Class - Unsigned integer (1 byte) - tcp.options.type.class
    pub tcp_options_type_class: String,
    /// Copy on fragmentation - Boolean - tcp.options.type.copy
    pub tcp_options_type_copy: String,
    /// Number - Unsigned integer (1 byte) - tcp.options.type.number
    pub tcp_options_type_number: String,
    /// Payload - Byte sequence - tcp.options.unknown.payload
    pub tcp_options_unknown_payload: String,
    /// TCP User Timeout - Boolean - tcp.options.user_to
    pub tcp_options_user_to: String,
    /// Granularity - Boolean - tcp.options.user_to_granularity
    pub tcp_options_user_to_granularity: String,
    /// User Timeout - Unsigned integer (2 bytes) - tcp.options.user_to_val
    pub tcp_options_user_to_val: String,
    /// TCP Window Scale Option - Boolean - tcp.options.wscale
    pub tcp_options_wscale: String,
    /// Multiplier - Unsigned integer (2 bytes) - tcp.options.wscale.multiplier
    pub tcp_options_wscale_multiplier: String,
    /// Shift count - Unsigned integer (1 byte) - tcp.options.wscale.shift
    pub tcp_options_wscale_shift: String,
    /// Window scale shift exceeds 14 - Label - tcp.options.wscale.shift.invalid
    pub tcp_options_wscale_shift_invalid: String,
    /// TCP Windows Scale Option Value - Unsigned integer (1 byte) - tcp.options.wscale_val
    pub tcp_options_wscale_val: String,
    /// TCP payload - Byte sequence - tcp.payload
    pub tcp_payload: String,
    /// Last frame of this PDU - Frame number - tcp.pdu.last_frame
    pub tcp_pdu_last_frame: String,
    /// PDU Size - Unsigned integer (4 bytes) - tcp.pdu.size
    pub tcp_pdu_size: String,
    /// Time until the last segment of this PDU - Time offset - tcp.pdu.time
    pub tcp_pdu_time: String,
    /// Source or Destination Port - Unsigned integer (2 bytes) - tcp.port
    pub tcp_port: String,
    /// Destination process name - Character string - tcp.proc.dstcmd
    pub tcp_proc_dstcmd: String,
    /// Destination process ID - Unsigned integer (4 bytes) - tcp.proc.dstpid
    pub tcp_proc_dstpid: String,
    /// Destination process user ID - Unsigned integer (4 bytes) - tcp.proc.dstuid
    pub tcp_proc_dstuid: String,
    /// Destination process user name - Character string - tcp.proc.dstuname
    pub tcp_proc_dstuname: String,
    /// Source process name - Character string - tcp.proc.srccmd
    pub tcp_proc_srccmd: String,
    /// Source process ID - Unsigned integer (4 bytes) - tcp.proc.srcpid
    pub tcp_proc_srcpid: String,
    /// Source process user ID - Unsigned integer (4 bytes) - tcp.proc.srcuid
    pub tcp_proc_srcuid: String,
    /// Source process user name - Character string - tcp.proc.srcuname
    pub tcp_proc_srcuname: String,
    /// Reassembled TCP Data - Byte sequence - tcp.reassembled.data
    pub tcp_reassembled_data: String,
    /// Reassembled TCP length - Unsigned integer (4 bytes) - tcp.reassembled.length
    pub tcp_reassembled_length: String,
    /// Reassembled PDU in frame - Frame number - tcp.reassembled_in
    pub tcp_reassembled_in: String,
    /// Reset cause - Character string - tcp.reset_cause
    pub tcp_reset_cause: String,
    /// TCP Segment - Frame number - tcp.segment
    pub tcp_segment: String,
    /// Segment count - Unsigned integer (4 bytes) - tcp.segment.count
    pub tcp_segment_count: String,
    /// Reassembling error - Frame number - tcp.segment.error
    pub tcp_segment_error: String,
    /// Multiple tail segments found - Boolean - tcp.segment.multipletails
    pub tcp_segment_multipletails: String,
    /// Segment overlap - Boolean - tcp.segment.overlap
    pub tcp_segment_overlap: String,
    /// Conflicting data in segment overlap - Boolean - tcp.segment.overlap.conflict
    pub tcp_segment_overlap_conflict: String,
    /// Segment too long - Boolean - tcp.segment.toolongfragment
    pub tcp_segment_toolongfragment: String,
    /// TCP segment data - Byte sequence - tcp.segment_data
    pub tcp_segment_data: String,
    /// Reassembled TCP Segments - Label - tcp.segments
    pub tcp_segments: String,
    /// Sequence Number - Unsigned integer (4 bytes) - tcp.seq
    pub tcp_seq: String,
    /// Sequence Number (raw) - Unsigned integer (4 bytes) - tcp.seq_raw
    pub tcp_seq_raw: String,
    /// Short segment - Label - tcp.short_segment
    pub tcp_short_segment: String,
    /// Source Port - Unsigned integer (2 bytes) - tcp.srcport
    pub tcp_srcport: String,
    /// Stream index - Unsigned integer (4 bytes) - tcp.stream
    pub tcp_stream: String,
    /// suboption would go past end of option - Label - tcp.suboption_malformed
    pub tcp_suboption_malformed: String,
    /// SYN Cookie hash - Unsigned integer (3 bytes) - tcp.syncookie.hash
    pub tcp_syncookie_hash: String,
    /// SYN Cookie Maximum Segment Size - Unsigned integer (1 byte) - tcp.syncookie.mss
    pub tcp_syncookie_mss: String,
    /// SYN Cookie Time - Unsigned integer (1 byte) - tcp.syncookie.time
    pub tcp_syncookie_time: String,
    /// Time since previous frame in this TCP stream - Time offset - tcp.time_delta
    pub tcp_time_delta: String,
    /// Time since first frame in this TCP stream - Time offset - tcp.time_relative
    pub tcp_time_relative: String,
    /// Urgent Pointer - Unsigned integer (2 bytes) - tcp.urgent_pointer
    pub tcp_urgent_pointer: String,
    /// The urgent pointer field is nonzero while the URG flag is not set - Label - tcp.urgent_pointer.non_zero
    pub tcp_urgent_pointer_non_zero: String,
    /// Calculated window size - Unsigned integer (4 bytes) - tcp.window_size
    pub tcp_window_size: String,
    /// Window size scaling factor - Signed integer (4 bytes) - tcp.window_size_scalefactor
    pub tcp_window_size_scalefactor: String,
    /// Window - Unsigned integer (2 bytes) - tcp.window_size_value
    pub tcp_window_size_value: String,
}

/// TCP implementation
impl TCP {
    /// Create a new TCP layer
    pub fn new() -> TCP {
        TCP {
            mptcp_analysis_echoed_key_mismatch: String::new(),
            mptcp_analysis_missing_algorithm: String::new(),
            mptcp_analysis_unexpected_idsn: String::new(),
            mptcp_analysis_unsupported_algorithm: String::new(),
            mptcp_connection_echoed_key_mismatch: String::new(),
            mptcp_connection_missing_algorithm: String::new(),
            mptcp_connection_unsupported_algorithm: String::new(),
            mptcp_dss_infinite_mapping: String::new(),
            mptcp_dss_missing_mapping: String::new(),
            tcp_ack: String::new(),
            tcp_ack_nonzero: String::new(),
            tcp_ack_raw: String::new(),
            tcp_analysis: String::new(),
            tcp_analysis_ack_lost_segment: String::new(),
            tcp_analysis_ack_rtt: String::new(),
            tcp_analysis_acks_frame: String::new(),
            tcp_analysis_bytes_in_flight: String::new(),
            tcp_analysis_duplicate_ack: String::new(),
            tcp_analysis_duplicate_ack_frame: String::new(),
            tcp_analysis_duplicate_ack_num: String::new(),
            tcp_analysis_fast_retransmission: String::new(),
            tcp_analysis_flags: String::new(),
            tcp_analysis_initial_rtt: String::new(),
            tcp_analysis_keep_alive: String::new(),
            tcp_analysis_keep_alive_ack: String::new(),
            tcp_analysis_lost_segment: String::new(),
            tcp_analysis_out_of_order: String::new(),
            tcp_analysis_push_bytes_sent: String::new(),
            tcp_analysis_retransmission: String::new(),
            tcp_analysis_reused_ports: String::new(),
            tcp_analysis_rto: String::new(),
            tcp_analysis_rto_frame: String::new(),
            tcp_analysis_spurious_retransmission: String::new(),
            tcp_analysis_tfo_ack: String::new(),
            tcp_analysis_tfo_ignored: String::new(),
            tcp_analysis_tfo_syn: String::new(),
            tcp_analysis_window_full: String::new(),
            tcp_analysis_window_update: String::new(),
            tcp_analysis_zero_window: String::new(),
            tcp_analysis_zero_window_probe: String::new(),
            tcp_analysis_zero_window_probe_ack: String::new(),
            tcp_bogus_header_length: String::new(),
            tcp_checksum: String::new(),
            tcp_checksum_ffff: String::new(),
            tcp_checksum_status: String::new(),
            tcp_checksum_bad: String::new(),
            tcp_checksum_bad_expert: String::new(),
            tcp_checksum_calculated: String::new(),
            tcp_checksum_good: String::new(),
            tcp_completeness: String::new(),
            tcp_connection_fin: String::new(),
            tcp_connection_fin_active: String::new(),
            tcp_connection_fin_passive: String::new(),
            tcp_connection_rst: String::new(),
            tcp_connection_sack: String::new(),
            tcp_connection_syn: String::new(),
            tcp_connection_synack: String::new(),
            tcp_continuation_to: String::new(),
            tcp_data: String::new(),
            tcp_dstport: String::new(),
            tcp_fin_retransmission: String::new(),
            tcp_flags: String::new(),
            tcp_flags_ace: String::new(),
            tcp_flags_ack: String::new(),
            tcp_flags_ae: String::new(),
            tcp_flags_cwr: String::new(),
            tcp_flags_ece: String::new(),
            tcp_flags_ecn: String::new(),
            tcp_flags_fin: String::new(),
            tcp_flags_ns: String::new(),
            tcp_flags_push: String::new(),
            tcp_flags_res: String::new(),
            tcp_flags_reset: String::new(),
            tcp_flags_str: String::new(),
            tcp_flags_syn: String::new(),
            tcp_flags_urg: String::new(),
            tcp_hdr_len: String::new(),
            tcp_len: String::new(),
            tcp_non_zero_bytes_after_eol: String::new(),
            tcp_nop: String::new(),
            tcp_nxtseq: String::new(),
            tcp_option_len_invalid: String::new(),
            tcp_option_kind: String::new(),
            tcp_option_len: String::new(),
            tcp_options: String::new(),
            tcp_options_acc_ecn_eceb: String::new(),
            tcp_options_acc_ecn_ee0b: String::new(),
            tcp_options_acc_ecn_ee1b: String::new(),
            tcp_options_ao_keyid: String::new(),
            tcp_options_ao_mac: String::new(),
            tcp_options_ao_rnextkeyid: String::new(),
            tcp_options_cc: String::new(),
            tcp_options_cc_value: String::new(),
            tcp_options_ccecho: String::new(),
            tcp_options_ccnew: String::new(),
            tcp_options_echo: String::new(),
            tcp_options_echo_reply: String::new(),
            tcp_options_echo_value: String::new(),
            tcp_options_experimental: String::new(),
            tcp_options_experimental_data: String::new(),
            tcp_options_experimental_exid: String::new(),
            tcp_options_experimental_magic_number: String::new(),
            tcp_options_md5: String::new(),
            tcp_options_md5_digest: String::new(),
            tcp_options_mood: String::new(),
            tcp_options_mood_val: String::new(),
            tcp_options_mptcp_addaddrtrunchmac: String::new(),
            tcp_options_mptcp_addrid: String::new(),
            tcp_options_mptcp_backup_flag: String::new(),
            tcp_options_mptcp_checksum: String::new(),
            tcp_options_mptcp_checksumreq_flags: String::new(),
            tcp_options_mptcp_dataack: String::new(),
            tcp_options_mptcp_dataack8_flag: String::new(),
            tcp_options_mptcp_dataackpresent_flag: String::new(),
            tcp_options_mptcp_datafin_flag: String::new(),
            tcp_options_mptcp_datalvllen: String::new(),
            tcp_options_mptcp_dataseqno: String::new(),
            tcp_options_mptcp_dseqn8_flag: String::new(),
            tcp_options_mptcp_dseqnpresent_flag: String::new(),
            tcp_options_mptcp_echo: String::new(),
            tcp_options_mptcp_extensibility_flag: String::new(),
            tcp_options_mptcp_flag_t_flag: String::new(),
            tcp_options_mptcp_flag_u_flag: String::new(),
            tcp_options_mptcp_flag_v_flag: String::new(),
            tcp_options_mptcp_flag_w_flag: String::new(),
            tcp_options_mptcp_flags: String::new(),
            tcp_options_mptcp_ipv4: String::new(),
            tcp_options_mptcp_ipv6: String::new(),
            tcp_options_mptcp_ipver: String::new(),
            tcp_options_mptcp_nomoresubflows_flag: String::new(),
            tcp_options_mptcp_port: String::new(),
            tcp_options_mptcp_rawdataack: String::new(),
            tcp_options_mptcp_rawdataseqno: String::new(),
            tcp_options_mptcp_recvkey: String::new(),
            tcp_options_mptcp_recvtok: String::new(),
            tcp_options_mptcp_reserved: String::new(),
            tcp_options_mptcp_reserved_flag: String::new(),
            tcp_options_mptcp_rst_reason: String::new(),
            tcp_options_mptcp_sendhmac: String::new(),
            tcp_options_mptcp_sendkey: String::new(),
            tcp_options_mptcp_sendmac: String::new(),
            tcp_options_mptcp_sendrand: String::new(),
            tcp_options_mptcp_sendtrunchmac: String::new(),
            tcp_options_mptcp_sendtruncmac: String::new(),
            tcp_options_mptcp_sha1_flag: String::new(),
            tcp_options_mptcp_sha256_flag: String::new(),
            tcp_options_mptcp_subflowseqno: String::new(),
            tcp_options_mptcp_subtype: String::new(),
            tcp_options_mptcp_version: String::new(),
            tcp_options_mss: String::new(),
            tcp_options_mss_absent: String::new(),
            tcp_options_mss_present: String::new(),
            tcp_options_mss_val: String::new(),
            tcp_options_qs: String::new(),
            tcp_options_qs_rate: String::new(),
            tcp_options_qs_ttl_diff: String::new(),
            tcp_options_rvbd_probe: String::new(),
            tcp_options_rvbd_probe_appli_ver: String::new(),
            tcp_options_rvbd_probe_client_ip: String::new(),
            tcp_options_rvbd_probe_flags: String::new(),
            tcp_options_rvbd_probe_flags_last: String::new(),
            tcp_options_rvbd_probe_flags_notcfe: String::new(),
            tcp_options_rvbd_probe_flags_probe: String::new(),
            tcp_options_rvbd_probe_flags_server: String::new(),
            tcp_options_rvbd_probe_flags_ssl: String::new(),
            tcp_options_rvbd_probe_len: String::new(),
            tcp_options_rvbd_probe_prober: String::new(),
            tcp_options_rvbd_probe_proxy_ip: String::new(),
            tcp_options_rvbd_probe_proxy_port: String::new(),
            tcp_options_rvbd_probe_reserved: String::new(),
            tcp_options_rvbd_probe_storeid: String::new(),
            tcp_options_rvbd_probe_type1: String::new(),
            tcp_options_rvbd_probe_type2: String::new(),
            tcp_options_rvbd_probe_version: String::new(),
            tcp_options_rvbd_probe_version_raw: String::new(),
            tcp_options_rvbd_trpy: String::new(),
            tcp_options_rvbd_trpy_client_port: String::new(),
            tcp_options_rvbd_trpy_dst_ip: String::new(),
            tcp_options_rvbd_trpy_dst_port: String::new(),
            tcp_options_rvbd_trpy_flags: String::new(),
            tcp_options_rvbd_trpy_flags_chksum: String::new(),
            tcp_options_rvbd_trpy_flags_fw_rst: String::new(),
            tcp_options_rvbd_trpy_flags_fw_rst_inner: String::new(),
            tcp_options_rvbd_trpy_flags_fw_rst_probe: String::new(),
            tcp_options_rvbd_trpy_flags_mode: String::new(),
            tcp_options_rvbd_trpy_flags_oob: String::new(),
            tcp_options_rvbd_trpy_src_ip: String::new(),
            tcp_options_rvbd_trpy_src_port: String::new(),
            tcp_options_sack: String::new(),
            tcp_options_sack_count: String::new(),
            tcp_options_sack_dsack: String::new(),
            tcp_options_sack_dsack_le: String::new(),
            tcp_options_sack_dsack_re: String::new(),
            tcp_options_sack_le: String::new(),
            tcp_options_sack_perm: String::new(),
            tcp_options_sack_re: String::new(),
            tcp_options_scps: String::new(),
            tcp_options_scps_binding: String::new(),
            tcp_options_scps_binding_data: String::new(),
            tcp_options_scps_binding_id: String::new(),
            tcp_options_scps_binding_len: String::new(),
            tcp_options_scps_vector: String::new(),
            tcp_options_scpsflags_bets: String::new(),
            tcp_options_scpsflags_compress: String::new(),
            tcp_options_scpsflags_nlts: String::new(),
            tcp_options_scpsflags_reserved: String::new(),
            tcp_options_scpsflags_reserved1: String::new(),
            tcp_options_scpsflags_reserved2: String::new(),
            tcp_options_scpsflags_reserved3: String::new(),
            tcp_options_scpsflags_snack1: String::new(),
            tcp_options_scpsflags_snack2: String::new(),
            tcp_options_snack: String::new(),
            tcp_options_snack_le: String::new(),
            tcp_options_snack_offset: String::new(),
            tcp_options_snack_re: String::new(),
            tcp_options_snack_sequence: String::new(),
            tcp_options_snack_size: String::new(),
            tcp_options_tar_reserved: String::new(),
            tcp_options_tarr_rate: String::new(),
            tcp_options_tfo: String::new(),
            tcp_options_tfo_cookie: String::new(),
            tcp_options_tfo_request: String::new(),
            tcp_options_time_stamp: String::new(),
            tcp_options_timestamp_tsecr: String::new(),
            tcp_options_timestamp_tsval: String::new(),
            tcp_options_timestamp_tsval_syncookie_ecn: String::new(),
            tcp_options_timestamp_tsval_syncookie_sack: String::new(),
            tcp_options_timestamp_tsval_syncookie_timestamp: String::new(),
            tcp_options_timestamp_tsval_syncookie_wscale: String::new(),
            tcp_options_type: String::new(),
            tcp_options_type_class: String::new(),
            tcp_options_type_copy: String::new(),
            tcp_options_type_number: String::new(),
            tcp_options_unknown_payload: String::new(),
            tcp_options_user_to: String::new(),
            tcp_options_user_to_granularity: String::new(),
            tcp_options_user_to_val: String::new(),
            tcp_options_wscale: String::new(),
            tcp_options_wscale_multiplier: String::new(),
            tcp_options_wscale_shift: String::new(),
            tcp_options_wscale_shift_invalid: String::new(),
            tcp_options_wscale_val: String::new(),
            tcp_payload: String::new(),
            tcp_pdu_last_frame: String::new(),
            tcp_pdu_size: String::new(),
            tcp_pdu_time: String::new(),
            tcp_port: String::new(),
            tcp_proc_dstcmd: String::new(),
            tcp_proc_dstpid: String::new(),
            tcp_proc_dstuid: String::new(),
            tcp_proc_dstuname: String::new(),
            tcp_proc_srccmd: String::new(),
            tcp_proc_srcpid: String::new(),
            tcp_proc_srcuid: String::new(),
            tcp_proc_srcuname: String::new(),
            tcp_reassembled_data: String::new(),
            tcp_reassembled_length: String::new(),
            tcp_reassembled_in: String::new(),
            tcp_reset_cause: String::new(),
            tcp_segment: String::new(),
            tcp_segment_count: String::new(),
            tcp_segment_error: String::new(),
            tcp_segment_multipletails: String::new(),
            tcp_segment_overlap: String::new(),
            tcp_segment_overlap_conflict: String::new(),
            tcp_segment_toolongfragment: String::new(),
            tcp_segment_data: String::new(),
            tcp_segments: String::new(),
            tcp_seq: String::new(),
            tcp_seq_raw: String::new(),
            tcp_short_segment: String::new(),
            tcp_srcport: String::new(),
            tcp_stream: String::new(),
            tcp_suboption_malformed: String::new(),
            tcp_syncookie_hash: String::new(),
            tcp_syncookie_mss: String::new(),
            tcp_syncookie_time: String::new(),
            tcp_time_delta: String::new(),
            tcp_time_relative: String::new(),
            tcp_urgent_pointer: String::new(),
            tcp_urgent_pointer_non_zero: String::new(),
            tcp_window_size: String::new(),
            tcp_window_size_scalefactor: String::new(),
            tcp_window_size_value: String::new(),
        }
    }

    /// Update the TCP layer with a new value
    ///
    /// This function maps the Wireshark/TShark field name to the corresponding
    /// TCP layer field name in the struct.
    pub fn update(&mut self, field: &str, value: &str) {
        match field {
            "mptcp.analysis.echoed_key_mismatch" => {
                self.mptcp_analysis_echoed_key_mismatch = value.to_string()
            }
            "mptcp.analysis.missing_algorithm" => {
                self.mptcp_analysis_missing_algorithm = value.to_string()
            }
            "mptcp.analysis.unexpected_idsn" => {
                self.mptcp_analysis_unexpected_idsn = value.to_string()
            }
            "mptcp.analysis.unsupported_algorithm" => {
                self.mptcp_analysis_unsupported_algorithm = value.to_string()
            }
            "mptcp.connection.echoed_key_mismatch" => {
                self.mptcp_connection_echoed_key_mismatch = value.to_string()
            }
            "mptcp.connection.missing_algorithm" => {
                self.mptcp_connection_missing_algorithm = value.to_string()
            }
            "mptcp.connection.unsupported_algorithm" => {
                self.mptcp_connection_unsupported_algorithm = value.to_string()
            }
            "mptcp.dss.infinite_mapping" => self.mptcp_dss_infinite_mapping = value.to_string(),
            "mptcp.dss.missing_mapping" => self.mptcp_dss_missing_mapping = value.to_string(),
            "tcp.ack" => self.tcp_ack = value.to_string(),
            "tcp.ack.nonzero" => self.tcp_ack_nonzero = value.to_string(),
            "tcp.ack_raw" => self.tcp_ack_raw = value.to_string(),
            "tcp.analysis" => self.tcp_analysis = value.to_string(),
            "tcp.analysis.ack_lost_segment" => {
                self.tcp_analysis_ack_lost_segment = value.to_string()
            }
            "tcp.analysis.ack_rtt" => self.tcp_analysis_ack_rtt = value.to_string(),
            "tcp.analysis.acks_frame" => self.tcp_analysis_acks_frame = value.to_string(),
            "tcp.analysis.bytes_in_flight" => self.tcp_analysis_bytes_in_flight = value.to_string(),
            "tcp.analysis.duplicate_ack" => self.tcp_analysis_duplicate_ack = value.to_string(),
            "tcp.analysis.duplicate_ack_frame" => {
                self.tcp_analysis_duplicate_ack_frame = value.to_string()
            }
            "tcp.analysis.duplicate_ack_num" => {
                self.tcp_analysis_duplicate_ack_num = value.to_string()
            }
            "tcp.analysis.fast_retransmission" => {
                self.tcp_analysis_fast_retransmission = value.to_string()
            }
            "tcp.analysis.flags" => self.tcp_analysis_flags = value.to_string(),
            "tcp.analysis.initial_rtt" => self.tcp_analysis_initial_rtt = value.to_string(),
            "tcp.analysis.keep_alive" => self.tcp_analysis_keep_alive = value.to_string(),
            "tcp.analysis.keep_alive_ack" => self.tcp_analysis_keep_alive_ack = value.to_string(),
            "tcp.analysis.lost_segment" => self.tcp_analysis_lost_segment = value.to_string(),
            "tcp.analysis.out_of_order" => self.tcp_analysis_out_of_order = value.to_string(),
            "tcp.analysis.push_bytes_sent" => self.tcp_analysis_push_bytes_sent = value.to_string(),
            "tcp.analysis.retransmission" => self.tcp_analysis_retransmission = value.to_string(),
            "tcp.analysis.reused_ports" => self.tcp_analysis_reused_ports = value.to_string(),
            "tcp.analysis.rto" => self.tcp_analysis_rto = value.to_string(),
            "tcp.analysis.rto_frame" => self.tcp_analysis_rto_frame = value.to_string(),
            "tcp.analysis.spurious_retransmission" => {
                self.tcp_analysis_spurious_retransmission = value.to_string()
            }
            "tcp.analysis.tfo_ack" => self.tcp_analysis_tfo_ack = value.to_string(),
            "tcp.analysis.tfo_ignored" => self.tcp_analysis_tfo_ignored = value.to_string(),
            "tcp.analysis.tfo_syn" => self.tcp_analysis_tfo_syn = value.to_string(),
            "tcp.analysis.window_full" => self.tcp_analysis_window_full = value.to_string(),
            "tcp.analysis.window_update" => self.tcp_analysis_window_update = value.to_string(),
            "tcp.analysis.zero_window" => self.tcp_analysis_zero_window = value.to_string(),
            "tcp.analysis.zero_window_probe" => {
                self.tcp_analysis_zero_window_probe = value.to_string()
            }
            "tcp.analysis.zero_window_probe_ack" => {
                self.tcp_analysis_zero_window_probe_ack = value.to_string()
            }
            "tcp.bogus_header_length" => self.tcp_bogus_header_length = value.to_string(),
            "tcp.checksum" => self.tcp_checksum = value.to_string(),
            "tcp.checksum.ffff" => self.tcp_checksum_ffff = value.to_string(),
            "tcp.checksum.status" => self.tcp_checksum_status = value.to_string(),
            "tcp.checksum_bad" => self.tcp_checksum_bad = value.to_string(),
            "tcp.checksum_bad.expert" => self.tcp_checksum_bad_expert = value.to_string(),
            "tcp.checksum_calculated" => self.tcp_checksum_calculated = value.to_string(),
            "tcp.checksum_good" => self.tcp_checksum_good = value.to_string(),
            "tcp.completeness" => self.tcp_completeness = value.to_string(),
            "tcp.connection.fin" => self.tcp_connection_fin = value.to_string(),
            "tcp.connection.fin_active" => self.tcp_connection_fin_active = value.to_string(),
            "tcp.connection.fin_passive" => self.tcp_connection_fin_passive = value.to_string(),
            "tcp.connection.rst" => self.tcp_connection_rst = value.to_string(),
            "tcp.connection.sack" => self.tcp_connection_sack = value.to_string(),
            "tcp.connection.syn" => self.tcp_connection_syn = value.to_string(),
            "tcp.connection.synack" => self.tcp_connection_synack = value.to_string(),
            "tcp.continuation_to" => self.tcp_continuation_to = value.to_string(),
            "tcp.data" => self.tcp_data = value.to_string(),
            "tcp.dstport" => self.tcp_dstport = value.to_string(),
            "tcp.fin_retransmission" => self.tcp_fin_retransmission = value.to_string(),
            "tcp.flags" => self.tcp_flags = value.to_string(),
            "tcp.flags.ace" => self.tcp_flags_ace = value.to_string(),
            "tcp.flags.ack" => self.tcp_flags_ack = value.to_string(),
            "tcp.flags.ae" => self.tcp_flags_ae = value.to_string(),
            "tcp.flags.cwr" => self.tcp_flags_cwr = value.to_string(),
            "tcp.flags.ece" => self.tcp_flags_ece = value.to_string(),
            "tcp.flags.ecn" => self.tcp_flags_ecn = value.to_string(),
            "tcp.flags.fin" => self.tcp_flags_fin = value.to_string(),
            "tcp.flags.ns" => self.tcp_flags_ns = value.to_string(),
            "tcp.flags.push" => self.tcp_flags_push = value.to_string(),
            "tcp.flags.res" => self.tcp_flags_res = value.to_string(),
            "tcp.flags.reset" => self.tcp_flags_reset = value.to_string(),
            "tcp.flags.str" => self.tcp_flags_str = value.to_string(),
            "tcp.flags.syn" => self.tcp_flags_syn = value.to_string(),
            "tcp.flags.urg" => self.tcp_flags_urg = value.to_string(),
            "tcp.hdr_len" => self.tcp_hdr_len = value.to_string(),
            "tcp.len" => self.tcp_len = value.to_string(),
            "tcp.non_zero_bytes_after_eol" => self.tcp_non_zero_bytes_after_eol = value.to_string(),
            "tcp.nop" => self.tcp_nop = value.to_string(),
            "tcp.nxtseq" => self.tcp_nxtseq = value.to_string(),
            "tcp.option.len.invalid" => self.tcp_option_len_invalid = value.to_string(),
            "tcp.option_kind" => self.tcp_option_kind = value.to_string(),
            "tcp.option_len" => self.tcp_option_len = value.to_string(),
            "tcp.options" => self.tcp_options = value.to_string(),
            "tcp.options.acc_ecn.eceb" => self.tcp_options_acc_ecn_eceb = value.to_string(),
            "tcp.options.acc_ecn.ee0b" => self.tcp_options_acc_ecn_ee0b = value.to_string(),
            "tcp.options.acc_ecn.ee1b" => self.tcp_options_acc_ecn_ee1b = value.to_string(),
            "tcp.options.ao.keyid" => self.tcp_options_ao_keyid = value.to_string(),
            "tcp.options.ao.mac" => self.tcp_options_ao_mac = value.to_string(),
            "tcp.options.ao.rnextkeyid" => self.tcp_options_ao_rnextkeyid = value.to_string(),
            "tcp.options.cc" => self.tcp_options_cc = value.to_string(),
            "tcp.options.cc_value" => self.tcp_options_cc_value = value.to_string(),
            "tcp.options.ccecho" => self.tcp_options_ccecho = value.to_string(),
            "tcp.options.ccnew" => self.tcp_options_ccnew = value.to_string(),
            "tcp.options.echo" => self.tcp_options_echo = value.to_string(),
            "tcp.options.echo_reply" => self.tcp_options_echo_reply = value.to_string(),
            "tcp.options.echo_value" => self.tcp_options_echo_value = value.to_string(),
            "tcp.options.experimental" => self.tcp_options_experimental = value.to_string(),
            "tcp.options.experimental.data" => {
                self.tcp_options_experimental_data = value.to_string()
            }
            "tcp.options.experimental.exid" => {
                self.tcp_options_experimental_exid = value.to_string()
            }
            "tcp.options.experimental.magic_number" => {
                self.tcp_options_experimental_magic_number = value.to_string()
            }
            "tcp.options.md5" => self.tcp_options_md5 = value.to_string(),
            "tcp.options.md5.digest" => self.tcp_options_md5_digest = value.to_string(),
            "tcp.options.mood" => self.tcp_options_mood = value.to_string(),
            "tcp.options.mood_val" => self.tcp_options_mood_val = value.to_string(),
            "tcp.options.mptcp.addaddrtrunchmac" => {
                self.tcp_options_mptcp_addaddrtrunchmac = value.to_string()
            }
            "tcp.options.mptcp.addrid" => self.tcp_options_mptcp_addrid = value.to_string(),
            "tcp.options.mptcp.backup.flag" => {
                self.tcp_options_mptcp_backup_flag = value.to_string()
            }
            "tcp.options.mptcp.checksum" => self.tcp_options_mptcp_checksum = value.to_string(),
            "tcp.options.mptcp.checksumreq.flags" => {
                self.tcp_options_mptcp_checksumreq_flags = value.to_string()
            }
            "tcp.options.mptcp.dataack" => self.tcp_options_mptcp_dataack = value.to_string(),
            "tcp.options.mptcp.dataack8.flag" => {
                self.tcp_options_mptcp_dataack8_flag = value.to_string()
            }
            "tcp.options.mptcp.dataackpresent.flag" => {
                self.tcp_options_mptcp_dataackpresent_flag = value.to_string()
            }
            "tcp.options.mptcp.datafin.flag" => {
                self.tcp_options_mptcp_datafin_flag = value.to_string()
            }
            "tcp.options.mptcp.datalvllen" => self.tcp_options_mptcp_datalvllen = value.to_string(),
            "tcp.options.mptcp.dataseqno" => self.tcp_options_mptcp_dataseqno = value.to_string(),
            "tcp.options.mptcp.dseqn8.flag" => {
                self.tcp_options_mptcp_dseqn8_flag = value.to_string()
            }
            "tcp.options.mptcp.dseqnpresent.flag" => {
                self.tcp_options_mptcp_dseqnpresent_flag = value.to_string()
            }
            "tcp.options.mptcp.echo" => self.tcp_options_mptcp_echo = value.to_string(),
            "tcp.options.mptcp.extensibility.flag" => {
                self.tcp_options_mptcp_extensibility_flag = value.to_string()
            }
            "tcp.options.mptcp.flag_T.flag" => {
                self.tcp_options_mptcp_flag_t_flag = value.to_string()
            }
            "tcp.options.mptcp.flag_U.flag" => {
                self.tcp_options_mptcp_flag_u_flag = value.to_string()
            }
            "tcp.options.mptcp.flag_V.flag" => {
                self.tcp_options_mptcp_flag_v_flag = value.to_string()
            }
            "tcp.options.mptcp.flag_W.flag" => {
                self.tcp_options_mptcp_flag_w_flag = value.to_string()
            }
            "tcp.options.mptcp.flags" => self.tcp_options_mptcp_flags = value.to_string(),
            "tcp.options.mptcp.ipv4" => self.tcp_options_mptcp_ipv4 = value.to_string(),
            "tcp.options.mptcp.ipv6" => self.tcp_options_mptcp_ipv6 = value.to_string(),
            "tcp.options.mptcp.ipver" => self.tcp_options_mptcp_ipver = value.to_string(),
            "tcp.options.mptcp.nomoresubflows.flag" => {
                self.tcp_options_mptcp_nomoresubflows_flag = value.to_string()
            }
            "tcp.options.mptcp.port" => self.tcp_options_mptcp_port = value.to_string(),
            "tcp.options.mptcp.rawdataack" => self.tcp_options_mptcp_rawdataack = value.to_string(),
            "tcp.options.mptcp.rawdataseqno" => {
                self.tcp_options_mptcp_rawdataseqno = value.to_string()
            }
            "tcp.options.mptcp.recvkey" => self.tcp_options_mptcp_recvkey = value.to_string(),
            "tcp.options.mptcp.recvtok" => self.tcp_options_mptcp_recvtok = value.to_string(),
            "tcp.options.mptcp.reserved" => self.tcp_options_mptcp_reserved = value.to_string(),
            "tcp.options.mptcp.reserved.flag" => {
                self.tcp_options_mptcp_reserved_flag = value.to_string()
            }
            "tcp.options.mptcp.rst_reason" => self.tcp_options_mptcp_rst_reason = value.to_string(),
            "tcp.options.mptcp.sendhmac" => self.tcp_options_mptcp_sendhmac = value.to_string(),
            "tcp.options.mptcp.sendkey" => self.tcp_options_mptcp_sendkey = value.to_string(),
            "tcp.options.mptcp.sendmac" => self.tcp_options_mptcp_sendmac = value.to_string(),
            "tcp.options.mptcp.sendrand" => self.tcp_options_mptcp_sendrand = value.to_string(),
            "tcp.options.mptcp.sendtrunchmac" => {
                self.tcp_options_mptcp_sendtrunchmac = value.to_string()
            }
            "tcp.options.mptcp.sendtruncmac" => {
                self.tcp_options_mptcp_sendtruncmac = value.to_string()
            }
            "tcp.options.mptcp.sha1.flag" => self.tcp_options_mptcp_sha1_flag = value.to_string(),
            "tcp.options.mptcp.sha256.flag" => {
                self.tcp_options_mptcp_sha256_flag = value.to_string()
            }
            "tcp.options.mptcp.subflowseqno" => {
                self.tcp_options_mptcp_subflowseqno = value.to_string()
            }
            "tcp.options.mptcp.subtype" => self.tcp_options_mptcp_subtype = value.to_string(),
            "tcp.options.mptcp.version" => self.tcp_options_mptcp_version = value.to_string(),
            "tcp.options.mss" => self.tcp_options_mss = value.to_string(),
            "tcp.options.mss.absent" => self.tcp_options_mss_absent = value.to_string(),
            "tcp.options.mss.present" => self.tcp_options_mss_present = value.to_string(),
            "tcp.options.mss_val" => self.tcp_options_mss_val = value.to_string(),
            "tcp.options.qs" => self.tcp_options_qs = value.to_string(),
            "tcp.options.qs.rate" => self.tcp_options_qs_rate = value.to_string(),
            "tcp.options.qs.ttl_diff" => self.tcp_options_qs_ttl_diff = value.to_string(),
            "tcp.options.rvbd.probe" => self.tcp_options_rvbd_probe = value.to_string(),
            "tcp.options.rvbd.probe.appli_ver" => {
                self.tcp_options_rvbd_probe_appli_ver = value.to_string()
            }
            "tcp.options.rvbd.probe.client.ip" => {
                self.tcp_options_rvbd_probe_client_ip = value.to_string()
            }
            "tcp.options.rvbd.probe.flags" => self.tcp_options_rvbd_probe_flags = value.to_string(),
            "tcp.options.rvbd.probe.flags.last" => {
                self.tcp_options_rvbd_probe_flags_last = value.to_string()
            }
            "tcp.options.rvbd.probe.flags.notcfe" => {
                self.tcp_options_rvbd_probe_flags_notcfe = value.to_string()
            }
            "tcp.options.rvbd.probe.flags.probe" => {
                self.tcp_options_rvbd_probe_flags_probe = value.to_string()
            }
            "tcp.options.rvbd.probe.flags.server" => {
                self.tcp_options_rvbd_probe_flags_server = value.to_string()
            }
            "tcp.options.rvbd.probe.flags.ssl" => {
                self.tcp_options_rvbd_probe_flags_ssl = value.to_string()
            }
            "tcp.options.rvbd.probe.len" => self.tcp_options_rvbd_probe_len = value.to_string(),
            "tcp.options.rvbd.probe.prober" => {
                self.tcp_options_rvbd_probe_prober = value.to_string()
            }
            "tcp.options.rvbd.probe.proxy.ip" => {
                self.tcp_options_rvbd_probe_proxy_ip = value.to_string()
            }
            "tcp.options.rvbd.probe.proxy.port" => {
                self.tcp_options_rvbd_probe_proxy_port = value.to_string()
            }
            "tcp.options.rvbd.probe.reserved" => {
                self.tcp_options_rvbd_probe_reserved = value.to_string()
            }
            "tcp.options.rvbd.probe.storeid" => {
                self.tcp_options_rvbd_probe_storeid = value.to_string()
            }
            "tcp.options.rvbd.probe.type1" => self.tcp_options_rvbd_probe_type1 = value.to_string(),
            "tcp.options.rvbd.probe.type2" => self.tcp_options_rvbd_probe_type2 = value.to_string(),
            "tcp.options.rvbd.probe.version" => {
                self.tcp_options_rvbd_probe_version = value.to_string()
            }
            "tcp.options.rvbd.probe.version_raw" => {
                self.tcp_options_rvbd_probe_version_raw = value.to_string()
            }
            "tcp.options.rvbd.trpy" => self.tcp_options_rvbd_trpy = value.to_string(),
            "tcp.options.rvbd.trpy.client.port" => {
                self.tcp_options_rvbd_trpy_client_port = value.to_string()
            }
            "tcp.options.rvbd.trpy.dst.ip" => self.tcp_options_rvbd_trpy_dst_ip = value.to_string(),
            "tcp.options.rvbd.trpy.dst.port" => {
                self.tcp_options_rvbd_trpy_dst_port = value.to_string()
            }
            "tcp.options.rvbd.trpy.flags" => self.tcp_options_rvbd_trpy_flags = value.to_string(),
            "tcp.options.rvbd.trpy.flags.chksum" => {
                self.tcp_options_rvbd_trpy_flags_chksum = value.to_string()
            }
            "tcp.options.rvbd.trpy.flags.fw_rst" => {
                self.tcp_options_rvbd_trpy_flags_fw_rst = value.to_string()
            }
            "tcp.options.rvbd.trpy.flags.fw_rst_inner" => {
                self.tcp_options_rvbd_trpy_flags_fw_rst_inner = value.to_string()
            }
            "tcp.options.rvbd.trpy.flags.fw_rst_probe" => {
                self.tcp_options_rvbd_trpy_flags_fw_rst_probe = value.to_string()
            }
            "tcp.options.rvbd.trpy.flags.mode" => {
                self.tcp_options_rvbd_trpy_flags_mode = value.to_string()
            }
            "tcp.options.rvbd.trpy.flags.oob" => {
                self.tcp_options_rvbd_trpy_flags_oob = value.to_string()
            }
            "tcp.options.rvbd.trpy.src.ip" => self.tcp_options_rvbd_trpy_src_ip = value.to_string(),
            "tcp.options.rvbd.trpy.src.port" => {
                self.tcp_options_rvbd_trpy_src_port = value.to_string()
            }
            "tcp.options.sack" => self.tcp_options_sack = value.to_string(),
            "tcp.options.sack.count" => self.tcp_options_sack_count = value.to_string(),
            "tcp.options.sack.dsack" => self.tcp_options_sack_dsack = value.to_string(),
            "tcp.options.sack.dsack_le" => self.tcp_options_sack_dsack_le = value.to_string(),
            "tcp.options.sack.dsack_re" => self.tcp_options_sack_dsack_re = value.to_string(),
            "tcp.options.sack_le" => self.tcp_options_sack_le = value.to_string(),
            "tcp.options.sack_perm" => self.tcp_options_sack_perm = value.to_string(),
            "tcp.options.sack_re" => self.tcp_options_sack_re = value.to_string(),
            "tcp.options.scps" => self.tcp_options_scps = value.to_string(),
            "tcp.options.scps.binding" => self.tcp_options_scps_binding = value.to_string(),
            "tcp.options.scps.binding.data" => {
                self.tcp_options_scps_binding_data = value.to_string()
            }
            "tcp.options.scps.binding.id" => self.tcp_options_scps_binding_id = value.to_string(),
            "tcp.options.scps.binding.len" => self.tcp_options_scps_binding_len = value.to_string(),
            "tcp.options.scps.vector" => self.tcp_options_scps_vector = value.to_string(),
            "tcp.options.scpsflags.bets" => self.tcp_options_scpsflags_bets = value.to_string(),
            "tcp.options.scpsflags.compress" => {
                self.tcp_options_scpsflags_compress = value.to_string()
            }
            "tcp.options.scpsflags.nlts" => self.tcp_options_scpsflags_nlts = value.to_string(),
            "tcp.options.scpsflags.reserved" => {
                self.tcp_options_scpsflags_reserved = value.to_string()
            }
            "tcp.options.scpsflags.reserved1" => {
                self.tcp_options_scpsflags_reserved1 = value.to_string()
            }
            "tcp.options.scpsflags.reserved2" => {
                self.tcp_options_scpsflags_reserved2 = value.to_string()
            }
            "tcp.options.scpsflags.reserved3" => {
                self.tcp_options_scpsflags_reserved3 = value.to_string()
            }
            "tcp.options.scpsflags.snack1" => self.tcp_options_scpsflags_snack1 = value.to_string(),
            "tcp.options.scpsflags.snack2" => self.tcp_options_scpsflags_snack2 = value.to_string(),
            "tcp.options.snack" => self.tcp_options_snack = value.to_string(),
            "tcp.options.snack.le" => self.tcp_options_snack_le = value.to_string(),
            "tcp.options.snack.offset" => self.tcp_options_snack_offset = value.to_string(),
            "tcp.options.snack.re" => self.tcp_options_snack_re = value.to_string(),
            "tcp.options.snack.sequence" => self.tcp_options_snack_sequence = value.to_string(),
            "tcp.options.snack.size" => self.tcp_options_snack_size = value.to_string(),
            "tcp.options.tar.reserved" => self.tcp_options_tar_reserved = value.to_string(),
            "tcp.options.tarr.rate" => self.tcp_options_tarr_rate = value.to_string(),
            "tcp.options.tfo" => self.tcp_options_tfo = value.to_string(),
            "tcp.options.tfo.cookie" => self.tcp_options_tfo_cookie = value.to_string(),
            "tcp.options.tfo.request" => self.tcp_options_tfo_request = value.to_string(),
            "tcp.options.time_stamp" => self.tcp_options_time_stamp = value.to_string(),
            "tcp.options.timestamp.tsecr" => self.tcp_options_timestamp_tsecr = value.to_string(),
            "tcp.options.timestamp.tsval" => self.tcp_options_timestamp_tsval = value.to_string(),
            "tcp.options.timestamp.tsval.syncookie.ecn" => {
                self.tcp_options_timestamp_tsval_syncookie_ecn = value.to_string()
            }
            "tcp.options.timestamp.tsval.syncookie.sack" => {
                self.tcp_options_timestamp_tsval_syncookie_sack = value.to_string()
            }
            "tcp.options.timestamp.tsval.syncookie.timestamp" => {
                self.tcp_options_timestamp_tsval_syncookie_timestamp = value.to_string()
            }
            "tcp.options.timestamp.tsval.syncookie.wscale" => {
                self.tcp_options_timestamp_tsval_syncookie_wscale = value.to_string()
            }
            "tcp.options.type" => self.tcp_options_type = value.to_string(),
            "tcp.options.type.class" => self.tcp_options_type_class = value.to_string(),
            "tcp.options.type.copy" => self.tcp_options_type_copy = value.to_string(),
            "tcp.options.type.number" => self.tcp_options_type_number = value.to_string(),
            "tcp.options.unknown.payload" => self.tcp_options_unknown_payload = value.to_string(),
            "tcp.options.user_to" => self.tcp_options_user_to = value.to_string(),
            "tcp.options.user_to_granularity" => {
                self.tcp_options_user_to_granularity = value.to_string()
            }
            "tcp.options.user_to_val" => self.tcp_options_user_to_val = value.to_string(),
            "tcp.options.wscale" => self.tcp_options_wscale = value.to_string(),
            "tcp.options.wscale.multiplier" => {
                self.tcp_options_wscale_multiplier = value.to_string()
            }
            "tcp.options.wscale.shift" => self.tcp_options_wscale_shift = value.to_string(),
            "tcp.options.wscale.shift.invalid" => {
                self.tcp_options_wscale_shift_invalid = value.to_string()
            }
            "tcp.options.wscale_val" => self.tcp_options_wscale_val = value.to_string(),
            "tcp.payload" => self.tcp_payload = value.to_string(),
            "tcp.pdu.last_frame" => self.tcp_pdu_last_frame = value.to_string(),
            "tcp.pdu.size" => self.tcp_pdu_size = value.to_string(),
            "tcp.pdu.time" => self.tcp_pdu_time = value.to_string(),
            "tcp.port" => self.tcp_port = value.to_string(),
            "tcp.proc.dstcmd" => self.tcp_proc_dstcmd = value.to_string(),
            "tcp.proc.dstpid" => self.tcp_proc_dstpid = value.to_string(),
            "tcp.proc.dstuid" => self.tcp_proc_dstuid = value.to_string(),
            "tcp.proc.dstuname" => self.tcp_proc_dstuname = value.to_string(),
            "tcp.proc.srccmd" => self.tcp_proc_srccmd = value.to_string(),
            "tcp.proc.srcpid" => self.tcp_proc_srcpid = value.to_string(),
            "tcp.proc.srcuid" => self.tcp_proc_srcuid = value.to_string(),
            "tcp.proc.srcuname" => self.tcp_proc_srcuname = value.to_string(),
            "tcp.reassembled.data" => self.tcp_reassembled_data = value.to_string(),
            "tcp.reassembled.length" => self.tcp_reassembled_length = value.to_string(),
            "tcp.reassembled_in" => self.tcp_reassembled_in = value.to_string(),
            "tcp.reset_cause" => self.tcp_reset_cause = value.to_string(),
            "tcp.segment" => self.tcp_segment = value.to_string(),
            "tcp.segment.count" => self.tcp_segment_count = value.to_string(),
            "tcp.segment.error" => self.tcp_segment_error = value.to_string(),
            "tcp.segment.multipletails" => self.tcp_segment_multipletails = value.to_string(),
            "tcp.segment.overlap" => self.tcp_segment_overlap = value.to_string(),
            "tcp.segment.overlap.conflict" => self.tcp_segment_overlap_conflict = value.to_string(),
            "tcp.segment.toolongfragment" => self.tcp_segment_toolongfragment = value.to_string(),
            "tcp.segment_data" => self.tcp_segment_data = value.to_string(),
            "tcp.segments" => self.tcp_segments = value.to_string(),
            "tcp.seq" => self.tcp_seq = value.to_string(),
            "tcp.seq_raw" => self.tcp_seq_raw = value.to_string(),
            "tcp.short_segment" => self.tcp_short_segment = value.to_string(),
            "tcp.srcport" => self.tcp_srcport = value.to_string(),
            "tcp.stream" => self.tcp_stream = value.to_string(),
            "tcp.suboption_malformed" => self.tcp_suboption_malformed = value.to_string(),
            "tcp.syncookie.hash" => self.tcp_syncookie_hash = value.to_string(),
            "tcp.syncookie.mss" => self.tcp_syncookie_mss = value.to_string(),
            "tcp.syncookie.time" => self.tcp_syncookie_time = value.to_string(),
            "tcp.time_delta" => self.tcp_time_delta = value.to_string(),
            "tcp.time_relative" => self.tcp_time_relative = value.to_string(),
            "tcp.urgent_pointer" => self.tcp_urgent_pointer = value.to_string(),
            "tcp.urgent_pointer.non_zero" => self.tcp_urgent_pointer_non_zero = value.to_string(),
            "tcp.window_size" => self.tcp_window_size = value.to_string(),
            "tcp.window_size_scalefactor" => self.tcp_window_size_scalefactor = value.to_string(),
            "tcp.window_size_value" => self.tcp_window_size_value = value.to_string(),
            &_ => (),
        }
    }

    /// Get the TCP layer header values for the CSV file
    pub fn get_csv_header(delimiter: &str) -> String {
        let mut header = String::new();

        header.push_str(format!("mptcp.analysis.missing_algorithm{}", delimiter).as_str());
        header.push_str(format!("mptcp.analysis.echoed_key_mismatch{}", delimiter).as_str());
        header.push_str(format!("mptcp.analysis.unexpected_idsn{}", delimiter).as_str());
        header.push_str(format!("mptcp.analysis.unsupported_algorithm{}", delimiter).as_str());
        header.push_str(format!("mptcp.connection.echoed_key_mismatch{}", delimiter).as_str());
        header.push_str(format!("mptcp.connection.missing_algorithm{}", delimiter).as_str());
        header.push_str(format!("mptcp.connection.unsupported_algorithm{}", delimiter).as_str());
        header.push_str(format!("mptcp.dss.infinite_mapping{}", delimiter).as_str());
        header.push_str(format!("mptcp.dss.missing_mapping{}", delimiter).as_str());
        header.push_str(format!("tcp.ack{}", delimiter).as_str());
        header.push_str(format!("tcp.ack.nonzero{}", delimiter).as_str());
        header.push_str(format!("tcp.ack_raw{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.ack_lost_segment{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.ack_rtt{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.acks_frame{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.bytes_in_flight{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.duplicate_ack{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.duplicate_ack_frame{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.duplicate_ack_num{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.fast_retransmission{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.flags{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.initial_rtt{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.keep_alive{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.keep_alive_ack{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.lost_segment{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.out_of_order{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.push_bytes_sent{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.retransmission{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.reused_ports{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.rto{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.rto_frame{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.spurious_retransmission{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.tfo_ack{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.tfo_ignored{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.tfo_syn{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.window_full{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.window_update{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.zero_window{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.zero_window_probe{}", delimiter).as_str());
        header.push_str(format!("tcp.analysis.zero_window_probe_ack{}", delimiter).as_str());
        header.push_str(format!("tcp.bogus_header_length{}", delimiter).as_str());
        header.push_str(format!("tcp.checksum{}", delimiter).as_str());
        header.push_str(format!("tcp.checksum.ffff{}", delimiter).as_str());
        header.push_str(format!("tcp.checksum.status{}", delimiter).as_str());
        header.push_str(format!("tcp.checksum_bad{}", delimiter).as_str());
        header.push_str(format!("tcp.checksum_bad.expert{}", delimiter).as_str());
        header.push_str(format!("tcp.checksum_calculated{}", delimiter).as_str());
        header.push_str(format!("tcp.checksum_good{}", delimiter).as_str());
        header.push_str(format!("tcp.completeness{}", delimiter).as_str());
        header.push_str(format!("tcp.connection.fin{}", delimiter).as_str());
        header.push_str(format!("tcp.connection.fin_active{}", delimiter).as_str());
        header.push_str(format!("tcp.connection.fin_passive{}", delimiter).as_str());
        header.push_str(format!("tcp.connection.rst{}", delimiter).as_str());
        header.push_str(format!("tcp.connection.sack{}", delimiter).as_str());
        header.push_str(format!("tcp.connection.syn{}", delimiter).as_str());
        header.push_str(format!("tcp.connection.synack{}", delimiter).as_str());
        header.push_str(format!("tcp.continuation_to{}", delimiter).as_str());
        header.push_str(format!("tcp.data{}", delimiter).as_str());
        header.push_str(format!("tcp.dstport{}", delimiter).as_str());
        header.push_str(format!("tcp.fin_retransmission{}", delimiter).as_str());
        header.push_str(format!("tcp.flags{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.ace{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.ack{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.ae{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.cwr{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.ece{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.ecn{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.fin{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.ns{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.push{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.res{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.reset{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.str{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.syn{}", delimiter).as_str());
        header.push_str(format!("tcp.flags.urg{}", delimiter).as_str());
        header.push_str(format!("tcp.hdr_len{}", delimiter).as_str());
        header.push_str(format!("tcp.len{}", delimiter).as_str());
        header.push_str(format!("tcp.non_zero_bytes_after_eol{}", delimiter).as_str());
        header.push_str(format!("tcp.nop{}", delimiter).as_str());
        header.push_str(format!("tcp.nxtseq{}", delimiter).as_str());
        header.push_str(format!("tcp.option.len.invalid{}", delimiter).as_str());
        header.push_str(format!("tcp.option_kind{}", delimiter).as_str());
        header.push_str(format!("tcp.option_len{}", delimiter).as_str());
        header.push_str(format!("tcp.options{}", delimiter).as_str());
        header.push_str(format!("tcp.options.acc_ecn.eceb{}", delimiter).as_str());
        header.push_str(format!("tcp.options.acc_ecn.ee0b{}", delimiter).as_str());
        header.push_str(format!("tcp.options.acc_ecn.ee1b{}", delimiter).as_str());
        header.push_str(format!("tcp.options.ao.keyid{}", delimiter).as_str());
        header.push_str(format!("tcp.options.ao.mac{}", delimiter).as_str());
        header.push_str(format!("tcp.options.ao.rnextkeyid{}", delimiter).as_str());
        header.push_str(format!("tcp.options.cc{}", delimiter).as_str());
        header.push_str(format!("tcp.options.cc_value{}", delimiter).as_str());
        header.push_str(format!("tcp.options.ccecho{}", delimiter).as_str());
        header.push_str(format!("tcp.options.ccnew{}", delimiter).as_str());
        header.push_str(format!("tcp.options.echo{}", delimiter).as_str());
        header.push_str(format!("tcp.options.echo_reply{}", delimiter).as_str());
        header.push_str(format!("tcp.options.echo_value{}", delimiter).as_str());
        header.push_str(format!("tcp.options.experimental{}", delimiter).as_str());
        header.push_str(format!("tcp.options.experimental.data{}", delimiter).as_str());
        header.push_str(format!("tcp.options.experimental.exid{}", delimiter).as_str());
        header.push_str(format!("tcp.options.experimental.magic_number{}", delimiter).as_str());
        header.push_str(format!("tcp.options.md5{}", delimiter).as_str());
        header.push_str(format!("tcp.options.md5.digest{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mood{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mood_val{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.addaddrtrunchmac{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.addrid{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.backup.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.checksum{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.checksumreq.flags{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.dataack{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.dataack8.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.dataackpresent.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.datafin.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.datalvllen{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.dataseqno{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.dseqn8.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.dseqnpresent.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.echo{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.extensibility.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.flag_T.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.flag_U.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.flag_V.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.flag_W.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.flags{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.ipv4{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.ipv6{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.ipver{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.nomoresubflows.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.port{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.rawdataack{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.rawdataseqno{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.recvkey{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.recvtok{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.reserved{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.reserved.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.rst_reason{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sendhmac{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sendkey{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sendmac{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sendrand{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sendtrunchmac{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sendtruncmac{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sha1.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.sha256.flag{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.subflowseqno{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.subtype{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mptcp.version{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mss{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mss.absent{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mss.present{}", delimiter).as_str());
        header.push_str(format!("tcp.options.mss_val{}", delimiter).as_str());
        header.push_str(format!("tcp.options.qs{}", delimiter).as_str());
        header.push_str(format!("tcp.options.qs.rate{}", delimiter).as_str());
        header.push_str(format!("tcp.options.qs.ttl_diff{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.appli_ver{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.client.ip{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.flags{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.flags.last{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.flags.notcfe{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.flags.probe{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.flags.server{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.flags.ssl{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.len{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.prober{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.proxy.ip{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.proxy.port{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.reserved{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.storeid{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.type1{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.type2{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.version{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.probe.version_raw{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.client.port{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.dst.ip{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.dst.port{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.flags{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.flags.chksum{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.flags.fw_rst{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.flags.fw_rst_inner{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.flags.fw_rst_probe{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.flags.mode{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.flags.oob{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.src.ip{}", delimiter).as_str());
        header.push_str(format!("tcp.options.rvbd.trpy.src.port{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack.count{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack.dsack{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack.dsack_le{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack.dsack_re{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack_le{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack_perm{}", delimiter).as_str());
        header.push_str(format!("tcp.options.sack_re{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scps{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scps.binding{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scps.binding.data{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scps.binding.id{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scps.binding.len{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scps.vector{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.bets{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.compress{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.nlts{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.reserved{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.reserved1{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.reserved2{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.reserved3{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.snack1{}", delimiter).as_str());
        header.push_str(format!("tcp.options.scpsflags.snack2{}", delimiter).as_str());
        header.push_str(format!("tcp.options.snack{}", delimiter).as_str());
        header.push_str(format!("tcp.options.snack.le{}", delimiter).as_str());
        header.push_str(format!("tcp.options.snack.offset{}", delimiter).as_str());
        header.push_str(format!("tcp.options.snack.re{}", delimiter).as_str());
        header.push_str(format!("tcp.options.snack.sequence{}", delimiter).as_str());
        header.push_str(format!("tcp.options.snack.size{}", delimiter).as_str());
        header.push_str(format!("tcp.options.tar.reserved{}", delimiter).as_str());
        header.push_str(format!("tcp.options.tarr.rate{}", delimiter).as_str());
        header.push_str(format!("tcp.options.tfo{}", delimiter).as_str());
        header.push_str(format!("tcp.options.tfo.cookie{}", delimiter).as_str());
        header.push_str(format!("tcp.options.tfo.request{}", delimiter).as_str());
        header.push_str(format!("tcp.options.time_stamp{}", delimiter).as_str());
        header.push_str(format!("tcp.options.timestamp.tsecr{}", delimiter).as_str());
        header.push_str(format!("tcp.options.timestamp.tsval{}", delimiter).as_str());
        header.push_str(format!("tcp.options.timestamp.tsval.syncookie.ecn{}", delimiter).as_str());
        header
            .push_str(format!("tcp.options.timestamp.tsval.syncookie.sack{}", delimiter).as_str());
        header.push_str(
            format!(
                "tcp.options.timestamp.tsval.syncookie.timestamp{}",
                delimiter
            )
            .as_str(),
        );
        header.push_str(
            format!("tcp.options.timestamp.tsval.syncookie.wscale{}", delimiter).as_str(),
        );
        header.push_str(format!("tcp.options.type{}", delimiter).as_str());
        header.push_str(format!("tcp.options.type.class{}", delimiter).as_str());
        header.push_str(format!("tcp.options.type.copy{}", delimiter).as_str());
        header.push_str(format!("tcp.options.type.number{}", delimiter).as_str());
        header.push_str(format!("tcp.options.unknown.payload{}", delimiter).as_str());
        header.push_str(format!("tcp.options.user_to{}", delimiter).as_str());
        header.push_str(format!("tcp.options.user_to_granularity{}", delimiter).as_str());
        header.push_str(format!("tcp.options.user_to_val{}", delimiter).as_str());
        header.push_str(format!("tcp.options.wscale{}", delimiter).as_str());
        header.push_str(format!("tcp.options.wscale.multiplier{}", delimiter).as_str());
        header.push_str(format!("tcp.options.wscale.shift{}", delimiter).as_str());
        header.push_str(format!("tcp.options.wscale.shift.invalid{}", delimiter).as_str());
        header.push_str(format!("tcp.options.wscale_val{}", delimiter).as_str());
        header.push_str(format!("tcp.payload{}", delimiter).as_str());
        header.push_str(format!("tcp.pdu.last_frame{}", delimiter).as_str());
        header.push_str(format!("tcp.pdu.size{}", delimiter).as_str());
        header.push_str(format!("tcp.pdu.time{}", delimiter).as_str());
        header.push_str(format!("tcp.port{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.dstcmd{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.dstpid{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.dstuid{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.dstuname{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.srccmd{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.srcpid{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.srcuid{}", delimiter).as_str());
        header.push_str(format!("tcp.proc.srcuname{}", delimiter).as_str());
        header.push_str(format!("tcp.reassembled.data{}", delimiter).as_str());
        header.push_str(format!("tcp.reassembled.length{}", delimiter).as_str());
        header.push_str(format!("tcp.reassembled_in{}", delimiter).as_str());
        header.push_str(format!("tcp.reset_cause{}", delimiter).as_str());
        header.push_str(format!("tcp.segment{}", delimiter).as_str());
        header.push_str(format!("tcp.segment.count{}", delimiter).as_str());
        header.push_str(format!("tcp.segment.error{}", delimiter).as_str());
        header.push_str(format!("tcp.segment.multipletails{}", delimiter).as_str());
        header.push_str(format!("tcp.segment.overlap{}", delimiter).as_str());
        header.push_str(format!("tcp.segment.overlap.conflict{}", delimiter).as_str());
        header.push_str(format!("tcp.segment.toolongfragment{}", delimiter).as_str());
        header.push_str(format!("tcp.segment_data{}", delimiter).as_str());
        header.push_str(format!("tcp.segments{}", delimiter).as_str());
        header.push_str(format!("tcp.seq{}", delimiter).as_str());
        header.push_str(format!("tcp.seq_raw{}", delimiter).as_str());
        header.push_str(format!("tcp.short_segment{}", delimiter).as_str());
        header.push_str(format!("tcp.srcport{}", delimiter).as_str());
        header.push_str(format!("tcp.stream{}", delimiter).as_str());
        header.push_str(format!("tcp.suboption_malformed{}", delimiter).as_str());
        header.push_str(format!("tcp.syncookie.hash{}", delimiter).as_str());
        header.push_str(format!("tcp.syncookie.mss{}", delimiter).as_str());
        header.push_str(format!("tcp.syncookie.time{}", delimiter).as_str());
        header.push_str(format!("tcp.time_delta{}", delimiter).as_str());
        header.push_str(format!("tcp.time_relative{}", delimiter).as_str());
        header.push_str(format!("tcp.urgent_pointer{}", delimiter).as_str());
        header.push_str(format!("tcp.urgent_pointer.non_zero{}", delimiter).as_str());
        header.push_str(format!("tcp.window_size{}", delimiter).as_str());
        header.push_str(format!("tcp.window_size_scalefactor{}", delimiter).as_str());
        header.push_str(format!("tcp.window_size_value{}", delimiter).as_str());

        header
    }

    /// Get the CSV data of the TCP layer as a string
    pub fn get_csv_data(&self, delimiter: &str) -> String {
        let mut data = String::new();

        data.push_str(format!("{}{}", self.mptcp_analysis_echoed_key_mismatch, delimiter).as_str());
        data.push_str(format!("{}{}", self.mptcp_analysis_missing_algorithm, delimiter).as_str());
        data.push_str(format!("{}{}", self.mptcp_analysis_unexpected_idsn, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.mptcp_analysis_unsupported_algorithm, delimiter).as_str(),
        );
        data.push_str(
            format!("{}{}", self.mptcp_connection_echoed_key_mismatch, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.mptcp_connection_missing_algorithm, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.mptcp_connection_unsupported_algorithm, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.mptcp_dss_infinite_mapping, delimiter).as_str());
        data.push_str(format!("{}{}", self.mptcp_dss_missing_mapping, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_ack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_ack_nonzero, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_ack_raw, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_ack_lost_segment, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_ack_rtt, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_acks_frame, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_bytes_in_flight, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_duplicate_ack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_duplicate_ack_frame, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_duplicate_ack_num, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_fast_retransmission, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_initial_rtt, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_keep_alive, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_keep_alive_ack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_lost_segment, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_out_of_order, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_push_bytes_sent, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_retransmission, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_reused_ports, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_rto, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_rto_frame, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.tcp_analysis_spurious_retransmission, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_analysis_tfo_ack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_tfo_ignored, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_tfo_syn, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_window_full, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_window_update, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_zero_window, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_zero_window_probe, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_analysis_zero_window_probe_ack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_bogus_header_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_checksum, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_checksum_ffff, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_checksum_status, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_checksum_bad, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_checksum_bad_expert, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_checksum_calculated, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_checksum_good, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_completeness, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_connection_fin, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_connection_fin_active, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_connection_fin_passive, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_connection_rst, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_connection_sack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_connection_syn, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_connection_synack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_continuation_to, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_dstport, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_fin_retransmission, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_ace, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_ack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_ae, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_cwr, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_ece, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_ecn, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_fin, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_ns, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_push, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_res, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_reset, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_str, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_syn, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_flags_urg, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_hdr_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_non_zero_bytes_after_eol, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_nop, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_nxtseq, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_option_len_invalid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_option_kind, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_option_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_acc_ecn_eceb, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_acc_ecn_ee0b, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_acc_ecn_ee1b, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_ao_keyid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_ao_mac, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_ao_rnextkeyid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_cc, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_cc_value, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_ccecho, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_ccnew, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_echo, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_echo_reply, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_echo_value, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_experimental, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_experimental_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_experimental_exid, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_experimental_magic_number, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_md5, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_md5_digest, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mood, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mood_val, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_addaddrtrunchmac, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_addrid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_backup_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_checksum, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.tcp_options_mptcp_checksumreq_flags, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_mptcp_dataack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_dataack8_flag, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_mptcp_dataackpresent_flag, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_mptcp_datafin_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_datalvllen, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_dataseqno, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_dseqn8_flag, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.tcp_options_mptcp_dseqnpresent_flag, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_mptcp_echo, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.tcp_options_mptcp_extensibility_flag, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_mptcp_flag_t_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_flag_u_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_flag_v_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_flag_w_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_ipv4, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_ipv6, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_ipver, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_mptcp_nomoresubflows_flag, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_mptcp_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_rawdataack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_rawdataseqno, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_recvkey, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_recvtok, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_reserved, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_reserved_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_rst_reason, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sendhmac, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sendkey, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sendmac, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sendrand, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sendtrunchmac, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sendtruncmac, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sha1_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_sha256_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_subflowseqno, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_subtype, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mptcp_version, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mss, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mss_absent, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mss_present, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_mss_val, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_qs, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_qs_rate, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_qs_ttl_diff, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_appli_ver, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_client_ip, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_flags_last, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.tcp_options_rvbd_probe_flags_notcfe, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_flags_probe, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.tcp_options_rvbd_probe_flags_server, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_flags_ssl, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_prober, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_proxy_ip, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_proxy_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_reserved, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_storeid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_type1, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_type2, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_version, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_probe_version_raw, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_client_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_dst_ip, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_dst_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_flags_chksum, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_flags_fw_rst, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_rvbd_trpy_flags_fw_rst_inner, delimiter
            )
            .as_str(),
        );
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_rvbd_trpy_flags_fw_rst_probe, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_flags_mode, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_flags_oob, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_src_ip, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_rvbd_trpy_src_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack_count, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack_dsack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack_dsack_le, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack_dsack_re, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack_le, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack_perm, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_sack_re, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scps, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scps_binding, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scps_binding_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scps_binding_id, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scps_binding_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scps_vector, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_bets, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_compress, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_nlts, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_reserved, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_reserved1, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_reserved2, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_reserved3, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_snack1, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_scpsflags_snack2, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_snack, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_snack_le, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_snack_offset, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_snack_re, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_snack_sequence, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_snack_size, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_tar_reserved, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_tarr_rate, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_tfo, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_tfo_cookie, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_tfo_request, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_time_stamp, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_timestamp_tsecr, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_timestamp_tsval, delimiter).as_str());
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_timestamp_tsval_syncookie_ecn, delimiter
            )
            .as_str(),
        );
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_timestamp_tsval_syncookie_sack, delimiter
            )
            .as_str(),
        );
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_timestamp_tsval_syncookie_timestamp, delimiter
            )
            .as_str(),
        );
        data.push_str(
            format!(
                "{}{}",
                self.tcp_options_timestamp_tsval_syncookie_wscale, delimiter
            )
            .as_str(),
        );
        data.push_str(format!("{}{}", self.tcp_options_type, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_type_class, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_type_copy, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_type_number, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_unknown_payload, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_user_to, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_user_to_granularity, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_user_to_val, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_wscale, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_wscale_multiplier, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_wscale_shift, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_wscale_shift_invalid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_options_wscale_val, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_payload, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_pdu_last_frame, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_pdu_size, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_pdu_time, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_port, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_dstcmd, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_dstpid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_dstuid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_dstuname, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_srccmd, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_srcpid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_srcuid, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_proc_srcuname, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_reassembled_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_reassembled_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_reassembled_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_reset_cause, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment_count, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment_error, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment_multipletails, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment_overlap, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment_overlap_conflict, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment_toolongfragment, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segment_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_segments, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_seq, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_seq_raw, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_short_segment, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_srcport, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_stream, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_suboption_malformed, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_syncookie_hash, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_syncookie_mss, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_syncookie_time, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_time_delta, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_time_relative, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_urgent_pointer, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_urgent_pointer_non_zero, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_window_size, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_window_size_scalefactor, delimiter).as_str());
        data.push_str(format!("{}{}", self.tcp_window_size_value, delimiter).as_str());

        data
    }
}
