/// Struct that represents the IP layer
///
/// Referenced from the [Wireshark documentation](https://www.wireshark.org/docs/dfref/i/ip.html)
#[derive(Debug)]
pub struct IP {
    /// Source or Destination Address - IPv4 address - ip.addr
    pub addr: String,
    /// Bogus IP header length - Label - ip.bogus_header_length
    pub bogus_header_length: String,
    /// Bogus IP length - Label - ip.bogus_ip_length
    pub bogus_ip_length: String,
    /// Bogus IP version - Label - ip.bogus_ip_version
    pub bogus_ip_version: String,
    /// Header Checksum - Unsigned integer (2 bytes) - ip.checksum
    pub checksum: String,
    /// Header checksum status - Unsigned integer (1 byte) - ip.checksum.status
    pub checksum_status: String,
    /// Bad - Boolean - ip.checksum_bad
    pub checksum_bad: String,
    /// Bad checksum - Label - ip.checksum_bad.expert
    pub checksum_bad_expert: String,
    /// Calculated Checksum - Unsigned integer (2 bytes) - ip.checksum_calculated
    pub checksum_calculated: String,
    /// Good - Boolean - ip.checksum_good
    pub checksum_good: String,
    /// Categories - Character string - ip.cipso.categories
    pub cipso_categories: String,
    /// DOI - Unsigned integer (4 bytes) - ip.cipso.doi
    pub cipso_doi: String,
    /// Malformed CIPSO tag - Label - ip.cipso.malformed
    pub cipso_malformed: String,
    /// Sensitivity Level - Unsigned integer (1 byte) - ip.cipso.sensitivity_level
    pub cipso_sensitivity_level: String,
    /// Tag data - Byte sequence - ip.cipso.tag_data
    pub cipso_tag_data: String,
    /// Tag Type - Unsigned integer (1 byte) - ip.cipso.tag_type
    pub cipso_tag_type: String,
    /// Current Route - IPv4 address - ip.cur_rt
    pub cur_rt: String,
    /// Current Route Host - Character string - ip.cur_rt_host
    pub cur_rt_host: String,
    /// Differentiated Services Field - Unsigned integer (1 byte) - ip.dsfield
    pub dsfield: String,
    /// ECN-CE - Unsigned integer (1 byte) - ip.dsfield.ce
    pub dsfield_ce: String,
    /// Differentiated Services Codepoint - Unsigned integer (1 byte) - ip.dsfield.dscp
    pub dsfield_dscp: String,
    /// Explicit Congestion Notification - Unsigned integer (1 byte) - ip.dsfield.ecn
    pub dsfield_ecn: String,
    /// ECN-Capable Transport (ECT) - Unsigned integer (1 byte) - ip.dsfield.ect
    pub dsfield_ect: String,
    /// Destination Address - IPv4 address - ip.dst
    pub dst: String,
    /// Destination Host - Character string - ip.dst_host
    pub dst_host: String,
    /// Empty Route - IPv4 address - ip.empty_rt
    pub empty_rt: String,
    /// Empty Route Host - Character string - ip.empty_rt_host
    pub empty_rt_host: String,
    /// Packet has evil intent - Label - ip.evil_packet
    pub evil_packet: String,
    /// Flags - Unsigned integer (1 byte) - ip.flags
    pub flags: String,
    /// Don't fragment - Boolean - ip.flags.df
    pub flags_df: String,
    /// More fragments - Boolean - ip.flags.mf
    pub flags_mf: String,
    /// Reserved bit - Boolean - ip.flags.rb
    pub flags_rb: String,
    /// Security flag - Boolean - ip.flags.sf
    pub flags_sf: String,
    /// Fragment Offset - Unsigned integer (2 bytes) - ip.frag_offset
    pub frag_offset: String,
    /// IPv4 Fragment - Frame number - ip.fragment
    pub fragment: String,
    /// Fragment count - Unsigned integer (4 bytes) - ip.fragment.count
    pub fragment_count: String,
    /// Defragmentation error - Frame number - ip.fragment.error
    pub fragment_error: String,
    /// Multiple tail fragments found - Boolean - ip.fragment.multipletails
    pub fragment_multipletails: String,
    /// Fragment overlap - Boolean - ip.fragment.overlap
    pub fragment_overlap: String,
    /// Conflicting data in fragment overlap - Boolean - ip.fragment.overlap.conflict
    pub fragment_overlap_conflict: String,
    /// Fragment too long - Boolean - ip.fragment.toolongfragment
    pub fragment_toolongfragment: String,
    /// IPv4 Fragments - Byte sequence - ip.fragments
    pub fragments: String,
    /// Source or Destination GeoIP AS Number - Unsigned integer (4 bytes) - ip.geoip.asnum
    pub geoip_asnum: String,
    /// Source or Destination GeoIP City - Character string - ip.geoip.city
    pub geoip_city: String,
    /// Source or Destination GeoIP Country - Character string - ip.geoip.country
    pub geoip_country: String,
    /// Source or Destination GeoIP ISO Two Letter Country Code - Character string - ip.geoip.country_iso
    pub geoip_country_iso: String,
    /// Destination GeoIP AS Number - Unsigned integer (4 bytes) - ip.geoip.dst_asnum
    pub geoip_dst_asnum: String,
    /// Destination GeoIP City - Character string - ip.geoip.dst_city
    pub geoip_dst_city: String,
    /// Destination GeoIP Country - Character string - ip.geoip.dst_country
    pub geoip_dst_country: String,
    /// Destination GeoIP ISO Two Letter Country Code - Character string - ip.geoip.dst_country_iso
    pub geoip_dst_country_iso: String,
    /// Destination GeoIP ISP - Character string - ip.geoip.dst_isp
    pub geoip_dst_isp: String,
    /// Destination GeoIP Latitude - Floating point (double-precision) - ip.geoip.dst_lat
    pub geoip_dst_lat: String,
    /// Destination GeoIP Longitude - Floating point (double-precision) - ip.geoip.dst_lon
    pub geoip_dst_lon: String,
    /// Destination GeoIP AS Organization - Character string - ip.geoip.dst_org
    pub geoip_dst_org: String,
    /// Destination GeoIP - Character string - ip.geoip.dst_summary
    pub geoip_dst_summary: String,
    /// Source or Destination GeoIP ISP - Character string - ip.geoip.isp
    pub geoip_isp: String,
    /// Source or Destination GeoIP Latitude - Floating point (double-precision) - ip.geoip.lat
    pub geoip_lat: String,
    /// Source or Destination GeoIP Longitude - Floating point (double-precision) - ip.geoip.lon
    pub geoip_lon: String,
    /// Source or Destination GeoIP AS Organization - Character string - ip.geoip.org
    pub geoip_org: String,
    /// Source GeoIP AS Number - Unsigned integer (4 bytes) - ip.geoip.src_asnum
    pub geoip_src_asnum: String,
    /// Source GeoIP City - Character string - ip.geoip.src_city
    pub geoip_src_city: String,
    /// Source GeoIP Country - Character string - ip.geoip.src_country
    pub geoip_src_country: String,
    /// Source GeoIP ISO Two Letter Country Code - Character string - ip.geoip.src_country_iso
    pub geoip_src_country_iso: String,
    /// Source GeoIP ISP - Character string - ip.geoip.src_isp
    pub geoip_src_isp: String,
    /// Source GeoIP Latitude - Floating point (double-precision) - ip.geoip.src_lat
    pub geoip_src_lat: String,
    /// Source GeoIP Longitude - Floating point (double-precision) - ip.geoip.src_lon
    pub geoip_src_lon: String,
    /// Source GeoIP AS Organization - Character string - ip.geoip.src_org
    pub geoip_src_org: String,
    /// Source GeoIP - Character string - ip.geoip.src_summary
    pub geoip_src_summary: String,
    /// Header Length - Unsigned integer (1 byte) - ip.hdr_len
    pub hdr_len: String,
    /// Source or Destination Host - Character string - ip.host
    pub host: String,
    /// Identification - Unsigned integer (2 bytes) - ip.id
    pub id: String,
    /// Total Length - Unsigned integer (2 bytes) - ip.len
    pub len: String,
    /// 4 NOP in a row - a router may have removed some options - Label - ip.nop
    pub nop: String,
    /// IP Address - IPv4 address - ip.opt.addr
    pub opt_addr: String,
    /// Additional Security Info - Byte sequence - ip.opt.ext_sec_add_sec_info
    pub opt_ext_sec_add_sec_info: String,
    /// Additional Security Info Format Code - Unsigned integer (1 byte) - ip.opt.ext_sec_add_sec_info_format_code
    pub opt_ext_sec_add_sec_info_format_code: String,
    /// Flag - Unsigned integer (1 byte) - ip.opt.flag
    pub opt_flag: String,
    /// ID Number - Unsigned integer (2 bytes) - ip.opt.id_number
    pub opt_id_number: String,
    /// Length - Unsigned integer (1 byte) - ip.opt.len
    pub opt_len: String,
    /// Invalid length for option - Label - ip.opt.len.invalid
    pub opt_len_invalid: String,
    /// MTU - Unsigned integer (2 bytes) - ip.opt.mtu
    pub opt_mtu: String,
    /// Outbound Hop Count - Unsigned integer (2 bytes) - ip.opt.ohc
    pub opt_ohc: String,
    /// Originator IP Address - IPv4 address - ip.opt.originator
    pub opt_originator: String,
    /// Overflow - Unsigned integer (1 byte) - ip.opt.overflow
    pub opt_overflow: String,
    /// Padding - Byte sequence - ip.opt.padding
    pub opt_padding: String,
    /// Pointer - Unsigned integer (1 byte) - ip.opt.ptr
    pub opt_ptr: String,
    /// Pointer points before first address - Label - ip.opt.ptr.before_address
    pub opt_ptr_before_address: String,
    /// Pointer points to middle of address - Label - ip.opt.ptr.middle_address
    pub opt_ptr_middle_address: String,
    /// Function - Unsigned integer (1 byte) - ip.opt.qs_func
    pub opt_qs_func: String,
    /// QS Nonce - Unsigned integer (4 bytes) - ip.opt.qs_nonce
    pub opt_qs_nonce: String,
    /// Rate - Unsigned integer (1 byte) - ip.opt.qs_rate
    pub opt_qs_rate: String,
    /// Reserved - Unsigned integer (4 bytes) - ip.opt.qs_reserved
    pub opt_qs_reserved: String,
    /// QS TTL - Unsigned integer (1 byte) - ip.opt.qs_ttl
    pub opt_qs_ttl: String,
    /// TTL Diff - Unsigned integer (1 byte) - ip.opt.qs_ttl_diff
    pub opt_qs_ttl_diff: String,
    /// Not Used - Unsigned integer (1 byte) - ip.opt.qs_unused
    pub opt_qs_unused: String,
    /// Router Alert - Unsigned integer (2 bytes) - ip.opt.ra
    pub opt_ra: String,
    /// Return Hop Count - Unsigned integer (2 bytes) - ip.opt.rhc
    pub opt_rhc: String,
    /// Classification Level - Unsigned integer (1 byte) - ip.opt.sec_cl
    pub opt_sec_cl: String,
    /// DOE - Boolean - ip.opt.sec_prot_auth_doe
    pub opt_sec_prot_auth_doe: String,
    /// Protection Authority Flags - Unsigned integer (1 byte) - ip.opt.sec_prot_auth_flags
    pub opt_sec_prot_auth_flags: String,
    /// Field Termination Indicator - Boolean - ip.opt.sec_prot_auth_fti
    pub opt_sec_prot_auth_fti: String,
    /// GENSER - Boolean - ip.opt.sec_prot_auth_genser
    pub opt_sec_prot_auth_genser: String,
    /// NSA - Boolean - ip.opt.sec_prot_auth_nsa
    pub opt_sec_prot_auth_nsa: String,
    /// SCI - Boolean - ip.opt.sec_prot_auth_sci
    pub opt_sec_prot_auth_sci: String,
    /// SIOP-ESI - Boolean - ip.opt.sec_prot_auth_siop_esi
    pub opt_sec_prot_auth_siop_esi: String,
    /// Unassigned - Unsigned integer (1 byte) - ip.opt.sec_prot_auth_unassigned
    pub opt_sec_prot_auth_unassigned: String,
    /// Compartments - Unsigned integer (2 bytes) - ip.opt.sec_rfc791_comp
    pub opt_sec_rfc791_comp: String,
    /// Handling Restrictions - Character string - ip.opt.sec_rfc791_hr
    pub opt_sec_rfc791_hr: String,
    /// Security - Unsigned integer (2 bytes) - ip.opt.sec_rfc791_sec
    pub opt_sec_rfc791_sec: String,
    /// Transmission Control Code - Character string - ip.opt.sec_rfc791_tcc
    pub opt_sec_rfc791_tcc: String,
    /// Stream Identifier - Unsigned integer (2 bytes) - ip.opt.sid
    pub opt_sid: String,
    /// Time stamp - Unsigned integer (4 bytes) - ip.opt.time_stamp
    pub opt_time_stamp: String,
    /// Address - IPv4 address - ip.opt.time_stamp_addr
    pub opt_time_stamp_addr: String,
    /// Type - Unsigned integer (1 byte) - ip.opt.type
    pub opt_type: String,
    /// Class - Unsigned integer (1 byte) - ip.opt.type.class
    pub opt_type_class: String,
    /// Copy on fragmentation - Boolean - ip.opt.type.copy
    pub opt_type_copy: String,
    /// Number - Unsigned integer (1 byte) - ip.opt.type.number
    pub opt_type_number: String,
    /// Protocol - Unsigned integer (1 byte) - ip.proto
    pub proto: String,
    /// Reassembled IPv4 data - Byte sequence - ip.reassembled.data
    pub reassembled_data: String,
    /// Reassembled IPv4 length - Unsigned integer (4 bytes) - ip.reassembled.length
    pub reassembled_length: String,
    /// Reassembled IPv4 in frame - Frame number - ip.reassembled_in
    pub reassembled_in: String,
    /// Recorded Route - IPv4 address - ip.rec_rt
    pub rec_rt: String,
    /// Recorded Route Host - Character string - ip.rec_rt_host
    pub rec_rt_host: String,
    /// Source Address - IPv4 address - ip.src
    pub src: String,
    /// Source Host - Character string - ip.src_host
    pub src_host: String,
    /// Source Route - IPv4 address - ip.src_rt
    pub src_rt: String,
    /// Source Route Host - Character string - ip.src_rt_host
    pub src_rt_host: String,
    /// Suboption would go past end of option - Label - ip.subopt_too_long
    pub subopt_too_long: String,
    /// Type of Service - Unsigned integer (1 byte) - ip.tos
    pub tos: String,
    /// Cost - Boolean - ip.tos.cost
    pub tos_cost: String,
    /// Delay - Boolean - ip.tos.delay
    pub tos_delay: String,
    /// Precedence - Unsigned integer (1 byte) - ip.tos.precedence
    pub tos_precedence: String,
    /// Reliability - Boolean - ip.tos.reliability
    pub tos_reliability: String,
    /// Throughput - Boolean - ip.tos.throughput
    pub tos_throughput: String,
    /// Time to Live - Unsigned integer (1 byte) - ip.ttl
    pub ttl: String,
    /// Time To Live - Label - ip.ttl.lncb
    pub ttl_lncb: String,
    /// Time To Live - Label - ip.ttl.too_small
    pub ttl_too_small: String,
    /// Version - Unsigned integer (1 byte) - ip.version
    pub version: String,
}

/// IP implementation
impl IP {
    /// Create a new IP layer
    pub fn new() -> IP {
        IP {
            addr: String::new(),
            bogus_header_length: String::new(),
            bogus_ip_length: String::new(),
            bogus_ip_version: String::new(),
            checksum: String::new(),
            checksum_status: String::new(),
            checksum_bad: String::new(),
            checksum_bad_expert: String::new(),
            checksum_calculated: String::new(),
            checksum_good: String::new(),
            cipso_categories: String::new(),
            cipso_doi: String::new(),
            cipso_malformed: String::new(),
            cipso_sensitivity_level: String::new(),
            cipso_tag_data: String::new(),
            cipso_tag_type: String::new(),
            cur_rt: String::new(),
            cur_rt_host: String::new(),
            dsfield: String::new(),
            dsfield_ce: String::new(),
            dsfield_dscp: String::new(),
            dsfield_ecn: String::new(),
            dsfield_ect: String::new(),
            dst: String::new(),
            dst_host: String::new(),
            empty_rt: String::new(),
            empty_rt_host: String::new(),
            evil_packet: String::new(),
            flags: String::new(),
            flags_df: String::new(),
            flags_mf: String::new(),
            flags_rb: String::new(),
            flags_sf: String::new(),
            frag_offset: String::new(),
            fragment: String::new(),
            fragment_count: String::new(),
            fragment_error: String::new(),
            fragment_multipletails: String::new(),
            fragment_overlap: String::new(),
            fragment_overlap_conflict: String::new(),
            fragment_toolongfragment: String::new(),
            fragments: String::new(),
            geoip_asnum: String::new(),
            geoip_city: String::new(),
            geoip_country: String::new(),
            geoip_country_iso: String::new(),
            geoip_dst_asnum: String::new(),
            geoip_dst_city: String::new(),
            geoip_dst_country: String::new(),
            geoip_dst_country_iso: String::new(),
            geoip_dst_isp: String::new(),
            geoip_dst_lat: String::new(),
            geoip_dst_lon: String::new(),
            geoip_dst_org: String::new(),
            geoip_dst_summary: String::new(),
            geoip_isp: String::new(),
            geoip_lat: String::new(),
            geoip_lon: String::new(),
            geoip_org: String::new(),
            geoip_src_asnum: String::new(),
            geoip_src_city: String::new(),
            geoip_src_country: String::new(),
            geoip_src_country_iso: String::new(),
            geoip_src_isp: String::new(),
            geoip_src_lat: String::new(),
            geoip_src_lon: String::new(),
            geoip_src_org: String::new(),
            geoip_src_summary: String::new(),
            hdr_len: String::new(),
            host: String::new(),
            id: String::new(),
            len: String::new(),
            nop: String::new(),
            opt_addr: String::new(),
            opt_ext_sec_add_sec_info: String::new(),
            opt_ext_sec_add_sec_info_format_code: String::new(),
            opt_flag: String::new(),
            opt_id_number: String::new(),
            opt_len: String::new(),
            opt_len_invalid: String::new(),
            opt_mtu: String::new(),
            opt_ohc: String::new(),
            opt_originator: String::new(),
            opt_overflow: String::new(),
            opt_padding: String::new(),
            opt_ptr: String::new(),
            opt_ptr_before_address: String::new(),
            opt_ptr_middle_address: String::new(),
            opt_qs_func: String::new(),
            opt_qs_nonce: String::new(),
            opt_qs_rate: String::new(),
            opt_qs_reserved: String::new(),
            opt_qs_ttl: String::new(),
            opt_qs_ttl_diff: String::new(),
            opt_qs_unused: String::new(),
            opt_ra: String::new(),
            opt_rhc: String::new(),
            opt_sec_cl: String::new(),
            opt_sec_prot_auth_doe: String::new(),
            opt_sec_prot_auth_flags: String::new(),
            opt_sec_prot_auth_fti: String::new(),
            opt_sec_prot_auth_genser: String::new(),
            opt_sec_prot_auth_nsa: String::new(),
            opt_sec_prot_auth_sci: String::new(),
            opt_sec_prot_auth_siop_esi: String::new(),
            opt_sec_prot_auth_unassigned: String::new(),
            opt_sec_rfc791_comp: String::new(),
            opt_sec_rfc791_hr: String::new(),
            opt_sec_rfc791_sec: String::new(),
            opt_sec_rfc791_tcc: String::new(),
            opt_sid: String::new(),
            opt_time_stamp: String::new(),
            opt_time_stamp_addr: String::new(),
            opt_type: String::new(),
            opt_type_class: String::new(),
            opt_type_copy: String::new(),
            opt_type_number: String::new(),
            proto: String::new(),
            reassembled_data: String::new(),
            reassembled_length: String::new(),
            reassembled_in: String::new(),
            rec_rt: String::new(),
            rec_rt_host: String::new(),
            src: String::new(),
            src_host: String::new(),
            src_rt: String::new(),
            src_rt_host: String::new(),
            subopt_too_long: String::new(),
            tos: String::new(),
            tos_cost: String::new(),
            tos_delay: String::new(),
            tos_precedence: String::new(),
            tos_reliability: String::new(),
            tos_throughput: String::new(),
            ttl: String::new(),
            ttl_lncb: String::new(),
            ttl_too_small: String::new(),
            version: String::new(),
        }
    }

    /// Update the IP layer with a new value
    ///
    /// This function maps the Wireshark/TShark field name to the corresponding
    /// IP layer field name in the struct.
    pub fn update(&mut self, field: &str, value: &str) {
        match field {
            "ip.addr" => self.addr = value.to_string(),
            "ip.bogus_header_length" => self.bogus_header_length = value.to_string(),
            "ip.bogus_ip_length" => self.bogus_ip_length = value.to_string(),
            "ip.bogus_ip_version" => self.bogus_ip_version = value.to_string(),
            "ip.checksum" => self.checksum = value.to_string(),
            "ip.checksum.status" => self.checksum_status = value.to_string(),
            "ip.checksum_bad" => self.checksum_bad = value.to_string(),
            "ip.checksum_bad.expert" => self.checksum_bad_expert = value.to_string(),
            "ip.checksum_calculated" => self.checksum_calculated = value.to_string(),
            "ip.checksum_good" => self.checksum_good = value.to_string(),
            "ip.cipso.categories" => self.cipso_categories = value.to_string(),
            "ip.cipso.doi" => self.cipso_doi = value.to_string(),
            "ip.cipso.malformed" => self.cipso_malformed = value.to_string(),
            "ip.cipso.sensitivity_level" => self.cipso_sensitivity_level = value.to_string(),
            "ip.cipso.tag_data" => self.cipso_tag_data = value.to_string(),
            "ip.cipso.tag_type" => self.cipso_tag_type = value.to_string(),
            "ip.cur_rt" => self.cur_rt = value.to_string(),
            "ip.cur_rt_host" => self.cur_rt_host = value.to_string(),
            "ip.dsfield" => self.dsfield = value.to_string(),
            "ip.dsfield.ce" => self.dsfield_ce = value.to_string(),
            "ip.dsfield.dscp" => self.dsfield_dscp = value.to_string(),
            "ip.dsfield.ecn" => self.dsfield_ecn = value.to_string(),
            "ip.dsfield.ect" => self.dsfield_ect = value.to_string(),
            "ip.dst" => self.dst = value.to_string(),
            "ip.dst_host" => self.dst_host = value.to_string(),
            "ip.empty_rt" => self.empty_rt = value.to_string(),
            "ip.empty_rt_host" => self.empty_rt_host = value.to_string(),
            "ip.evil_packet" => self.evil_packet = value.to_string(),
            "ip.flags" => self.flags = value.to_string(),
            "ip.flags.df" => self.flags_df = value.to_string(),
            "ip.flags.mf" => self.flags_mf = value.to_string(),
            "ip.flags.rb" => self.flags_rb = value.to_string(),
            "ip.flags.sf" => self.flags_sf = value.to_string(),
            "ip.frag_offset" => self.frag_offset = value.to_string(),
            "ip.fragment" => self.fragment = value.to_string(),
            "ip.fragment.count" => self.fragment_count = value.to_string(),
            "ip.fragment.error" => self.fragment_error = value.to_string(),
            "ip.fragment.multipletails" => self.fragment_multipletails = value.to_string(),
            "ip.fragment.overlap" => self.fragment_overlap = value.to_string(),
            "ip.fragment.overlap.conflict" => self.fragment_overlap_conflict = value.to_string(),
            "ip.fragment.toolongfragment" => self.fragment_toolongfragment = value.to_string(),
            "ip.fragments" => self.fragments = value.to_string(),
            "ip.geoip.asnum" => self.geoip_asnum = value.to_string(),
            "ip.geoip.city" => self.geoip_city = value.to_string(),
            "ip.geoip.country" => self.geoip_country = value.to_string(),
            "ip.geoip.country_iso" => self.geoip_country_iso = value.to_string(),
            "ip.geoip.dst_asnum" => self.geoip_dst_asnum = value.to_string(),
            "ip.geoip.dst_city" => self.geoip_dst_city = value.to_string(),
            "ip.geoip.dst_country" => self.geoip_dst_country = value.to_string(),
            "ip.geoip.dst_country_iso" => self.geoip_dst_country_iso = value.to_string(),
            "ip.geoip.dst_isp" => self.geoip_dst_isp = value.to_string(),
            "ip.geoip.dst_lat" => self.geoip_dst_lat = value.to_string(),
            "ip.geoip.dst_lon" => self.geoip_dst_lon = value.to_string(),
            "ip.geoip.dst_org" => self.geoip_dst_org = value.to_string(),
            "ip.geoip.dst_summary" => self.geoip_dst_summary = value.to_string(),
            "ip.geoip.isp" => self.geoip_isp = value.to_string(),
            "ip.geoip.lat" => self.geoip_lat = value.to_string(),
            "ip.geoip.lon" => self.geoip_lon = value.to_string(),
            "ip.geoip.org" => self.geoip_org = value.to_string(),
            "ip.geoip.src_asnum" => self.geoip_src_asnum = value.to_string(),
            "ip.geoip.src_city" => self.geoip_src_city = value.to_string(),
            "ip.geoip.src_country" => self.geoip_src_country = value.to_string(),
            "ip.geoip.src_country_iso" => self.geoip_src_country_iso = value.to_string(),
            "ip.geoip.src_isp" => self.geoip_src_isp = value.to_string(),
            "ip.geoip.src_lat" => self.geoip_src_lat = value.to_string(),
            "ip.geoip.src_lon" => self.geoip_src_lon = value.to_string(),
            "ip.geoip.src_org" => self.geoip_src_org = value.to_string(),
            "ip.geoip.src_summary" => self.geoip_src_summary = value.to_string(),
            "ip.hdr_len" => self.hdr_len = value.to_string(),
            "ip.host" => self.host = value.to_string(),
            "ip.id" => self.id = value.to_string(),
            "ip.len" => self.len = value.to_string(),
            "ip.nop" => self.nop = value.to_string(),
            "ip.opt.addr" => self.opt_addr = value.to_string(),
            "ip.opt.ext_sec_add_sec_info" => self.opt_ext_sec_add_sec_info = value.to_string(),
            "ip.opt.ext_sec_add_sec_info_format_code" => {
                self.opt_ext_sec_add_sec_info_format_code = value.to_string()
            }
            "ip.opt.flag" => self.opt_flag = value.to_string(),
            "ip.opt.id_number" => self.opt_id_number = value.to_string(),
            "ip.opt.len" => self.opt_len = value.to_string(),
            "ip.opt.len.invalid" => self.opt_len_invalid = value.to_string(),
            "ip.opt.mtu" => self.opt_mtu = value.to_string(),
            "ip.opt.ohc" => self.opt_ohc = value.to_string(),
            "ip.opt.originator" => self.opt_originator = value.to_string(),
            "ip.opt.overflow" => self.opt_overflow = value.to_string(),
            "ip.opt.padding" => self.opt_padding = value.to_string(),
            "ip.opt.ptr" => self.opt_ptr = value.to_string(),
            "ip.opt.ptr.before_address" => self.opt_ptr_before_address = value.to_string(),
            "ip.opt.ptr.middle_address" => self.opt_ptr_middle_address = value.to_string(),
            "ip.opt.qs_func" => self.opt_qs_func = value.to_string(),
            "ip.opt.qs_nonce" => self.opt_qs_nonce = value.to_string(),
            "ip.opt.qs_rate" => self.opt_qs_rate = value.to_string(),
            "ip.opt.qs_reserved" => self.opt_qs_reserved = value.to_string(),
            "ip.opt.qs_ttl" => self.opt_qs_ttl = value.to_string(),
            "ip.opt.qs_ttl_diff" => self.opt_qs_ttl_diff = value.to_string(),
            "ip.opt.qs_unused" => self.opt_qs_unused = value.to_string(),
            "ip.opt.ra" => self.opt_ra = value.to_string(),
            "ip.opt.rhc" => self.opt_rhc = value.to_string(),
            "ip.opt.sec_cl" => self.opt_sec_cl = value.to_string(),
            "ip.opt.sec_prot_auth_doe" => self.opt_sec_prot_auth_doe = value.to_string(),
            "ip.opt.sec_prot_auth_flags" => self.opt_sec_prot_auth_flags = value.to_string(),
            "ip.opt.sec_prot_auth_fti" => self.opt_sec_prot_auth_fti = value.to_string(),
            "ip.opt.sec_prot_auth_genser" => self.opt_sec_prot_auth_genser = value.to_string(),
            "ip.opt.sec_prot_auth_nsa" => self.opt_sec_prot_auth_nsa = value.to_string(),
            "ip.opt.sec_prot_auth_sci" => self.opt_sec_prot_auth_sci = value.to_string(),
            "ip.opt.sec_prot_auth_siop_esi" => self.opt_sec_prot_auth_siop_esi = value.to_string(),
            "ip.opt.sec_prot_auth_unassigned" => {
                self.opt_sec_prot_auth_unassigned = value.to_string()
            }
            "ip.opt.sec_rfc791_comp" => self.opt_sec_rfc791_comp = value.to_string(),
            "ip.opt.sec_rfc791_hr" => self.opt_sec_rfc791_hr = value.to_string(),
            "ip.opt.sec_rfc791_sec" => self.opt_sec_rfc791_sec = value.to_string(),
            "ip.opt.sec_rfc791_tcc" => self.opt_sec_rfc791_tcc = value.to_string(),
            "ip.opt.sid" => self.opt_sid = value.to_string(),
            "ip.opt.time_stamp" => self.opt_time_stamp = value.to_string(),
            "ip.opt.time_stamp_addr" => self.opt_time_stamp_addr = value.to_string(),
            "ip.opt.type" => self.opt_type = value.to_string(),
            "ip.opt.type.class" => self.opt_type_class = value.to_string(),
            "ip.opt.type.copy" => self.opt_type_copy = value.to_string(),
            "ip.opt.type.number" => self.opt_type_number = value.to_string(),
            "ip.proto" => self.proto = value.to_string(),
            "ip.reassembled.data" => self.reassembled_data = value.to_string(),
            "ip.reassembled.length" => self.reassembled_length = value.to_string(),
            "ip.reassembled_in" => self.reassembled_in = value.to_string(),
            "ip.rec_rt" => self.rec_rt = value.to_string(),
            "ip.rec_rt_host" => self.rec_rt_host = value.to_string(),
            "ip.src" => self.src = value.to_string(),
            "ip.src_host" => self.src_host = value.to_string(),
            "ip.src_rt" => self.src_rt = value.to_string(),
            "ip.src_rt_host" => self.src_rt_host = value.to_string(),
            "ip.subopt_too_long" => self.subopt_too_long = value.to_string(),
            "ip.tos" => self.tos = value.to_string(),
            "ip.tos.cost" => self.tos_cost = value.to_string(),
            "ip.tos.delay" => self.tos_delay = value.to_string(),
            "ip.tos.precedence" => self.tos_precedence = value.to_string(),
            "ip.tos.reliability" => self.tos_reliability = value.to_string(),
            "ip.tos.throughput" => self.tos_throughput = value.to_string(),
            "ip.ttl" => self.ttl = value.to_string(),
            "ip.ttl.lncb" => self.ttl_lncb = value.to_string(),
            "ip.ttl.too_small" => self.ttl_too_small = value.to_string(),
            "ip.version" => self.version = value.to_string(),
            &_ => (),
        }
    }

    /// Get the IP layer header values for the CSV file
    pub fn get_csv_header(delimiter: &str) -> String {
        let mut header = String::new();

        header.push_str(format!("ip.addr{}", delimiter).as_str());
        header.push_str(format!("ip.bogus_header_length{}", delimiter).as_str());
        header.push_str(format!("ip.bogus_ip_length{}", delimiter).as_str());
        header.push_str(format!("ip.bogus_ip_version{}", delimiter).as_str());
        header.push_str(format!("ip.checksum{}", delimiter).as_str());
        header.push_str(format!("ip.checksum.status{}", delimiter).as_str());
        header.push_str(format!("ip.checksum_bad{}", delimiter).as_str());
        header.push_str(format!("ip.checksum_bad.expert{}", delimiter).as_str());
        header.push_str(format!("ip.checksum_calculated{}", delimiter).as_str());
        header.push_str(format!("ip.checksum_good{}", delimiter).as_str());
        header.push_str(format!("ip.cipso.categories{}", delimiter).as_str());
        header.push_str(format!("ip.cipso.doi{}", delimiter).as_str());
        header.push_str(format!("ip.cipso.malformed{}", delimiter).as_str());
        header.push_str(format!("ip.cipso.sensitivity_level{}", delimiter).as_str());
        header.push_str(format!("ip.cipso.tag_data{}", delimiter).as_str());
        header.push_str(format!("ip.cipso.tag_type{}", delimiter).as_str());
        header.push_str(format!("ip.cur_rt{}", delimiter).as_str());
        header.push_str(format!("ip.cur_rt_host{}", delimiter).as_str());
        header.push_str(format!("ip.dsfield{}", delimiter).as_str());
        header.push_str(format!("ip.dsfield.ce{}", delimiter).as_str());
        header.push_str(format!("ip.dsfield.dscp{}", delimiter).as_str());
        header.push_str(format!("ip.dsfield.ecn{}", delimiter).as_str());
        header.push_str(format!("ip.dsfield.ect{}", delimiter).as_str());
        header.push_str(format!("ip.dst{}", delimiter).as_str());
        header.push_str(format!("ip.dst_host{}", delimiter).as_str());
        header.push_str(format!("ip.empty_rt{}", delimiter).as_str());
        header.push_str(format!("ip.empty_rt_host{}", delimiter).as_str());
        header.push_str(format!("ip.evil_packet{}", delimiter).as_str());
        header.push_str(format!("ip.flags{}", delimiter).as_str());
        header.push_str(format!("ip.flags.df{}", delimiter).as_str());
        header.push_str(format!("ip.flags.mf{}", delimiter).as_str());
        header.push_str(format!("ip.flags.rb{}", delimiter).as_str());
        header.push_str(format!("ip.flags.sf{}", delimiter).as_str());
        header.push_str(format!("ip.frag_offset{}", delimiter).as_str());
        header.push_str(format!("ip.fragment{}", delimiter).as_str());
        header.push_str(format!("ip.fragment.count{}", delimiter).as_str());
        header.push_str(format!("ip.fragment.error{}", delimiter).as_str());
        header.push_str(format!("ip.fragment.multipletails{}", delimiter).as_str());
        header.push_str(format!("ip.fragment.overlap{}", delimiter).as_str());
        header.push_str(format!("ip.fragment.overlap.conflict{}", delimiter).as_str());
        header.push_str(format!("ip.fragment.toolongfragment{}", delimiter).as_str());
        header.push_str(format!("ip.fragments{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.asnum{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.city{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.country{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.country_iso{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_asnum{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_city{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_country{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_country_iso{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_isp{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_lat{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_lon{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_org{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.dst_summary{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.isp{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.lat{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.lon{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.org{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_asnum{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_city{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_country{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_country_iso{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_isp{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_lat{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_lon{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_org{}", delimiter).as_str());
        header.push_str(format!("ip.geoip.src_summary{}", delimiter).as_str());
        header.push_str(format!("ip.hdr_len{}", delimiter).as_str());
        header.push_str(format!("ip.host{}", delimiter).as_str());
        header.push_str(format!("ip.id{}", delimiter).as_str());
        header.push_str(format!("ip.len{}", delimiter).as_str());
        header.push_str(format!("ip.nop{}", delimiter).as_str());
        header.push_str(format!("ip.opt.addr{}", delimiter).as_str());
        header.push_str(format!("ip.opt.ext_sec_add_sec_info{}", delimiter).as_str());
        header.push_str(format!("ip.opt.ext_sec_add_sec_info_format_code{}", delimiter).as_str());
        header.push_str(format!("ip.opt.flag{}", delimiter).as_str());
        header.push_str(format!("ip.opt.id_number{}", delimiter).as_str());
        header.push_str(format!("ip.opt.len{}", delimiter).as_str());
        header.push_str(format!("ip.opt.len.invalid{}", delimiter).as_str());
        header.push_str(format!("ip.opt.mtu{}", delimiter).as_str());
        header.push_str(format!("ip.opt.ohc{}", delimiter).as_str());
        header.push_str(format!("ip.opt.originator{}", delimiter).as_str());
        header.push_str(format!("ip.opt.overflow{}", delimiter).as_str());
        header.push_str(format!("ip.opt.padding{}", delimiter).as_str());
        header.push_str(format!("ip.opt.ptr{}", delimiter).as_str());
        header.push_str(format!("ip.opt.ptr.before_address{}", delimiter).as_str());
        header.push_str(format!("ip.opt.ptr.middle_address{}", delimiter).as_str());
        header.push_str(format!("ip.opt.qs_func{}", delimiter).as_str());
        header.push_str(format!("ip.opt.qs_nonce{}", delimiter).as_str());
        header.push_str(format!("ip.opt.qs_rate{}", delimiter).as_str());
        header.push_str(format!("ip.opt.qs_reserved{}", delimiter).as_str());
        header.push_str(format!("ip.opt.qs_ttl{}", delimiter).as_str());
        header.push_str(format!("ip.opt.qs_ttl_diff{}", delimiter).as_str());
        header.push_str(format!("ip.opt.qs_unused{}", delimiter).as_str());
        header.push_str(format!("ip.opt.ra{}", delimiter).as_str());
        header.push_str(format!("ip.opt.rhc{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_cl{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_doe{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_flags{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_fti{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_genser{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_nsa{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_sci{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_siop_esi{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_prot_auth_unassigned{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_rfc791_comp{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_rfc791_hr{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_rfc791_sec{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sec_rfc791_tcc{}", delimiter).as_str());
        header.push_str(format!("ip.opt.sid{}", delimiter).as_str());
        header.push_str(format!("ip.opt.time_stamp{}", delimiter).as_str());
        header.push_str(format!("ip.opt.time_stamp_addr{}", delimiter).as_str());
        header.push_str(format!("ip.opt.type{}", delimiter).as_str());
        header.push_str(format!("ip.opt.type.class{}", delimiter).as_str());
        header.push_str(format!("ip.opt.type.copy{}", delimiter).as_str());
        header.push_str(format!("ip.opt.type.number{}", delimiter).as_str());
        header.push_str(format!("ip.proto{}", delimiter).as_str());
        header.push_str(format!("ip.reassembled.data{}", delimiter).as_str());
        header.push_str(format!("ip.reassembled.length{}", delimiter).as_str());
        header.push_str(format!("ip.reassembled_in{}", delimiter).as_str());
        header.push_str(format!("ip.rec_rt{}", delimiter).as_str());
        header.push_str(format!("ip.rec_rt_host{}", delimiter).as_str());
        header.push_str(format!("ip.src{}", delimiter).as_str());
        header.push_str(format!("ip.src_host{}", delimiter).as_str());
        header.push_str(format!("ip.src_rt{}", delimiter).as_str());
        header.push_str(format!("ip.src_rt_host{}", delimiter).as_str());
        header.push_str(format!("ip.subopt_too_long{}", delimiter).as_str());
        header.push_str(format!("ip.tos{}", delimiter).as_str());
        header.push_str(format!("ip.tos.cost{}", delimiter).as_str());
        header.push_str(format!("ip.tos.delay{}", delimiter).as_str());
        header.push_str(format!("ip.tos.precedence{}", delimiter).as_str());
        header.push_str(format!("ip.tos.reliability{}", delimiter).as_str());
        header.push_str(format!("ip.tos.throughput{}", delimiter).as_str());
        header.push_str(format!("ip.ttl{}", delimiter).as_str());
        header.push_str(format!("ip.ttl.lncb{}", delimiter).as_str());
        header.push_str(format!("ip.ttl.too_small{}", delimiter).as_str());
        header.push_str(format!("ip.version{}", delimiter).as_str());

        header
    }

    /// Get the CSV data of the IP layer as a string
    pub fn get_csv_data(&self, delimiter: &str) -> String {
        let mut data = String::new();

        data.push_str(format!("{}{}", self.addr, delimiter).as_str());
        data.push_str(format!("{}{}", self.bogus_header_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.bogus_ip_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.bogus_ip_version, delimiter).as_str());
        data.push_str(format!("{}{}", self.checksum, delimiter).as_str());
        data.push_str(format!("{}{}", self.checksum_status, delimiter).as_str());
        data.push_str(format!("{}{}", self.checksum_bad, delimiter).as_str());
        data.push_str(format!("{}{}", self.checksum_bad_expert, delimiter).as_str());
        data.push_str(format!("{}{}", self.checksum_calculated, delimiter).as_str());
        data.push_str(format!("{}{}", self.checksum_good, delimiter).as_str());
        data.push_str(format!("{}{}", self.cipso_categories, delimiter).as_str());
        data.push_str(format!("{}{}", self.cipso_doi, delimiter).as_str());
        data.push_str(format!("{}{}", self.cipso_malformed, delimiter).as_str());
        data.push_str(format!("{}{}", self.cipso_sensitivity_level, delimiter).as_str());
        data.push_str(format!("{}{}", self.cipso_tag_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.cipso_tag_type, delimiter).as_str());
        data.push_str(format!("{}{}", self.cur_rt, delimiter).as_str());
        data.push_str(format!("{}{}", self.cur_rt_host, delimiter).as_str());
        data.push_str(format!("{}{}", self.dsfield, delimiter).as_str());
        data.push_str(format!("{}{}", self.dsfield_ce, delimiter).as_str());
        data.push_str(format!("{}{}", self.dsfield_dscp, delimiter).as_str());
        data.push_str(format!("{}{}", self.dsfield_ecn, delimiter).as_str());
        data.push_str(format!("{}{}", self.dsfield_ect, delimiter).as_str());
        data.push_str(format!("{}{}", self.dst, delimiter).as_str());
        data.push_str(format!("{}{}", self.dst_host, delimiter).as_str());
        data.push_str(format!("{}{}", self.empty_rt, delimiter).as_str());
        data.push_str(format!("{}{}", self.empty_rt_host, delimiter).as_str());
        data.push_str(format!("{}{}", self.evil_packet, delimiter).as_str());
        data.push_str(format!("{}{}", self.flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.flags_df, delimiter).as_str());
        data.push_str(format!("{}{}", self.flags_mf, delimiter).as_str());
        data.push_str(format!("{}{}", self.flags_rb, delimiter).as_str());
        data.push_str(format!("{}{}", self.flags_sf, delimiter).as_str());
        data.push_str(format!("{}{}", self.frag_offset, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragment, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragment_count, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragment_error, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragment_multipletails, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragment_overlap, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragment_overlap_conflict, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragment_toolongfragment, delimiter).as_str());
        data.push_str(format!("{}{}", self.fragments, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_asnum, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_city, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_country, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_country_iso, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_asnum, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_city, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_country, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_country_iso, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_isp, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_lat, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_lon, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_org, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_dst_summary, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_isp, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_lat, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_lon, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_org, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_asnum, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_city, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_country, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_country_iso, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_isp, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_lat, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_lon, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_org, delimiter).as_str());
        data.push_str(format!("{}{}", self.geoip_src_summary, delimiter).as_str());
        data.push_str(format!("{}{}", self.hdr_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.host, delimiter).as_str());
        data.push_str(format!("{}{}", self.id, delimiter).as_str());
        data.push_str(format!("{}{}", self.len, delimiter).as_str());
        data.push_str(format!("{}{}", self.nop, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_addr, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_ext_sec_add_sec_info, delimiter).as_str());
        data.push_str(
            format!("{}{}", self.opt_ext_sec_add_sec_info_format_code, delimiter).as_str(),
        );
        data.push_str(format!("{}{}", self.opt_flag, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_id_number, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_len, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_len_invalid, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_mtu, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_ohc, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_originator, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_overflow, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_padding, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_ptr, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_ptr_before_address, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_ptr_middle_address, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_qs_func, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_qs_nonce, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_qs_rate, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_qs_reserved, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_qs_ttl, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_qs_ttl_diff, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_qs_unused, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_ra, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_rhc, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_cl, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_doe, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_flags, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_fti, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_genser, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_nsa, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_sci, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_siop_esi, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_prot_auth_unassigned, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_rfc791_comp, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_rfc791_hr, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_rfc791_sec, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sec_rfc791_tcc, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_sid, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_time_stamp, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_time_stamp_addr, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_type, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_type_class, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_type_copy, delimiter).as_str());
        data.push_str(format!("{}{}", self.opt_type_number, delimiter).as_str());
        data.push_str(format!("{}{}", self.proto, delimiter).as_str());
        data.push_str(format!("{}{}", self.reassembled_data, delimiter).as_str());
        data.push_str(format!("{}{}", self.reassembled_length, delimiter).as_str());
        data.push_str(format!("{}{}", self.reassembled_in, delimiter).as_str());
        data.push_str(format!("{}{}", self.rec_rt, delimiter).as_str());
        data.push_str(format!("{}{}", self.rec_rt_host, delimiter).as_str());
        data.push_str(format!("{}{}", self.src, delimiter).as_str());
        data.push_str(format!("{}{}", self.src_host, delimiter).as_str());
        data.push_str(format!("{}{}", self.src_rt, delimiter).as_str());
        data.push_str(format!("{}{}", self.src_rt_host, delimiter).as_str());
        data.push_str(format!("{}{}", self.subopt_too_long, delimiter).as_str());
        data.push_str(format!("{}{}", self.tos, delimiter).as_str());
        data.push_str(format!("{}{}", self.tos_cost, delimiter).as_str());
        data.push_str(format!("{}{}", self.tos_delay, delimiter).as_str());
        data.push_str(format!("{}{}", self.tos_precedence, delimiter).as_str());
        data.push_str(format!("{}{}", self.tos_reliability, delimiter).as_str());
        data.push_str(format!("{}{}", self.tos_throughput, delimiter).as_str());
        data.push_str(format!("{}{}", self.ttl, delimiter).as_str());
        data.push_str(format!("{}{}", self.ttl_lncb, delimiter).as_str());
        data.push_str(format!("{}{}", self.ttl_too_small, delimiter).as_str());
        data.push_str(format!("{}{}", self.version, delimiter).as_str());

        data
    }
}
