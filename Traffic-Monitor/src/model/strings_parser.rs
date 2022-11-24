/// This file contains functions to parse strings in various formats

/// Convert Hex string to unicode string
/// For example: 22:73:74:61:74:75:73:22:3a:22:73:74:61:72:74:22 -> "status":"start"
/// Skip the colon
pub fn hex_to_string(hex: &str) -> String {
    let mut result = String::new();
    let mut hex = hex.to_string();

    hex.retain(|c| c != ':');

    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();

        result.push(byte as char);
    }

    result
}

/// Remove new line characters from a string
pub fn remove_new_lines(string: &str) -> String {
    string
        .replace("\r", "")
        .replace("\n", "")
        .replace("\r\n", "")
}
