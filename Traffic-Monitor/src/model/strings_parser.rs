/// This file contains functions to parse strings in various formats

/// Convert Hex string to unicode string
/// For example: 22:73:74:61:74:75:73:22:3a:22:73:74:61:72:74:22 -> "status":"start"
/// Skip the colon
pub fn hex_to_string(hex: &str) -> String {
    let mut result = String::new();
    let mut hex = hex.to_string();

    hex.retain(|c| c != ':');

    let mut chars = hex.chars();

    while let Some(c) = chars.next() {
        let mut s = String::new();
        s.push(c);
        s.push(match chars.next() {
            Some(c) => c,
            None => continue,
        });

        let c = match u8::from_str_radix(&s, 16) {
            Ok(c) => c as char,
            Err(_) => continue,
        };

        result.push(c);
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
