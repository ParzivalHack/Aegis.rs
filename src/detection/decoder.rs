use base64::{Engine as _, engine::general_purpose};

pub struct Decoder;

impl Decoder {
    pub fn detect_and_decode(text: &str, max_depth: usize) -> Vec<(String, String)> {
        let mut results = Vec::new();
        Self::decode_recursive(text, 0, max_depth, &mut results);
        results
    }

    fn decode_recursive(text: &str, depth: usize, max_depth: usize, results: &mut Vec<(String, String)>) {
        if depth >= max_depth {
            return;
        }

        // Try base64
        if let Some(decoded) = Self::try_base64(text) {
            results.push(("base64".to_string(), decoded.clone()));
            Self::decode_recursive(&decoded, depth + 1, max_depth, results);
        }

        // Try hex
        if let Some(decoded) = Self::try_hex(text) {
            results.push(("hex".to_string(), decoded.clone()));
            Self::decode_recursive(&decoded, depth + 1, max_depth, results);
        }

        // Try ROT13
        let rot13 = Self::rot13(text);
        if rot13 != text {
            results.push(("rot13".to_string(), rot13.clone()));
            Self::decode_recursive(&rot13, depth + 1, max_depth, results);
        }
    }

    fn try_base64(text: &str) -> Option<String> {
        // Remove whitespace
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        
        // Must be reasonable length and valid base64 chars
        if cleaned.len() < 20 || !cleaned.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
            return None;
        }

        general_purpose::STANDARD
            .decode(cleaned.as_bytes())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    fn try_hex(text: &str) -> Option<String> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        
        if cleaned.len() < 20 || cleaned.len() % 2 != 0 {
            return None;
        }

        if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        let bytes: Result<Vec<u8>, _> = (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16))
            .collect();

        bytes.ok().and_then(|b| String::from_utf8(b).ok())
    }

    fn rot13(text: &str) -> String {
        text.chars()
            .map(|c| match c {
                'a'..='z' => ((((c as u8 - b'a') + 13) % 26) + b'a') as char,
                'A'..='Z' => ((((c as u8 - b'A') + 13) % 26) + b'A') as char,
                _ => c,
            })
            .collect()
    }
}
