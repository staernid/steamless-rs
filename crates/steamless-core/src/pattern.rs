/// High-performance byte pattern scanner supporting wildcard byte tokens (`??`).
///
/// # Example
/// ```ignore
/// let data = [0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x50];
/// let pos = find_pattern(&data, "E8 00 00 00 00 50");
/// assert_eq!(pos, Some(1));
/// ```
pub fn find_pattern(data: &[u8], pattern: &str) -> Option<usize> {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.is_empty() || data.len() < tokens.len() {
        return None;
    }

    let mut pattern_bytes = Vec::with_capacity(tokens.len());
    let mut pattern_mask = Vec::with_capacity(tokens.len());

    for token in tokens {
        if token == "??" || token == "?" {
            pattern_bytes.push(0u8);
            pattern_mask.push(false);
        } else if let Ok(val) = u8::from_str_radix(token, 16) {
            pattern_bytes.push(val);
            pattern_mask.push(true);
        } else {
            return None;
        }
    }

    let len = pattern_bytes.len();
    if data.len() < len {
        return None;
    }

    'outer: for i in 0..=(data.len() - len) {
        for j in 0..len {
            if pattern_mask[j] && data[i + j] != pattern_bytes[j] {
                continue 'outer;
            }
        }
        return Some(i);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_find() {
        let data = vec![0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00];
        assert_eq!(find_pattern(&data, "55 8B EC 81 EC ?? ?? ?? ??"), Some(0));
        assert_eq!(find_pattern(&data, "81 EC 00"), Some(3));
        assert_eq!(find_pattern(&data, "FF FF"), None);
    }
}
