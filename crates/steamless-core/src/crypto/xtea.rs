/// SteamStub XOR decryption algorithm.
/// Decrypts stream data in-place using key chaining.
pub fn steam_xor(data: &mut [u8], mut key: u32) -> u32 {
    let mut offset = 0;
    if key == 0 && data.len() >= 4 {
        offset = 4;
        key = u32::from_le_bytes(data[0..4].try_into().unwrap());
    }

    for chunk in data[offset..].chunks_exact_mut(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap());
        let decoded = val ^ key;
        chunk.copy_from_slice(&decoded.to_le_bytes());
        key = val;
    }

    key
}

/// XTEA 32-round block decryption pass 2.
pub fn steam_drmp_decrypt_pass2(keys: &[u32; 4], mut v1: u32, mut v2: u32, n: u32) -> (u32, u32) {
    const DELTA: u32 = 0x9E3779B9;
    let mut sum = DELTA.wrapping_mul(n);

    for _ in 0..n {
        let temp1 = ((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1);
        let key_idx1 = ((sum >> 11) & 3) as usize;
        let temp2 = sum.wrapping_add(keys[key_idx1]);
        v2 = v2.wrapping_sub(temp1 ^ temp2);

        sum = sum.wrapping_sub(DELTA);

        let temp3 = ((v2 << 4) ^ (v2 >> 5)).wrapping_add(v2);
        let key_idx2 = (sum & 3) as usize;
        let temp4 = sum.wrapping_add(keys[key_idx2]);
        v1 = v1.wrapping_sub(temp3 ^ temp4);
    }

    (v1, v2)
}

/// SteamDRMP XTEA pass 1 CBC-like stream decryption.
pub fn steam_drmp_decrypt_pass1(data: &mut [u8], keys: &[u32; 4]) {
    let mut v1: u32 = 0x55555555;
    let mut v2: u32 = 0x55555555;

    for chunk in data.chunks_exact_mut(8) {
        let d1 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let d2 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());

        let (res1, res2) = steam_drmp_decrypt_pass2(keys, d1, d2, 32);

        let out1 = res1 ^ v1;
        let out2 = res2 ^ v2;

        chunk[0..4].copy_from_slice(&out1.to_le_bytes());
        chunk[4..8].copy_from_slice(&out2.to_le_bytes());

        v1 = d1;
        v2 = d2;
    }
}
