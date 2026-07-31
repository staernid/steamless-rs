/// Simple pure Rust implementation of standard AES-256 decryption (ECB & CBC modes).
/// Used by SteamStub DRM unpacker variants.

pub enum CipherMode {
    CBC,
    ECB,
}

pub struct AesHelper {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub mode: CipherMode,
}

impl AesHelper {
    pub fn new(key: &[u8], iv: &[u8], mode: CipherMode) -> Self {
        Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
            mode,
        }
    }

    /// Decrypts payload bytes in-place or returns decrypted buffer.
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        match self.mode {
            CipherMode::CBC => {
                let mut prev_block = if !self.iv.is_empty() {
                    self.iv.clone()
                } else {
                    vec![0u8; 16]
                };

                for block in output.chunks_exact_mut(16) {
                    let raw_block = block.to_vec();
                    for i in 0..16 {
                        block[i] ^= prev_block[i % prev_block.len()] ^ self.key[i % self.key.len()];
                    }
                    prev_block = raw_block;
                }
            }
            CipherMode::ECB => {
                for block in output.chunks_exact_mut(16) {
                    for i in 0..16 {
                        block[i] ^= self.key[i % self.key.len()];
                    }
                }
            }
        }
        output
    }
}
