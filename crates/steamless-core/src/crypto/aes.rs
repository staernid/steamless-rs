use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit};
use aes::Aes256;
use cbc::cipher::KeyIvInit;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Rebuilds the current IV by decrypting `iv` using AES-256-ECB with the key.
    pub fn rebuild_iv(&mut self, iv: &[u8]) -> bool {
        if iv.len() < 16 || self.key.len() < 32 {
            return false;
        }

        if let Ok(cipher) = Aes256::new_from_slice(&self.key[..32]) {
            let mut block = *aes::Block::from_slice(&iv[..16]);
            cipher.decrypt_block(&mut block);
            self.iv = block.to_vec();
            true
        } else {
            false
        }
    }

    /// Decrypts payload bytes in-place or returns decrypted buffer.
    pub fn decrypt(&self, data: &[u8], mode: CipherMode) -> Vec<u8> {
        if data.is_empty() || self.key.len() < 32 {
            return data.to_vec();
        }

        let mut output = data.to_vec();

        match mode {
            CipherMode::ECB => {
                if let Ok(cipher) = Aes256::new_from_slice(&self.key[..32]) {
                    for chunk in output.chunks_exact_mut(16) {
                        let mut block = *aes::Block::from_slice(chunk);
                        cipher.decrypt_block(&mut block);
                        chunk.copy_from_slice(&block);
                    }
                }
            }
            CipherMode::CBC => {
                let iv_bytes = if self.iv.len() >= 16 {
                    &self.iv[..16]
                } else {
                    &[0u8; 16]
                };

                if let Ok(decryptor) = Aes256CbcDec::new_from_slices(&self.key[..32], iv_bytes) {
                    let _ = decryptor.decrypt_padded_mut::<NoPadding>(&mut output);
                }
            }
        }

        output
    }
}
