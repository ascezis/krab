//! Заголовок файла: 54 байта, фиксированная раскладка, little-endian (раздел 4).
//!
//! Заголовок разбирается ДО проверки пломбы, то есть по недоверенным байтам.
//! Поэтому парсер намеренно тупой: читаем по известным смещениям, проверяем границы.

use crate::error::{Error, Result};
use crate::kdf::KdfParams;

pub const MAGIC: [u8; 4] = *b"KRAB";
pub const VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 54;

// Смещения полей.
const OFF_VERSION: usize = 4;
const OFF_MEMORY: usize = 5;
const OFF_PASSES: usize = 9;
const OFF_PARALLELISM: usize = 13;
const OFF_SALT: usize = 14;
const OFF_NONCE: usize = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[..4].copy_from_slice(&MAGIC);
        b[OFF_VERSION] = VERSION;
        b[OFF_MEMORY..OFF_MEMORY + 4].copy_from_slice(&self.kdf.memory_kib.to_le_bytes());
        b[OFF_PASSES..OFF_PASSES + 4].copy_from_slice(&self.kdf.passes.to_le_bytes());
        b[OFF_PARALLELISM] = self.kdf.parallelism;
        b[OFF_SALT..OFF_SALT + SALT_LEN].copy_from_slice(&self.salt);
        b[OFF_NONCE..OFF_NONCE + NONCE_LEN].copy_from_slice(&self.nonce);
        b
    }

    /// Разбор заголовка из начала файла. Проверяет сигнатуру, версию и границы
    /// параметров Argon2id (раздел 5.1, шаг 2): после успешного разбора параметры
    /// уже безопасно передавать в KDF.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let n = bytes.len().min(MAGIC.len());
        // Пустой файл совпадает с любым префиксом, но хранилищем не является.
        if bytes.is_empty() || bytes[..n] != MAGIC[..n] {
            return Err(Error::NotAKrabFile);
        }
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let version = bytes[OFF_VERSION];
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let kdf = KdfParams {
            memory_kib: read_u32(bytes, OFF_MEMORY),
            passes: read_u32(bytes, OFF_PASSES),
            parallelism: bytes[OFF_PARALLELISM],
        };
        kdf.validate()?;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[OFF_SALT..OFF_SALT + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[OFF_NONCE..OFF_NONCE + NONCE_LEN]);

        Ok(Self { kdf, salt, nonce })
    }
}

fn read_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MEMORY_MIN_KIB;

    fn sample() -> Header {
        Header {
            kdf: KdfParams {
                memory_kib: 65_536,
                passes: 3,
                parallelism: 2,
            },
            salt: [0xAA; SALT_LEN],
            nonce: [0xBB; NONCE_LEN],
        }
    }

    #[test]
    fn layout_is_exactly_as_documented() {
        let b = sample().to_bytes();
        assert_eq!(b.len(), 54);
        assert_eq!(&b[0..4], b"KRAB");
        assert_eq!(b[4], 1);
        assert_eq!(&b[5..9], &[0x00, 0x00, 0x01, 0x00]); // 65536 LE
        assert_eq!(&b[9..13], &[3, 0, 0, 0]);
        assert_eq!(b[13], 2);
        assert_eq!(&b[14..30], &[0xAA; 16]);
        assert_eq!(&b[30..54], &[0xBB; 24]);
    }

    #[test]
    fn roundtrip() {
        let h = sample();
        assert_eq!(Header::parse(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn parse_ignores_bytes_after_header() {
        let mut v = sample().to_bytes().to_vec();
        v.extend_from_slice(&[1, 2, 3]);
        assert_eq!(Header::parse(&v).unwrap(), sample());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut b = sample().to_bytes();
        b[0] = b'X';
        assert!(matches!(Header::parse(&b), Err(Error::NotAKrabFile)));
        assert!(matches!(Header::parse(b""), Err(Error::NotAKrabFile)));
        assert!(matches!(Header::parse(b"hello"), Err(Error::NotAKrabFile)));
    }

    #[test]
    fn rejects_truncated() {
        let b = sample().to_bytes();
        assert!(matches!(Header::parse(&b[..4]), Err(Error::Truncated)));
        assert!(matches!(Header::parse(&b[..53]), Err(Error::Truncated)));
        assert!(matches!(Header::parse(b"KR"), Err(Error::Truncated)));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut b = sample().to_bytes();
        b[4] = 2;
        assert!(matches!(
            Header::parse(&b),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_params_out_of_bounds() {
        let set = |off: usize, bytes: &[u8]| {
            let mut b = sample().to_bytes();
            b[off..off + bytes.len()].copy_from_slice(bytes);
            b
        };
        let below = (MEMORY_MIN_KIB - 1).to_le_bytes();
        for b in [
            set(OFF_MEMORY, &below),
            set(OFF_MEMORY, &u32::MAX.to_le_bytes()),
            set(OFF_PASSES, &0u32.to_le_bytes()),
            set(OFF_PASSES, &11u32.to_le_bytes()),
            set(OFF_PARALLELISM, &[0]),
            set(OFF_PARALLELISM, &[9]),
        ] {
            assert!(matches!(
                Header::parse(&b),
                Err(Error::KdfParamsOutOfRange { .. })
            ));
        }
    }
}
