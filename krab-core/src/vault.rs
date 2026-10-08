//! Хранилище: шифрование, расшифровка, открытие и сохранение (разделы 4–6).
//!
//! Файл = [заголовок 54 байта, открытый][шифротекст тела][пломба 16 байт].
//! Весь заголовок подаётся в шифр как AAD, поэтому подмена любого его байта
//! (например, слабых параметров KDF) ломает пломбу.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{Header, HEADER_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::kdf::{self, KdfParams, KEY_LEN};
use crate::model::Entry;
use crate::storage;

/// Тело хранилища: корневой CBOR-словарь, чтобы позже можно было добавлять поля.
#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct BodyRef<'a> {
    entries: &'a [Entry],
}

/// Открытое хранилище в памяти. Ключ и записи зануляются при уничтожении.
pub struct Vault {
    path: PathBuf,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; KEY_LEN]>,
    entries: Vec<Entry>,
}

impl Vault {
    /// Создать новое хранилище с параметрами, подобранными под эту машину.
    pub fn create_calibrated(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        Self::create(path, password, KdfParams::calibrate()?)
    }

    /// Создать новое пустое хранилище с заданными параметрами KDF и сразу записать файл.
    /// Существующий файл не перезаписывается.
    pub fn create(path: impl AsRef<Path>, password: &[u8], kdf: KdfParams) -> Result<Self> {
        let path = path.as_ref();
        kdf.validate()?; // не создаём файлы, которые сами же не сможем открыть
        if path.exists() {
            return Err(Error::AlreadyExists(path.to_path_buf()));
        }

        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let key = kdf::derive_key(password, &salt, &kdf)?;

        let mut vault = Self {
            path: path.to_path_buf(),
            kdf,
            salt,
            key,
            entries: Vec::new(),
        };
        vault.save()?;
        Ok(vault)
    }

    /// Открыть хранилище.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path)?;

        // Заголовок разбирается по недоверенным байтам; границы параметров
        // проверяются внутри `parse`, до того как Argon2 выделит память.
        let header = Header::parse(&bytes)?;
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Truncated);
        }

        let key = kdf::derive_key(password, &header.salt, &header.kdf)?;
        let plain = decrypt_body(&key, &bytes)?;

        let body: Body = ciborium::from_reader(plain.as_slice())
            .map_err(|e| Error::Deserialize(e.to_string()))?;

        Ok(Self {
            path: path.to_path_buf(),
            kdf: header.kdf,
            salt: header.salt,
            key,
            entries: body.entries,
        })
    }

    /// Сохранить хранилище. Каждый раз новый случайный nonce (раздел 5.2, правило 1),
    /// соль и параметры KDF остаются прежними.
    pub fn save(&mut self) -> Result<()> {
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let header = Header {
            kdf: self.kdf,
            salt: self.salt,
            nonce,
        };

        let mut plain = Zeroizing::new(Vec::new());
        ciborium::into_writer(
            &BodyRef {
                entries: &self.entries,
            },
            &mut *plain,
        )
        .map_err(|e| Error::Serialize(e.to_string()))?;

        let file = encrypt_file(&self.key, &header, &plain)?;
        storage::write_atomic(&self.path, &file)
    }

    /// Перенастроить KDF: новая соль, новые параметры и (возможно) новый пароль.
    /// Для «просто пересоздать ключ под текущую машину» передайте тот же пароль
    /// и `KdfParams::calibrate()?`. Файл переписывается сразу; если запись не удалась,
    /// в памяти остаётся старый ключ, как и на диске.
    pub fn rekey(&mut self, new_password: &[u8], new_kdf: KdfParams) -> Result<()> {
        new_kdf.validate()?;
        let mut new_salt = [0u8; SALT_LEN];
        fill_random(&mut new_salt)?;
        let new_key = kdf::derive_key(new_password, &new_salt, &new_kdf)?;

        let old_kdf = std::mem::replace(&mut self.kdf, new_kdf);
        let old_salt = std::mem::replace(&mut self.salt, new_salt);
        let old_key = std::mem::replace(&mut self.key, new_key);

        if let Err(e) = self.save() {
            self.kdf = old_kdf;
            self.salt = old_salt;
            self.key = old_key;
            return Err(e);
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    /// Добавить запись в память (на диск попадёт при `save`). Возвращает её id.
    pub fn add(&mut self, entry: Entry) -> Uuid {
        let id = entry.id;
        self.entries.push(entry);
        id
    }

    /// Удалить запись из хранилища (окончательно; подтверждение это дело интерфейса).
    /// Данные записи затираются в памяти при уничтожении. Из файла запись исчезнет
    /// при следующем `save`. Возвращает `true`, если запись была.
    pub fn remove(&mut self, id: Uuid) -> bool {
        match self.entries.iter().position(|e| e.id == id) {
            Some(i) => {
                self.entries.remove(i); // Drop занулит строки записи
                true
            }
            None => false,
        }
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("kdf", &self.kdf)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| Error::Random(e.to_string()))
}

/// Собирает готовый файл: заголовок + шифротекст + пломба.
/// Заголовок целиком идёт как AAD.
fn encrypt_file(key: &[u8; KEY_LEN], header: &Header, plaintext: &[u8]) -> Result<Vec<u8>> {
    let header_bytes = header.to_bytes();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| Error::Encrypt)?;

    let mut file = Vec::with_capacity(HEADER_LEN + sealed.len());
    file.extend_from_slice(&header_bytes);
    file.extend_from_slice(&sealed);
    Ok(file)
}

/// Расшифровка тела. AAD и nonce берутся прямо из байтов файла.
/// Любая неудача проверки пломбы это «неверный пароль или файл повреждён».
fn decrypt_body(key: &[u8; KEY_LEN], file: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if file.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }
    let (aad, sealed) = file.split_at(HEADER_LEN);
    let nonce = &aad[HEADER_LEN - NONCE_LEN..];

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::WrongPasswordOrCorrupted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MEMORY_MIN_KIB;

    fn fast() -> KdfParams {
        KdfParams::new(MEMORY_MIN_KIB, 1, 1).unwrap()
    }

    /// Ключевое свойство раздела 4.3: заголовок входит в пломбу.
    /// Шифруем тем же ключом и тем же nonce, но БЕЗ AAD: файл с правильным ключом
    /// и целым шифротекстом всё равно не должен открыться.
    #[test]
    fn header_is_bound_to_tag_via_aad() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.krabic");
        let mut v = Vault::create(&path, b"pw", fast()).unwrap();
        v.add(Entry::new(crate::model::EntryType::Note, "n"));
        v.save().unwrap();

        let header = Header::parse(&fs::read(&path).unwrap()).unwrap();
        let mut plain = Vec::new();
        ciborium::into_writer(
            &BodyRef {
                entries: v.entries(),
            },
            &mut plain,
        )
        .unwrap();

        // Тот же ключ, тот же nonce, но пломба посчитана без заголовка.
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*v.key));
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&header.nonce),
                Payload {
                    msg: &plain,
                    aad: b"",
                },
            )
            .unwrap();
        let mut forged = header.to_bytes().to_vec();
        forged.extend_from_slice(&sealed);
        fs::write(&path, &forged).unwrap();

        assert!(matches!(
            Vault::open(&path, b"pw"),
            Err(Error::WrongPasswordOrCorrupted)
        ));

        // Контроль: с правильным AAD тот же ключ открывает.
        let good = encrypt_file(&v.key, &header, &plain).unwrap();
        fs::write(&path, &good).unwrap();
        assert!(Vault::open(&path, b"pw").is_ok());
    }

    #[test]
    fn debug_hides_key_and_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create(dir.path().join("v.krabic"), b"pw", fast()).unwrap();
        v.add(Entry::new(crate::model::EntryType::Note, "MY-TITLE"));
        let s = format!("{v:?}");
        assert!(!s.contains("MY-TITLE"));
        assert!(!s.contains("key"));
    }
}
