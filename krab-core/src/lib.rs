//! krab-core: ядро локального зашифрованного хранилища секретов.
//!
//! Ядро хранит и считает, интерфейс показывает. Формат файла и крипто описаны
//! в `ARCHITECTURE.md`. Модель угроз: потеря устройства и холодный доступ к файлу.
//! Формат и «непонятность» файла защитой не являются, защита это только шифр и пароль.
//!
//! Публичное API пока черновое (шаг 3 плана): `Vault::create/open/save`,
//! простые `add/get/remove`, `rekey`.

#![forbid(unsafe_code)]

pub mod error;
pub(crate) mod header;
pub(crate) mod kdf;
pub mod model;
pub(crate) mod storage;
pub mod vault;

// Типы и значения, которые нужны снаружи (CLI, тесты).
// Внутренняя кухня (header, kdf, storage) снаружи не видна.
pub use error::{Error, Result};
pub use header::{HEADER_LEN, NONCE_LEN};
pub use kdf::{KdfParams, MEMORY_MIN_KIB};
pub use model::{Entry, EntryType, Field, FieldKind};
pub use vault::Vault;
