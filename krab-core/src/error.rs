use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] io::Error),

    #[error("это не файл хранилища krab (нет сигнатуры KRAB)")]
    NotAKrabFile,

    #[error("файл слишком короткий, чтобы быть хранилищем")]
    Truncated,

    #[error("неподдерживаемая версия формата: {0}")]
    UnsupportedVersion(u8),

    #[error("параметр Argon2id «{name}» = {value} вне допустимых границ {min}…{max}")]
    KdfParamsOutOfRange {
        name: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },

    /// Пломба не сошлась. Неверный пароль и повреждённый файл различить нельзя.
    #[error("неверный пароль или файл повреждён")]
    WrongPasswordOrCorrupted,

    #[error("ошибка Argon2id: {0}")]
    Kdf(String),

    #[error("не удалось получить случайные байты от ОС: {0}")]
    Random(String),

    #[error("не удалось зашифровать данные")]
    Encrypt,

    #[error("не удалось сериализовать тело хранилища: {0}")]
    Serialize(String),

    /// Пломба сошлась (данные целые), но CBOR не разбирается.
    #[error("тело хранилища расшифровано, но не разбирается: {0}")]
    Deserialize(String),

    #[error("файл уже существует: {}", .0.display())]
    AlreadyExists(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;
