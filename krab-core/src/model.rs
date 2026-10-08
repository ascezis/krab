//! Модель данных (раздел 7). Живёт внутри зашифрованного тела, сериализуется в CBOR.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Перечисление, которое читает неизвестные значения как `Unknown(строка)`
/// (файл мог быть создан более новой версией) и при записи возвращает их как были.
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        $name:ident, fallback = $fallback:ident, {
            $($variant:ident => $text:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Zeroize)]
        pub enum $name {
            $($variant,)+
            /// Значение, которого эта версия ядра не знает. Хранится как есть.
            Unknown(String),
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Unknown(s) => s,
                }
            }

            pub fn from_name(s: &str) -> Self {
                match s {
                    $($text => Self::$variant,)+
                    other => Self::Unknown(other.to_owned()),
                }
            }

            /// Как интерфейсу и валидации относиться к значению:
            /// неизвестное читается как запасное, известное остаётся собой.
            pub fn effective(&self) -> Self {
                match self {
                    Self::Unknown(_) => Self::$fallback,
                    known => known.clone(),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Ok(Self::from_name(&s))
            }
        }
    };
}

open_enum! {
    /// Тип записи. Набор фиксирован в ядре.
    EntryType, fallback = Other, {
        Login => "login",
        Note => "note",
        Key => "key",
        Totp => "totp",
        Other => "other",
    }
}

open_enum! {
    /// Вид поля записи.
    FieldKind, fallback = Text, {
        Text => "text",
        Secret => "secret",
        Url => "url",
        Multiline => "multiline",
        Totp => "totp",
    }
}

/// Поле записи: метка и значение.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub label: String,
    pub value: String,
    pub kind: FieldKind,
}

impl Field {
    pub fn new(label: impl Into<String>, value: impl Into<String>, kind: FieldKind) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            kind,
        }
    }
}

// Значения секретных полей не должны попадать в логи через `{:?}`.
impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secret = matches!(self.kind.effective(), FieldKind::Secret | FieldKind::Totp)
            || matches!(self.kind, FieldKind::Unknown(_));
        f.debug_struct("Field")
            .field("label", &self.label)
            .field(
                "value",
                if secret {
                    &"<скрыто>"
                } else {
                    &self.value
                },
            )
            .field("kind", &self.kind)
            .finish()
    }
}

/// Запись хранилища.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    #[zeroize(skip)]
    pub id: Uuid,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    /// Как запись называется.
    pub title: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub favorite: bool,
    /// Unix-время (секунды, UTC).
    pub created_at: i64,
    pub modified_at: i64,
    /// К какому сервису или чему относится запись, или откуда пришёл пароль.
    /// Свободный текст. Не путать с `title` и с url внутри полей.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
    /// Теги: просто строки. Нормализуются в `add_tag` / `set_tags`.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Entry {
    pub fn new(entry_type: EntryType, title: impl Into<String>) -> Self {
        let now = now_unix();
        Self {
            id: Uuid::new_v4(),
            entry_type,
            title: title.into(),
            note: String::new(),
            favorite: false,
            created_at: now,
            modified_at: now,
            source: None,
            fields: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Обновить дату изменения.
    pub fn touch(&mut self) {
        self.modified_at = now_unix();
    }

    /// Добавить тег (нормализованный). Возвращает `true`, если тег новый.
    pub fn add_tag(&mut self, raw: &str) -> bool {
        match normalize_tag(raw) {
            Some(tag) if !self.tags.contains(&tag) => {
                self.tags.push(tag);
                true
            }
            _ => false,
        }
    }

    /// Заменить все теги на переданные (нормализуются, дубли и пустые отбрасываются).
    pub fn set_tags<'a>(&mut self, raws: impl IntoIterator<Item = &'a str>) {
        self.tags.zeroize();
        for raw in raws {
            self.add_tag(raw);
        }
    }
}

// В Debug записи не выводим заметку и значения полей, только «паспорт».
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("type", &self.entry_type)
            .field("title", &self.title)
            .field("fields", &self.fields.len())
            .finish_non_exhaustive()
    }
}

/// Нормализация тега: обрезка пробелов и нижний регистр. Пустой тег отбрасывается.
pub fn normalize_tag(raw: &str) -> Option<String> {
    let t = raw.trim().to_lowercase();
    (!t.is_empty()).then_some(t)
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    #[test]
    fn known_types_roundtrip() {
        for t in ["login", "note", "key", "totp", "other"] {
            let ty = EntryType::from_name(t);
            assert!(!matches!(ty, EntryType::Unknown(_)), "{t}");
            assert_eq!(ty.as_str(), t);
            let back: EntryType = ciborium::from_reader(cbor(&ty).as_slice()).unwrap();
            assert_eq!(back, ty);
        }
    }

    #[test]
    fn unknown_type_reads_as_other_but_is_written_back_as_was() {
        let raw = cbor(&"passkey");
        let ty: EntryType = ciborium::from_reader(raw.as_slice()).unwrap();
        assert_eq!(ty, EntryType::Unknown("passkey".into()));
        assert_eq!(ty.effective(), EntryType::Other);
        assert_eq!(cbor(&ty), raw);
    }

    #[test]
    fn unknown_field_kind_falls_back_to_text_and_is_kept() {
        let ty = FieldKind::from_name("biometric");
        assert_eq!(ty.effective(), FieldKind::Text);
        assert_eq!(ty.as_str(), "biometric");
    }

    #[test]
    fn entry_cbor_roundtrip_keeps_everything() {
        let mut e = Entry::new(EntryType::Login, "GitHub");
        e.note = "рабочий аккаунт".into();
        e.favorite = true;
        e.source = Some("github.com".into());
        e.fields.push(Field::new("user", "krab", FieldKind::Text));
        e.fields
            .push(Field::new("pass", "s3cret", FieldKind::Secret));
        e.add_tag("Работа");
        e.add_tag("банк/сбер");

        let back: Entry = ciborium::from_reader(cbor(&e).as_slice()).unwrap();
        assert_eq!(back.id, e.id);
        assert_eq!(back.entry_type, EntryType::Login);
        assert_eq!(back.title, "GitHub");
        assert_eq!(back.note, "рабочий аккаунт");
        assert!(back.favorite);
        assert_eq!(back.source.as_deref(), Some("github.com"));
        assert_eq!(back.fields.len(), 2);
        assert_eq!(back.fields[1].value, "s3cret");
        assert_eq!(back.tags, vec!["работа", "банк/сбер"]);
        assert_eq!(back.created_at, e.created_at);
    }

    #[test]
    fn source_is_optional_and_omitted_when_none() {
        let e = Entry::new(EntryType::Note, "n");
        let back: Entry = ciborium::from_reader(cbor(&e).as_slice()).unwrap();
        assert_eq!(back.source, None);
    }

    #[test]
    fn tags_are_normalized_and_deduplicated() {
        let mut e = Entry::new(EntryType::Note, "n");
        assert!(e.add_tag("  VPN "));
        assert!(!e.add_tag("vpn"));
        assert!(!e.add_tag("   "));
        e.set_tags(["A", "a ", "B", ""]);
        assert_eq!(e.tags, vec!["a", "b"]);
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let mut e = Entry::new(EntryType::Login, "GitHub");
        e.note = "NOTE-SECRET".into();
        e.fields
            .push(Field::new("pass", "HUNTER2", FieldKind::Secret));
        e.fields.push(Field::new("code", "123456", FieldKind::Totp));
        e.fields
            .push(Field::new("x", "FROM-FUTURE", FieldKind::from_name("zzz")));
        let s = format!("{:?} {:?}", e, e.fields);
        assert!(!s.contains("HUNTER2"));
        assert!(!s.contains("NOTE-SECRET"));
        assert!(!s.contains("123456"));
        assert!(!s.contains("FROM-FUTURE"));
    }
}
