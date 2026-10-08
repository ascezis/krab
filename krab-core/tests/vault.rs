//! Сквозные тесты через публичное API: круг «сохранить, открыть», неверный пароль,
//! повреждённый байт, подменённый заголовок и т.д.

use std::fs;
use std::path::{Path, PathBuf};

use krab_core::{Entry, EntryType, Error, Field, FieldKind, KdfParams, Vault};
use krab_core::{HEADER_LEN, MEMORY_MIN_KIB, NONCE_LEN};

const PW: &[u8] = b"correct horse battery staple";

fn fast() -> KdfParams {
    KdfParams::new(MEMORY_MIN_KIB, 1, 1).unwrap()
}

fn new_vault() -> (tempfile::TempDir, PathBuf, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.krabic");
    let vault = Vault::create(&path, PW, fast()).unwrap();
    (dir, path, vault)
}

fn sample_entry() -> Entry {
    let mut e = Entry::new(EntryType::Login, "GitHub");
    e.note = "рабочий аккаунт".into();
    e.favorite = true;
    e.source = Some("github.com".into());
    e.fields.push(Field::new("user", "krab", FieldKind::Text));
    e.fields
        .push(Field::new("password", "p@ss-w0rd", FieldKind::Secret));
    e.fields.push(Field::new(
        "login url",
        "https://github.com/login",
        FieldKind::Url,
    ));
    e.add_tag("Работа");
    e.add_tag("dev");
    e
}

fn nonce_of(path: &Path) -> Vec<u8> {
    let b = fs::read(path).unwrap();
    b[HEADER_LEN - NONCE_LEN..HEADER_LEN].to_vec()
}

#[test]
fn save_then_open_roundtrip() {
    let (_d, path, mut v) = new_vault();
    let e = sample_entry();
    let id = v.add(e.clone());
    v.add(Entry::new(EntryType::Note, "пустая заметка"));
    v.save().unwrap();

    let opened = Vault::open(&path, PW).unwrap();
    assert_eq!(opened.entries().len(), 2);
    let back = opened.get(id).expect("запись найдена по id");
    assert_eq!(back.title, "GitHub");
    assert_eq!(back.entry_type, EntryType::Login);
    assert_eq!(back.note, "рабочий аккаунт");
    assert!(back.favorite);
    assert_eq!(back.source.as_deref(), Some("github.com"));
    assert_eq!(back.tags, vec!["работа", "dev"]);
    assert_eq!(back.created_at, e.created_at);
    assert_eq!(back.fields.len(), 3);
    assert_eq!(back.fields[1].label, "password");
    assert_eq!(back.fields[1].value, "p@ss-w0rd");
    assert_eq!(back.fields[1].kind, FieldKind::Secret);
    assert_eq!(opened.kdf_params(), fast());
}

#[test]
fn empty_vault_roundtrip() {
    let (_d, path, _v) = new_vault();
    let opened = Vault::open(&path, PW).unwrap();
    assert!(opened.entries().is_empty());
}

#[test]
fn file_starts_with_magic_and_hides_plaintext() {
    let (_d, path, mut v) = new_vault();
    v.add(sample_entry());
    v.save().unwrap();
    let bytes = fs::read(&path).unwrap();
    assert_eq!(&bytes[..4], b"KRAB");
    assert_eq!(bytes[4], 1);
    for needle in ["GitHub", "p@ss-w0rd", "рабочий аккаунт", "github.com"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "в файле открытым текстом найдено: {needle}"
        );
    }
}

#[test]
fn wrong_password_is_rejected() {
    let (_d, path, _v) = new_vault();
    assert!(matches!(
        Vault::open(&path, b"wrong"),
        Err(Error::WrongPasswordOrCorrupted)
    ));
    assert!(matches!(
        Vault::open(&path, b""),
        Err(Error::WrongPasswordOrCorrupted)
    ));
}

/// Меняем по одному байту в каждой позиции файла: заголовок, шифротекст, пломба.
/// Ни одно изменение не должно давать успешное открытие.
#[test]
fn every_single_byte_flip_is_detected() {
    let (_d, path, mut v) = new_vault();
    v.add(Entry::new(EntryType::Note, "x"));
    v.save().unwrap();
    let original = fs::read(&path).unwrap();

    for i in 0..original.len() {
        let mut tampered = original.clone();
        tampered[i] ^= 0x01;
        fs::write(&path, &tampered).unwrap();
        assert!(
            Vault::open(&path, PW).is_err(),
            "изменение байта {i} (из {}) не обнаружено",
            original.len()
        );
    }

    fs::write(&path, &original).unwrap();
    assert!(
        Vault::open(&path, PW).is_ok(),
        "оригинал должен открываться"
    );
}

#[test]
fn tampered_header_params_are_detected() {
    let (_d, path, _v) = new_vault();
    let original = fs::read(&path).unwrap();

    // passes: 1 -> 2 (в границах, но подмена слабых/сильных параметров должна ломать открытие)
    let mut t = original.clone();
    t[9] = 2;
    fs::write(&path, &t).unwrap();
    assert!(matches!(
        Vault::open(&path, PW),
        Err(Error::WrongPasswordOrCorrupted)
    ));

    // nonce
    let mut t = original.clone();
    t[30] ^= 0xFF;
    fs::write(&path, &t).unwrap();
    assert!(matches!(
        Vault::open(&path, PW),
        Err(Error::WrongPasswordOrCorrupted)
    ));

    // salt
    let mut t = original.clone();
    t[14] ^= 0xFF;
    fs::write(&path, &t).unwrap();
    assert!(matches!(
        Vault::open(&path, PW),
        Err(Error::WrongPasswordOrCorrupted)
    ));
}

#[test]
fn out_of_bounds_params_rejected_before_any_work() {
    let (_d, path, _v) = new_vault();
    let original = fs::read(&path).unwrap();

    // память = u32::MAX KiB (~4 TiB): должен быть быстрый отказ, а не попытка выделить память
    let mut t = original.clone();
    t[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&path, &t).unwrap();
    assert!(matches!(
        Vault::open(&path, PW),
        Err(Error::KdfParamsOutOfRange { .. })
    ));

    // память ниже минимума OWASP
    let mut t = original.clone();
    t[5..9].copy_from_slice(&(MEMORY_MIN_KIB - 1).to_le_bytes());
    fs::write(&path, &t).unwrap();
    assert!(matches!(
        Vault::open(&path, PW),
        Err(Error::KdfParamsOutOfRange { .. })
    ));
}

#[test]
fn not_a_krab_file_and_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x");

    fs::write(&p, b"definitely not a vault, just text").unwrap();
    assert!(matches!(Vault::open(&p, PW), Err(Error::NotAKrabFile)));

    fs::write(&p, b"").unwrap();
    assert!(matches!(Vault::open(&p, PW), Err(Error::NotAKrabFile)));

    let (_d, path, _v) = new_vault();
    let original = fs::read(&path).unwrap();
    // обрезан внутри заголовка
    fs::write(&p, &original[..20]).unwrap();
    assert!(matches!(Vault::open(&p, PW), Err(Error::Truncated)));
    // заголовок есть, пломбы нет
    fs::write(&p, &original[..HEADER_LEN + 5]).unwrap();
    assert!(matches!(Vault::open(&p, PW), Err(Error::Truncated)));
    // отрезан хвост (часть пломбы)
    fs::write(&p, &original[..original.len() - 1]).unwrap();
    assert!(matches!(
        Vault::open(&p, PW),
        Err(Error::WrongPasswordOrCorrupted)
    ));
}

#[test]
fn unsupported_version_is_reported() {
    let (_d, path, _v) = new_vault();
    let mut b = fs::read(&path).unwrap();
    b[4] = 2;
    fs::write(&path, &b).unwrap();
    assert!(matches!(
        Vault::open(&path, PW),
        Err(Error::UnsupportedVersion(2))
    ));
}

#[test]
fn nonce_changes_on_every_save_salt_stays() {
    let (_d, path, mut v) = new_vault();
    let mut nonces = vec![nonce_of(&path)];
    let salt0 = fs::read(&path).unwrap()[14..30].to_vec();
    let mut bodies = vec![fs::read(&path).unwrap()[HEADER_LEN..].to_vec()];

    for _ in 0..5 {
        v.save().unwrap(); // содержимое то же самое
        nonces.push(nonce_of(&path));
        let b = fs::read(&path).unwrap();
        assert_eq!(&b[14..30], &salt0[..], "соль должна оставаться прежней");
        bodies.push(b[HEADER_LEN..].to_vec());
    }

    for i in 0..nonces.len() {
        for j in i + 1..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "nonce повторился: {i} и {j}");
            assert_ne!(
                bodies[i], bodies[j],
                "одинаковое содержимое дало одинаковый шифротекст"
            );
        }
    }
}

#[test]
fn create_refuses_to_overwrite_existing_file() {
    let (_d, path, _v) = new_vault();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Vault::create(&path, b"other", fast()),
        Err(Error::AlreadyExists(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn create_rejects_params_that_could_not_be_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let bad = KdfParams {
        memory_kib: 1024,
        passes: 1,
        parallelism: 1,
    };
    let path = dir.path().join("v.krabic");
    assert!(matches!(
        Vault::create(&path, PW, bad),
        Err(Error::KdfParamsOutOfRange { .. })
    ));
    assert!(!path.exists());
}

#[test]
fn removed_entry_is_gone_after_save() {
    let (_d, path, mut v) = new_vault();
    let keep = v.add(Entry::new(EntryType::Note, "оставить"));
    let kill = v.add(sample_entry());
    v.save().unwrap();

    assert!(v.remove(kill));
    assert!(!v.remove(kill), "повторное удаление ничего не находит");
    v.save().unwrap();

    let opened = Vault::open(&path, PW).unwrap();
    assert_eq!(opened.entries().len(), 1);
    assert!(opened.get(keep).is_some());
    assert!(opened.get(kill).is_none());
}

#[test]
fn edit_in_place_is_persisted() {
    let (_d, path, mut v) = new_vault();
    let id = v.add(sample_entry());
    v.save().unwrap();

    {
        let e = v.get_mut(id).unwrap();
        e.fields[1].value = "new-password".into();
        e.touch();
    }
    v.save().unwrap();

    let opened = Vault::open(&path, PW).unwrap();
    assert_eq!(opened.get(id).unwrap().fields[1].value, "new-password");
}

#[test]
fn unknown_entry_type_survives_open_and_save() {
    let (_d, path, mut v) = new_vault();
    // Эмулируем запись, созданную более новой версией ядра.
    let id = v.add(Entry::new(EntryType::from_name("passkey"), "Passkey"));
    v.save().unwrap();

    let mut reopened = Vault::open(&path, PW).unwrap();
    let e = reopened.get(id).unwrap();
    assert_eq!(e.entry_type, EntryType::Unknown("passkey".into()));
    assert_eq!(e.entry_type.effective(), EntryType::Other);

    reopened.save().unwrap(); // сохранили, не трогая запись
    let again = Vault::open(&path, PW).unwrap();
    assert_eq!(
        again.get(id).unwrap().entry_type,
        EntryType::Unknown("passkey".into()),
        "неизвестный тип должен записываться обратно как был"
    );
}

#[test]
fn rekey_changes_password_salt_and_params() {
    let (_d, path, mut v) = new_vault();
    let id = v.add(sample_entry());
    v.save().unwrap();
    let before = fs::read(&path).unwrap();

    let new_params = KdfParams::new(MEMORY_MIN_KIB + 1024, 2, 1).unwrap();
    v.rekey(b"new password", new_params).unwrap();
    let after = fs::read(&path).unwrap();
    assert_ne!(&before[14..30], &after[14..30], "соль должна смениться");

    assert!(matches!(
        Vault::open(&path, PW),
        Err(Error::WrongPasswordOrCorrupted)
    ));
    let opened = Vault::open(&path, b"new password").unwrap();
    assert_eq!(opened.kdf_params(), new_params);
    assert_eq!(opened.get(id).unwrap().title, "GitHub");

    // и после перенастройки сохранение продолжает работать
    v.save().unwrap();
    assert!(Vault::open(&path, b"new password").is_ok());
}

#[test]
fn rekey_with_invalid_params_changes_nothing() {
    let (_d, path, mut v) = new_vault();
    let before = fs::read(&path).unwrap();
    let bad = KdfParams {
        memory_kib: 1,
        passes: 1,
        parallelism: 1,
    };
    assert!(v.rekey(b"x", bad).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    v.save().unwrap();
    assert!(
        Vault::open(&path, PW).is_ok(),
        "старый пароль всё ещё работает"
    );
}

#[test]
fn save_leaves_no_temp_files() {
    let (dir, _path, mut v) = new_vault();
    for _ in 0..3 {
        v.save().unwrap();
    }
    let names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["test.krabic"]);
}

#[test]
fn create_calibrated_produces_openable_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cal.krabic");
    let v = Vault::create_calibrated(&path, PW).unwrap();
    let params = v.kdf_params();
    assert!(params.validate().is_ok());
    let opened = Vault::open(&path, PW).unwrap();
    assert_eq!(opened.kdf_params(), params);
}
