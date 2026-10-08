//! Безопасная запись на диск (раздел 6): временный файл рядом, fsync,
//! атомарное переименование поверх основного. В любой момент на диске лежит
//! либо целиком старый, либо целиком новый файл.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| Error::Io(std::io::Error::other("в пути нет имени файла")))?;

    let tmp = temp_path(dir, &name.to_string_lossy())?;

    let result = write_and_rename(&tmp, path, data);
    if result.is_err() {
        let _ = fs::remove_file(&tmp); // подчищаем за собой, ошибку уборки не показываем
        return result;
    }

    // Фиксируем само переименование. Это best-effort: данные уже на месте,
    // а на некоторых ФС fsync каталога не поддерживается.
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn write_and_rename(tmp: &Path, target: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // хранилище читает только владелец
    }
    let mut f = opts.open(tmp)?;
    f.write_all(data)?;
    f.flush()?;
    f.sync_all()?; // запись полностью завершена до переименования
    drop(f);
    fs::rename(tmp, target)?;
    Ok(())
}

fn temp_path(dir: &Path, name: &str) -> Result<PathBuf> {
    let mut rnd = [0u8; 6];
    getrandom::getrandom(&mut rnd).map_err(|e| Error::Random(e.to_string()))?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    Ok(dir.join(format!(".{name}.{suffix}.tmp")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_replaces_without_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.krabic");

        write_atomic(&p, b"one").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        write_atomic(&p, b"second version").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"second version");

        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["v.krabic"], "временные файлы должны исчезнуть");
    }

    #[test]
    fn failed_write_keeps_old_file_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.krabic");
        write_atomic(&p, b"old").unwrap();

        // Цель, поверх которой нельзя переименовать файл: непустой каталог.
        let blocked = dir.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        fs::write(blocked.join("x"), b"x").unwrap();
        assert!(write_atomic(&blocked, b"new").is_err());

        assert_eq!(fs::read(&p).unwrap(), b"old");
        let leftovers = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.krabic");
        write_atomic(&p, b"x").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
