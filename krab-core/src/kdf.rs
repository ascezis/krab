//! Argon2id: параметры, границы допустимого, подбор под машину, получение ключа.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;

// Границы при открытии файла (раздел 5.3). Хардкодим границы, а не значения.
// Расширять безопасно, сужать осторожно: старые файлы перестанут открываться.
pub const MEMORY_MIN_KIB: u32 = 19_456; // 19 MiB, минимум по OWASP
pub const MEMORY_MAX_KIB: u32 = 1_048_576; // 1 GiB
pub const PASSES_MIN: u32 = 1;
pub const PASSES_MAX: u32 = 10;
pub const PARALLELISM_MIN: u8 = 1;
pub const PARALLELISM_MAX: u8 = 8;

/// Потолок памяти при подборе параметров (чтобы файл открывался на обычном ноутбуке).
pub const CALIBRATE_MEMORY_CAP_KIB: u32 = 262_144; // 256 MiB
/// Потолок параллелизма при подборе. Файл, созданный на 16-ядерной машине, не должен
/// открываться в 4 раза медленнее на ноутбуке с 4 ядрами. Граница при открытии при этом
/// остаётся 8.
pub const CALIBRATE_PARALLELISM_CAP: u8 = 4;
/// Целевая пауза при открытии: 0,5–1 с, метим в середину.
const TARGET_SECS: f64 = 0.75;
const TARGET_MAX_SECS: f64 = 1.0;

/// Параметры Argon2id. Лежат в заголовке файла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Память в KiB, идёт в Argon2 как есть, без пересчёта.
    pub memory_kib: u32,
    pub passes: u32,
    pub parallelism: u8,
}

impl KdfParams {
    pub fn new(memory_kib: u32, passes: u32, parallelism: u8) -> Result<Self> {
        let p = Self {
            memory_kib,
            passes,
            parallelism,
        };
        p.validate()?;
        Ok(p)
    }

    /// Проверка границ. Вызывается до любого выделения памяти под Argon2.
    pub fn validate(&self) -> Result<()> {
        check(
            "память (KiB)",
            self.memory_kib as u64,
            MEMORY_MIN_KIB as u64,
            MEMORY_MAX_KIB as u64,
        )?;
        check(
            "проходы",
            self.passes as u64,
            PASSES_MIN as u64,
            PASSES_MAX as u64,
        )?;
        check(
            "параллелизм",
            self.parallelism as u64,
            PARALLELISM_MIN as u64,
            PARALLELISM_MAX as u64,
        )
    }

    /// Замеряет скорость этой машины и подбирает параметры под паузу ~0,5–1 с.
    pub fn calibrate() -> Result<Self> {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let parallelism =
            cores.clamp(PARALLELISM_MIN as usize, CALIBRATE_PARALLELISM_CAP as usize) as u8;

        let probe = Self {
            memory_kib: CALIBRATE_MEMORY_CAP_KIB,
            passes: 1,
            parallelism,
        };
        let started = Instant::now();
        derive_key(b"krab-calibration", &[0u8; 16], &probe)?;
        Ok(plan(started.elapsed(), probe.memory_kib, parallelism))
    }
}

fn check(name: &'static str, value: u64, min: u64, max: u64) -> Result<()> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(Error::KdfParamsOutOfRange {
            name,
            value,
            min,
            max,
        })
    }
}

/// Выбор параметров по замеру одного прохода при `memory_kib`.
/// Время Argon2 примерно линейно по памяти и по числу проходов.
fn plan(one_pass: Duration, memory_kib: u32, parallelism: u8) -> KdfParams {
    let secs = one_pass.as_secs_f64().max(1e-6);

    if secs > TARGET_MAX_SECS {
        // Даже один проход слишком долгий: урезаем память (кратно 1 MiB), но не ниже минимума.
        let scaled = (memory_kib as f64 * TARGET_SECS / secs) as u32;
        let memory = (scaled / 1024 * 1024).max(MEMORY_MIN_KIB).min(memory_kib);
        return KdfParams {
            memory_kib: memory,
            passes: PASSES_MIN,
            parallelism,
        };
    }

    let passes = ((TARGET_SECS / secs).round() as u32).clamp(PASSES_MIN, PASSES_MAX);
    KdfParams {
        memory_kib,
        passes,
        parallelism,
    }
}

/// Пароль + соль + параметры → 32-байтный ключ. Параметры должны быть уже проверены,
/// но на всякий случай проверяем ещё раз: дёшево, а защита от выделения гигабайтов.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.passes,
        params.parallelism as u32,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn bounds_accept_edges() {
        assert!(KdfParams::new(MEMORY_MIN_KIB, 1, 1).is_ok());
        assert!(KdfParams::new(MEMORY_MAX_KIB, 10, 8).is_ok());
    }

    #[test]
    fn bounds_reject_outside() {
        assert!(KdfParams::new(MEMORY_MIN_KIB - 1, 1, 1).is_err());
        assert!(KdfParams::new(MEMORY_MAX_KIB + 1, 1, 1).is_err());
        assert!(KdfParams::new(MEMORY_MIN_KIB, 0, 1).is_err());
        assert!(KdfParams::new(MEMORY_MIN_KIB, 11, 1).is_err());
        assert!(KdfParams::new(MEMORY_MIN_KIB, 1, 0).is_err());
        assert!(KdfParams::new(MEMORY_MIN_KIB, 1, 9).is_err());
        assert!(KdfParams::new(u32::MAX, 1, 1).is_err());
    }

    #[test]
    fn derive_key_rejects_bad_params_without_work() {
        let bad = KdfParams {
            memory_kib: u32::MAX,
            passes: 1,
            parallelism: 1,
        };
        assert!(matches!(
            derive_key(b"pw", &[0u8; 16], &bad),
            Err(Error::KdfParamsOutOfRange { .. })
        ));
    }

    #[test]
    fn derive_key_is_deterministic_and_sensitive() {
        let p = KdfParams::new(MEMORY_MIN_KIB, 1, 1).unwrap();
        let a = derive_key(b"pw", &[1u8; 16], &p).unwrap();
        let b = derive_key(b"pw", &[1u8; 16], &p).unwrap();
        let c = derive_key(b"pw2", &[1u8; 16], &p).unwrap();
        let d = derive_key(b"pw", &[2u8; 16], &p).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    #[test]
    fn plan_fast_machine_adds_passes() {
        // 100 мс за проход -> ~7-8 проходов под 0,75 с
        let p = plan(ms(100), CALIBRATE_MEMORY_CAP_KIB, 4);
        assert_eq!(p.memory_kib, CALIBRATE_MEMORY_CAP_KIB);
        assert_eq!(p.passes, 8); // round(7.5) = 8
        assert!(p.validate().is_ok());
    }

    #[test]
    fn plan_very_fast_machine_caps_passes() {
        let p = plan(ms(1), CALIBRATE_MEMORY_CAP_KIB, 4);
        assert_eq!(p.passes, PASSES_MAX);
    }

    #[test]
    fn plan_mid_machine_one_pass() {
        let p = plan(ms(800), CALIBRATE_MEMORY_CAP_KIB, 2);
        assert_eq!(p.passes, 1);
        assert_eq!(p.memory_kib, CALIBRATE_MEMORY_CAP_KIB);
    }

    #[test]
    fn plan_slow_machine_reduces_memory() {
        // 3 с за проход при 256 MiB -> ~64 MiB, кратно 1 MiB
        let p = plan(Duration::from_secs(3), CALIBRATE_MEMORY_CAP_KIB, 2);
        assert_eq!(p.passes, 1);
        assert_eq!(p.memory_kib, 65_536);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn plan_never_goes_below_minimum_memory() {
        let p = plan(Duration::from_secs(600), CALIBRATE_MEMORY_CAP_KIB, 1);
        assert_eq!(p.memory_kib, MEMORY_MIN_KIB);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn calibrate_returns_valid_params_within_cap() {
        let p = KdfParams::calibrate().unwrap();
        assert!(p.validate().is_ok());
        assert!(p.memory_kib <= CALIBRATE_MEMORY_CAP_KIB);
        assert!(p.parallelism <= CALIBRATE_PARALLELISM_CAP);
    }
}
