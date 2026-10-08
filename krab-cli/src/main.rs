mod ui;

use std::fmt;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use inquire::validator::Validation;
use inquire::{CustomUserError, Password, PasswordDisplayMode, Select, Text};
use krab_core::{Entry, EntryType, Field, FieldKind, Vault};

#[derive(Parser)]
#[command(
    name = "krab",
    version,
    about = "Локальное зашифрованное хранилище секретов"
)]
struct Cli {
    /// Путь к файлу хранилища
    #[arg(short, long, env = "KRAB_VAULT", default_value = "vault.krabic")]
    vault: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Создать новое хранилище
    Init,
    /// Список записей
    List,
    /// Добавить новую запись
    Add,
}

fn main() {
    ui::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(&cli.vault),
        Commands::List => cmd_list(&cli.vault),
        Commands::Add => cmd_add(&cli.vault),
    }
}

// ---------------------------------------------------------------- команды

fn cmd_init(path: &Path) {
    ui::banner();
    ui::info(&format!("Новое хранилище: {}", path.display()));

    let password = ui::ask(
        Password::new("Придумайте мастер-пароль:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_custom_confirmation_message("Повторите пароль:")
            .with_custom_confirmation_error_message("Пароли не совпадают.")
            .with_validator(non_empty("Пароль не может быть пустым."))
            .with_help_message("Забудете его, данные не восстановить")
            .prompt(),
    );

    if password.chars().count() < 10 {
        ui::warn("Пароль короткий. Для мастер-пароля лучше длинная фраза.");
    }

    let pb = ui::spinner("Подбираю параметры защиты под эту машину…");
    let created = Vault::create_calibrated(path, password.as_bytes());
    pb.finish_and_clear();

    match created {
        Ok(_) => {
            ui::ok("Хранилище создано");
            ui::hint("Добавить запись: krab add   ·   Показать список: krab list");
        }
        Err(e) => ui::fail(&format!("Не удалось создать хранилище: {e}")),
    }
}

fn cmd_list(path: &Path) {
    ui::header(path);
    let vault = open_vault(path);

    let entries = vault.entries();
    if entries.is_empty() {
        ui::info("Хранилище пусто");
        ui::hint("Добавить запись: krab add");
        return;
    }

    println!("{}", ui::entries_table(entries));
    ui::info(&format!("Записей: {}", entries.len()));
}

fn cmd_add(path: &Path) {
    ui::header(path);
    let mut vault = open_vault(path);

    let kind = ui::ask(Select::new("Тип записи:", Kind::ALL.to_vec()).prompt());
    let entry_type = kind.entry_type();

    let title = ui::ask(
        Text::new("Название:")
            .with_validator(non_empty("Название не может быть пустым."))
            .prompt(),
    );
    let mut entry = Entry::new(entry_type, title.trim());

    match kind {
        Kind::Login => {
            push_field(
                &mut entry,
                "url",
                FieldKind::Url,
                optional_text("URL / сайт:"),
            );
            push_field(
                &mut entry,
                "username",
                FieldKind::Text,
                optional_text("Логин:"),
            );
            push_field(
                &mut entry,
                "password",
                FieldKind::Secret,
                optional_secret("Пароль:"),
            );
        }
        Kind::Note => {
            push_field(
                &mut entry,
                "text",
                FieldKind::Multiline,
                optional_text("Текст заметки:"),
            );
        }
        Kind::Key => {
            push_field(
                &mut entry,
                "key",
                FieldKind::Secret,
                optional_secret("Секретный ключ:"),
            );
        }
        Kind::Totp => {
            push_field(
                &mut entry,
                "totp_secret",
                FieldKind::Totp,
                optional_secret("TOTP-секрет:"),
            );
        }
        Kind::Other => {}
    }

    if let Some(tags) = optional_text("Теги через запятую:") {
        for tag in tags.split(',') {
            let tag = tag.trim();
            if !tag.is_empty() {
                entry.tags.push(tag.to_string());
            }
        }
    }

    vault.add(entry);
    match vault.save() {
        Ok(_) => ui::ok("Запись добавлена"),
        Err(e) => ui::fail(&format!("Не удалось сохранить: {e}")),
    }
}

// ---------------------------------------------------------------- общее

/// Спросить мастер-пароль и открыть хранилище (со спиннером на время Argon2).
fn open_vault(path: &Path) -> Vault {
    if !path.exists() {
        ui::fail(&format!(
            "Хранилище не найдено: {}. Создайте его командой: krab init",
            path.display()
        ));
    }

    let password = ui::ask(
        Password::new("Мастер-пароль:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt(),
    );

    let pb = ui::spinner("Расшифровываю хранилище…");
    let opened = Vault::open(path, password.as_bytes());
    pb.finish_and_clear();

    match opened {
        Ok(v) => v,
        Err(e) => ui::fail(&format!("Не удалось открыть хранилище: {e}")),
    }
}

fn non_empty(
    message: &'static str,
) -> impl Fn(&str) -> Result<Validation, CustomUserError> + Clone {
    move |input: &str| {
        if input.trim().is_empty() {
            Ok(Validation::Invalid(message.into()))
        } else {
            Ok(Validation::Valid)
        }
    }
}

/// Необязательный текст: Enter или Esc пропускают поле, Ctrl+C отменяет всё.
fn optional_text(prompt: &str) -> Option<String> {
    let answer = ui::ask(
        Text::new(prompt)
            .with_help_message("Необязательно, Enter чтобы пропустить")
            .prompt_skippable(),
    );
    answer.filter(|s| !s.trim().is_empty())
}

/// То же для секретов: ввод скрыт точками.
fn optional_secret(prompt: &str) -> Option<String> {
    let answer = ui::ask(
        Password::new(prompt)
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .with_help_message("Необязательно, Enter чтобы пропустить")
            .prompt_skippable(),
    );
    answer.filter(|s| !s.is_empty())
}

fn push_field(entry: &mut Entry, label: &str, kind: FieldKind, value: Option<String>) {
    if let Some(value) = value {
        entry.fields.push(Field::new(label, value, kind));
    }
}

/// Тип записи в меню выбора. Показываемый текст и значение не смешиваются.
#[derive(Clone, Copy)]
enum Kind {
    Login,
    Note,
    Key,
    Totp,
    Other,
}

impl Kind {
    const ALL: [Kind; 5] = [Kind::Login, Kind::Note, Kind::Key, Kind::Totp, Kind::Other];

    fn entry_type(self) -> EntryType {
        match self {
            Kind::Login => EntryType::Login,
            Kind::Note => EntryType::Note,
            Kind::Key => EntryType::Key,
            Kind::Totp => EntryType::Totp,
            Kind::Other => EntryType::Other,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ui::type_label(&self.entry_type()))
    }
}
