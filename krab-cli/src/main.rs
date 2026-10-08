use clap::{Parser, Subcommand};
use colored::Colorize;
use inquire::{Password, Select, Text};
use krab_core::{Vault, Entry, EntryType, Field, FieldKind};
use std::path::PathBuf;
use std::process;

const ASCII_CRAB: &str = r#"
    /\_/\  /\_/   ( o.o )( o.o )
    > ^ <  > ^ <
  /|     ||     |\
 (_|_____|_____|_)
     k r a b
"#;

#[derive(Parser)]
#[command(name = "krab", version = "0.1.0", about = "Локальное зашифрованное хранилище секретов", long_about = None)]
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
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => {
            println!("{}", ASCII_CRAB.truecolor(255, 87, 34)); // Orange crab
            println!("Создание нового хранилища по пути: {}", cli.vault.display().to_string().cyan());
            
            let password = match Password::new("Придумайте мастер-пароль:").without_confirmation().prompt() {
                Ok(p) => p,
                Err(_) => process::exit(1),
            };
            
            if password.is_empty() {
                eprintln!("{}", "✗ Пароль не может быть пустым.".red());
                process::exit(1);
            }

            let confirm = match Password::new("Повторите пароль:").without_confirmation().prompt() {
                Ok(p) => p,
                Err(_) => process::exit(1),
            };

            if password != confirm {
                eprintln!("{}", "✗ Пароли не совпадают.".red());
                process::exit(1);
            }

            println!("{}", "⚡ Калибровка защиты под вашу систему (это займет около секунды)...".yellow());
            
            match Vault::create_calibrated(&cli.vault, password.as_bytes()) {
                Ok(_) => println!("{}", "✓ Хранилище успешно создано!".green().bold()),
                Err(e) => {
                    eprintln!("{} {}", "✗ Ошибка создания:".red(), e);
                    process::exit(1);
                }
            }
        }
        Commands::List => {
            let password = match Password::new("Мастер-пароль:").without_confirmation().prompt() {
                Ok(p) => p,
                Err(_) => process::exit(1),
            };

            let vault = match Vault::open(&cli.vault, password.as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{} {}", "✗ Ошибка открытия:".red(), e);
                    process::exit(1);
                }
            };

            let entries = vault.entries();
            if entries.is_empty() {
                println!("{}", "Хранилище пусто.".yellow());
            } else {
                println!("Найдено записей: {}", entries.len().to_string().cyan());
                for entry in entries {
                    println!("- [{}] {} ({})", entry.entry_type.as_str().cyan(), entry.title, entry.id.to_string().bright_black());
                }
            }
        }
        Commands::Add => {
            let password = match Password::new("Мастер-пароль:").without_confirmation().prompt() {
                Ok(p) => p,
                Err(_) => process::exit(1),
            };

            let mut vault = match Vault::open(&cli.vault, password.as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{} {}", "✗ Ошибка открытия:".red(), e);
                    process::exit(1);
                }
            };

            let options = vec!["🔑 Login", "📝 Note", "🗝️ Key", "⏱️ TOTP", "📦 Other"];
            let choice = match Select::new("Тип записи:", options).prompt() {
                Ok(c) => c,
                Err(_) => process::exit(1),
            };

            let entry_type = match choice {
                "🔑 Login" => EntryType::Login,
                "📝 Note" => EntryType::Note,
                "🗝️ Key" => EntryType::Key,
                "⏱️ TOTP" => EntryType::Totp,
                _ => EntryType::Other,
            };

            let title = match Text::new("Название:").prompt() {
                Ok(t) => t,
                Err(_) => process::exit(1),
            };

            if title.is_empty() {
                eprintln!("{}", "✗ Название не может быть пустым.".red());
                process::exit(1);
            }

            let mut entry = Entry::new(entry_type.clone(), &title);

            match entry_type {
                EntryType::Login => {
                    if let Ok(url) = Text::new("URL/Сайт (опционально):").prompt() {
                        if !url.is_empty() {
                            entry.fields.push(Field::new("url", url, FieldKind::Url));
                        }
                    }
                    if let Ok(username) = Text::new("Логин:").prompt() {
                        if !username.is_empty() {
                            entry.fields.push(Field::new("username", username, FieldKind::Text));
                        }
                    }
                    if let Ok(pass) = Password::new("Пароль:").without_confirmation().prompt() {
                        if !pass.is_empty() {
                            entry.fields.push(Field::new("password", pass, FieldKind::Secret));
                        }
                    }
                }
                EntryType::Note => {
                    if let Ok(text) = Text::new("Текст заметки:").prompt() {
                        if !text.is_empty() {
                            entry.fields.push(Field::new("text", text, FieldKind::Multiline));
                        }
                    }
                }
                EntryType::Key => {
                    if let Ok(key) = Password::new("Секретный ключ:").without_confirmation().prompt() {
                        if !key.is_empty() {
                            entry.fields.push(Field::new("key", key, FieldKind::Secret));
                        }
                    }
                }
                EntryType::Totp => {
                    if let Ok(secret) = Password::new("TOTP секрет:").without_confirmation().prompt() {
                        if !secret.is_empty() {
                            entry.fields.push(Field::new("totp_secret", secret, FieldKind::Totp));
                        }
                    }
                }
                _ => {}
            }

            if let Ok(tags_input) = Text::new("Теги (через запятую, опционально):").prompt() {
                for tag in tags_input.split(',') {
                    let tag = tag.trim();
                    if !tag.is_empty() {
                        entry.tags.push(tag.to_string());
                    }
                }
            }

            vault.add(entry);
            match vault.save() {
                Ok(_) => println!("{}", "✓ Запись добавлена!".green().bold()),
                Err(e) => {
                    eprintln!("{} {}", "✗ Ошибка сохранения:".red(), e);
                    process::exit(1);
                }
            }
        }
    }
}