//! Оформление CLI: цвета, баннер, спиннер, таблица, единый стиль сообщений.
//!
//! Правило: всё «оформление» (баннер, статусы, спиннер) уходит в stderr,
//! а данные (таблица записей) в stdout. Так вывод можно будет спокойно
//! перенаправлять в файл или в другую программу.
//!
//! Цвета отключаются стандартной переменной `NO_COLOR` (это умеет `colored`).

use std::io::IsTerminal;
use std::process;
use std::time::Duration;

use colored::Colorize;
use comfy_table::{Cell, Color as TableColor, ContentArrangement, Table, modifiers, presets};
use indicatif::{ProgressBar, ProgressStyle};
use inquire::InquireError;
use inquire::ui::{Color, RenderConfig, StyleSheet, Styled};
use krab_core::{Entry, EntryType};

/// Фирменный оранжевый.
const ACCENT: (u8, u8, u8) = (255, 90, 0);

/// Пиксельный краб (зеркалится из левой половины, сгенерирован design/gen_banner.py).
const CRAB: [&str; 5] = [
    " ▄▀▀▀▄ ◉       ◉ ▄▀▀▀▄",
    " ▀▄▄ █▄█▄▄▄▄▄▄▄█▄█ ▄▄▀",
    "   ▄███████████████▄",
    "    ▀█████████████▀",
    "   ▄▀ █ ▀▄▀▄▀▄▀ █ ▀▄",
];

const INNER: usize = 46;

/// Вызвать один раз в начале `main`: настраивает вид всех вопросов `inquire`.
pub fn init() {
    let accent = Color::Rgb {
        r: ACCENT.0,
        g: ACCENT.1,
        b: ACCENT.2,
    };
    let config = RenderConfig::default_colored()
        .with_prompt_prefix(Styled::new("?").with_fg(accent))
        .with_answered_prompt_prefix(Styled::new("✓").with_fg(Color::LightGreen))
        .with_highlighted_option_prefix(Styled::new("›").with_fg(accent))
        .with_answer(StyleSheet::new().with_fg(accent))
        .with_help_message(StyleSheet::new().with_fg(Color::DarkGrey));
    inquire::set_global_render_config(config);
}

fn accent(s: &str) -> colored::ColoredString {
    s.truecolor(ACCENT.0, ACCENT.1, ACCENT.2)
}

fn print_boxed_row(plain: &str, styled: &str) {
    let plain_chars = plain.chars().count();
    let pad = INNER.saturating_sub(plain_chars);
    eprintln!(
        "{} {}{}{}",
        "│".dimmed(),
        styled,
        " ".repeat(pad),
        " │".dimmed()
    );
}

/// Большой баннер: для `init`. В не-терминале (пайп, лог) не печатается.
pub fn banner() {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let border = "─".repeat(INNER + 2);
    eprintln!();
    eprintln!("{}{}{}", "╭".dimmed(), border.dimmed(), "╮".dimmed());
    for (i, line) in CRAB.iter().enumerate() {
        let plain = format!(" {line}");
        let styled = if i == 0 {
            format!(
                " {}{}{}{}{}",
                accent("▄▀▀▀▄ "),
                "◉".white().bold(),
                "       ",
                "◉".white().bold(),
                accent(" ▄▀▀▀▄")
            )
        } else {
            format!(" {}", accent(line))
        };
        print_boxed_row(&plain, &styled);
    }
    print_boxed_row("", "");
    let title_plain = format!("krab  v{}", env!("CARGO_PKG_VERSION"));
    let title_styled = format!(
        "{}  {}",
        accent("krab").bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );
    print_boxed_row(&title_plain, &title_styled);
    let tagline = "локальное хранилище секретов";
    print_boxed_row(tagline, &tagline.dimmed().to_string());
    eprintln!("{}{}{}", "╰".dimmed(), border.dimmed(), "╯".dimmed());
    eprintln!();
}

/// Короткая шапка для остальных команд: одна строка.
pub fn header(vault_path: &std::path::Path) {
    if !std::io::stderr().is_terminal() {
        return;
    }
    eprintln!(
        "{} {} {}",
        accent("krab").bold(),
        "›".dimmed(),
        vault_path.display().to_string().dimmed()
    );
}

pub fn ok(msg: &str) {
    eprintln!("{} {}", "✓".green().bold(), msg);
}

pub fn warn(msg: &str) {
    eprintln!("{} {}", "!".yellow().bold(), msg);
}

pub fn info(msg: &str) {
    eprintln!("{} {}", "·".dimmed(), msg);
}

/// Подсказка «что делать дальше».
pub fn hint(msg: &str) {
    eprintln!("  {}", msg.dimmed());
}

/// Сообщение об ошибке и выход с кодом 1.
pub fn fail(msg: &str) -> ! {
    eprintln!("{} {}", "✗".red().bold(), msg);
    process::exit(1);
}

/// Результат вопроса `inquire`. Ctrl+C / Esc прерывают всю операцию
/// (ничего не сохраняется), любая другая ошибка это ошибка.
pub fn ask<T>(result: Result<T, InquireError>) -> T {
    match result {
        Ok(v) => v,
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            eprintln!();
            eprintln!("{}", "Отменено. Ничего не сохранено.".dimmed());
            process::exit(130);
        }
        Err(e) => fail(&format!("Ошибка ввода: {e}")),
    }
}

/// Спиннер для долгих шагов (Argon2 занимает около секунды).
/// В не-терминале вместо анимации печатается одна строка.
pub fn spinner(msg: &str) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        eprintln!("{msg}");
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.yellow} {msg}")
            .expect("шаблон спиннера")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Человеческое название типа записи.
pub fn type_label(t: &EntryType) -> &str {
    match t {
        EntryType::Login => "Логин",
        EntryType::Note => "Заметка",
        EntryType::Key => "Ключ",
        EntryType::Totp => "TOTP",
        EntryType::Other => "Другое",
        EntryType::Unknown(s) => s.as_str(),
    }
}

/// Таблица записей для `list`.
pub fn entries_table(entries: &[Entry]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(presets::UTF8_FULL)
        .apply_modifier(modifiers::UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(["#", "Тип", "Название", "Теги", "ID"]);

    for (i, e) in entries.iter().enumerate() {
        let id = e.id.to_string();
        let short_id = id.get(..8).unwrap_or(&id).to_string();
        table.add_row(vec![
            Cell::new(i + 1).fg(TableColor::DarkGrey),
            Cell::new(type_label(&e.entry_type)).fg(TableColor::Cyan),
            Cell::new(&e.title),
            Cell::new(e.tags.join(", ")),
            Cell::new(short_id).fg(TableColor::DarkGrey),
        ]);
    }
    table
}
