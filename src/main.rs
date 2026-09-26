use std::io::Write;
use std::process::ExitCode;
use wublocker::Options;

enum Action {
    Disable,
    Enable,
}

fn parse() -> (Option<Action>, Options) {
    let mut action = None;
    let mut o = Options::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.trim_start_matches('-').to_ascii_lowercase().as_str() {
            "disable" => action = Some(Action::Disable),
            "enable" => action = Some(Action::Enable),
            "action" => {
                if let Some(v) = args.next() {
                    match v.to_ascii_lowercase().as_str() {
                        "disable" => action = Some(Action::Disable),
                        "enable" => action = Some(Action::Enable),
                        _ => {}
                    }
                }
            }
            "deeprepair" | "deep-repair" => o.deep_repair = true,
            "refreshbaseline" | "refresh-baseline" => o.refresh_baseline = true,
            "nocachereset" | "no-cache-reset" => o.no_cache_reset = true,
            "nostorerepair" | "no-store-repair" => o.no_store_repair = true,
            _ => {}
        }
    }
    (action, o)
}

fn prompt() -> Action {
    loop {
        print!("Enter D (disable) or E (enable): ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return Action::Disable;
        }
        match line.trim().to_ascii_uppercase().as_str() {
            "D" => return Action::Disable,
            "E" => return Action::Enable,
            _ => {}
        }
    }
}

fn main() -> ExitCode {
    if !wublocker::is_elevated() {
        wublocker::relaunch_elevated();
        return ExitCode::SUCCESS;
    }
    let (action, opts) = parse();
    let action = action.unwrap_or_else(prompt);
    match action {
        Action::Disable => wublocker::disable(&opts),
        Action::Enable => wublocker::enable(&opts),
    }
    ExitCode::SUCCESS
}
