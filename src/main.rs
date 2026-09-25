mod baseline;
mod codec;
mod consts;
mod elevation;
mod error;
mod facl;
mod handle;
mod log;
mod policy;
mod reg;
mod regtree;
mod repair;
mod sddl;

mod sid;
mod svc;
mod tasks;
mod ti;
mod token;
mod waas;

use std::io::Write;
use std::process::ExitCode;

#[derive(PartialEq)]
enum Action {
    Disable,
    Enable,
}

struct Cli {
    action: Option<Action>,
    deep_repair: bool,
    refresh_baseline: bool,
    no_cache_reset: bool,
    no_store_repair: bool,
}

fn parse_args() -> Cli {
    let mut cli = Cli {
        action: None,
        deep_repair: false,
        refresh_baseline: false,
        no_cache_reset: false,
        no_store_repair: false,
    };
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        let low = a.trim_start_matches('-').to_ascii_lowercase();
        match low.as_str() {
            "disable" => cli.action = Some(Action::Disable),
            "enable" => cli.action = Some(Action::Enable),
            "action" => {
                if let Some(v) = args.next() {
                    match v.to_ascii_lowercase().as_str() {
                        "disable" => cli.action = Some(Action::Disable),
                        "enable" => cli.action = Some(Action::Enable),
                        _ => {}
                    }
                }
            }
            "deeprepair" | "deep-repair" => cli.deep_repair = true,
            "refreshbaseline" | "refresh-baseline" => cli.refresh_baseline = true,
            "nocachereset" | "no-cache-reset" => cli.no_cache_reset = true,
            "nostorerepair" | "no-store-repair" => cli.no_store_repair = true,
            _ => {}
        }
    }
    cli
}

fn prompt_action() -> Action {
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
    match elevation::is_elevated() {
        Ok(true) => {}
        Ok(false) => {
            if let Err(e) = elevation::relaunch_elevated() {
                log::error("failed to relaunch elevated", Some(&e));
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            log::error("elevation check failed", Some(&e));
            return ExitCode::FAILURE;
        }
    }

    let cli = parse_args();
    let action = cli.action.unwrap_or_else(prompt_action);

    match action {
        Action::Disable => {
            log::state("[1/5] saving pre-disable baseline...");
            baseline::save_dynamic(cli.refresh_baseline);
            log::state("[2/5] stopping update services...");
            svc::stop_update_services();
            log::state("[3/5] disabling + locking services (WaaSMedic hardening)...");
            svc::disable_all();
            log::state("[4/5] applying registry policy block...");
            policy::set_block();
            log::state("[5/5] disabling scheduled tasks...");
            tasks::disable();
            log::state("DONE. Windows Update disabled. A reboot fully settles the block.");
        }
        Action::Enable => {
            let baseline_available = baseline::exists();
            log::state("[1/8] removing policy residue...");
            repair::remove_residue();
            log::state("[2/8] restoring + unlocking services (WaaSMedic restore)...");
            svc::enable_all();
            log::state("[3/8] removing registry policy block...");
            policy::remove_block();
            log::state("[4/8] re-enabling scheduled tasks...");
            tasks::enable();
            log::state("[5/8] restoring exact baseline state...");
            baseline::restore_dynamic();
            if !baseline_available {
                repair::remove_residue();
            }
            log::state("[6/8] resetting WU cache (SoftwareDistribution/catroot2)...");
            repair::reset_wu_client(cli.no_cache_reset);
            log::state("[7/8] repairing Microsoft Store (this can take a few minutes)...");
            repair::repair_store(cli.no_store_repair);
            if cli.deep_repair {
                log::state("running DISM + SFC deep repair (can take a long time)...");
            }
            repair::deep_repair(cli.deep_repair);
            log::state("[8/8] verifying + starting update services...");
            repair::post_restore_health();
            for s in ["BITS", "wuauserv", "UsoSvc"] {
                svc::start_service(s);
            }
            log::state("DONE. Windows Update enabled.");
        }
    }

    ExitCode::SUCCESS
}
