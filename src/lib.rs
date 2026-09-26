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

pub use log::{clear_sink, set_sink};

#[derive(Clone, Copy, Default)]
pub struct Options {
    pub deep_repair: bool,
    pub refresh_baseline: bool,
    pub no_cache_reset: bool,
    pub no_store_repair: bool,
}

pub fn is_elevated() -> bool {
    elevation::is_elevated().unwrap_or(false)
}

pub fn relaunch_elevated() -> bool {
    elevation::relaunch_elevated().is_ok()
}

pub fn disable(o: &Options) {
    log::state("[1/5] saving pre-disable baseline...");
    baseline::save_dynamic(o.refresh_baseline);
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

pub fn enable(o: &Options) {
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
    repair::reset_wu_client(o.no_cache_reset);
    log::state("[7/8] repairing Microsoft Store (this can take a few minutes)...");
    repair::repair_store(o.no_store_repair);
    if o.deep_repair {
        log::state("running DISM + SFC deep repair (can take a long time)...");
    }
    repair::deep_repair(o.deep_repair);
    log::state("[8/8] verifying + starting update services...");
    repair::post_restore_health();
    for s in ["BITS", "wuauserv", "UsoSvc"] {
        svc::start_service(s);
    }
    log::state("DONE. Windows Update enabled.");
}

pub fn check() {
    let mut disabled = 0;
    let mut total = 0;
    for s in consts::UPDATE_SERVICES
        .iter()
        .chain(consts::OPTIONAL_SERVICES.iter())
    {
        let rel = format!("SYSTEM\\CurrentControlSet\\Services\\{s}");
        if !reg::exists(&rel) {
            continue;
        }
        total += 1;
        let start = reg::get_dword(&rel, "Start");
        let is_disabled = start == Some(4);
        if is_disabled {
            disabled += 1;
        }
        let deny = svc::has_deny_ace(&svc::get_sddl(s), "SY");
        let start_txt = start.map(|v| v.to_string()).unwrap_or_else(|| "?".into());
        log::state(&format!(
            "{s}: Start={start_txt} (4=disabled), SYSTEM-deny={deny}"
        ));
    }
    let au = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";
    let policy_on = reg::get_dword(au, "NoAutoUpdate") == Some(1);
    log::state(&format!("policy NoAutoUpdate set = {policy_on}"));

    if total > 0 && disabled == total {
        log::state("STATUS: Windows Update looks DISABLED (blocked).");
    } else if disabled == 0 {
        log::state("STATUS: Windows Update looks ENABLED.");
    } else {
        log::state(&format!(
            "STATUS: partial - {disabled}/{total} services disabled."
        ));
    }
}
