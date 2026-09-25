use crate::{reg, svc};
use std::path::Path;
use std::process::Command;

fn run(exe: &str, args: &[&str]) {
    let _ = Command::new(exe).args(args).output();
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
}

pub fn remove_residue() {
    let targets: [(&str, &[&str]); 8] = [
        (
            "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
            &[
                "NoAutoUpdate",
                "AUOptions",
                "UseWUServer",
                "ScheduledInstallDay",
                "ScheduledInstallTime",
            ],
        ),
        (
            "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
            &[
                "DisableWindowsUpdateAccess",
                "ExcludeWUDriversInQualityUpdate",
                "SetDisableUXWUAccess",
                "SetDisablePauseUpdates",
                "WUServer",
                "WUStatusServer",
            ],
        ),
        (
            "SOFTWARE\\Policies\\Microsoft\\WindowsStore",
            &["AutoDownload", "DisableOSUpgrade"],
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
            &["AUOptions", "IncludeRecommendedUpdates"],
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
            &["SearchOrderConfig", "DontSearchWindowsUpdate"],
        ),
        (
            "SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching",
            &[
                "DriverUpdateWizardWuSearchEnabled",
                "DontPromptForWindowsUpdate",
            ],
        ),
        (
            "SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata",
            &["PreventDeviceMetadataFromNetwork"],
        ),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing",
            &[
                "LocalSourcePath",
                "UseWindowsUpdate",
                "RepairContentServerSource",
                "NeverAttemptPayloadDownload",
            ],
        ),
    ];
    for (path, names) in targets {
        if !reg::exists(path) {
            continue;
        }
        for name in names {
            reg::delete_value(path, name);
        }
        if path.starts_with("SOFTWARE\\Policies\\") && reg::key_counts(path) == Some((0, 0)) {
            reg::delete_key(path);
        }
    }
    run("gpupdate.exe", &["/target:computer", "/force"]);
}

pub fn reset_wu_client(no_cache_reset: bool) {
    if no_cache_reset {
        return;
    }
    for s in ["UsoSvc", "wuauserv", "bits", "cryptsvc", "DoSvc"] {
        svc::stop_service(s);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let root = system_root();
    for p in [
        Path::new(&root).join("SoftwareDistribution"),
        Path::new(&root).join("System32").join("catroot2"),
    ] {
        if p.exists() {
            let mut renamed = p.clone().into_os_string();
            renamed.push(format!(".wubreset.{stamp}"));
            if std::fs::rename(&p, &renamed).is_err() {
                crate::log::error(&format!("could not rename WU cache {}", p.display()), None);
            }
        }
    }
    for s in ["cryptsvc", "bits", "wuauserv", "UsoSvc", "DoSvc"] {
        svc::start_service(s);
    }
}

pub fn repair_store(no_store_repair: bool) {
    if no_store_repair {
        return;
    }
    for s in [
        "InstallService",
        "ClipSVC",
        "AppXSvc",
        "BITS",
        "DoSvc",
        "wuauserv",
    ] {
        svc::config_start_type(s, 3);
        svc::start_service(s);
    }
    run("wsreset.exe", &["-i"]);
    run("wsreset.exe", &[]);

    for pkg in [
        "Microsoft.WindowsStore",
        "Microsoft.StorePurchaseApp",
        "Microsoft.DesktopAppInstaller",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.GamingServices",
    ] {
        crate::log::state(&format!("  re-registering AppX: {pkg}"));
        let cmd = format!(
            "Get-AppxPackage -AllUsers -Name {pkg} | ForEach-Object {{ Add-AppxPackage -DisableDevelopmentMode -Register (Join-Path $_.InstallLocation 'AppXManifest.xml') -ErrorAction SilentlyContinue }}"
        );
        run(
            "powershell.exe",
            &["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd],
        );
    }
}

pub fn deep_repair(deep: bool) {
    if !deep {
        return;
    }
    run("DISM.exe", &["/Online", "/Cleanup-Image", "/RestoreHealth"]);
    run("sfc.exe", &["/scannow"]);
}

pub fn post_restore_health() {
    let checks: [(&str, &[&str]); 3] = [
        (
            "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
            &["UseWUServer", "NoAutoUpdate"],
        ),
        (
            "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
            &["WUServer", "WUStatusServer", "DisableWindowsUpdateAccess"],
        ),
        (
            "SOFTWARE\\Policies\\Microsoft\\WindowsStore",
            &["AutoDownload"],
        ),
    ];
    let mut bad = Vec::new();
    for (path, names) in checks {
        if !reg::exists(path) {
            continue;
        }
        for name in names {
            if reg::get_dword(path, name).is_some() || reg::get_string(path, name).is_some() {
                bad.push(format!("{path}\\{name}"));
            }
        }
    }
    if !bad.is_empty() {
        crate::log::error(
            &format!("still-present blocking policy values: {}", bad.join(", ")),
            None,
        );
    }

    for s in [
        "wuauserv",
        "BITS",
        "UsoSvc",
        "DoSvc",
        "InstallService",
        "ClipSVC",
    ] {
        let rel = format!("SYSTEM\\CurrentControlSet\\Services\\{s}");
        if reg::get_dword(&rel, "Start") == Some(4) {
            crate::log::error(&format!("service is still disabled: {s}"), None);
        }
    }
}
