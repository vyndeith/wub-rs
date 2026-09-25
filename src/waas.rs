use crate::{facl, reg, svc, ti};
use std::path::{Path, PathBuf};

const SUFFIX: &str = ".wublocker.bak";
const WAAS_BINARIES: [&str; 5] = [
    "WaaSMedicSvc.dll",
    "WaaSMedic.exe",
    "WaaSMedicAgent.exe",
    "WaaSMedicCapsule.dll",
    "WaaSMedicPS.dll",
];
const UPFC_BINARIES: [&str; 2] = ["upfc.exe", "SIHClient.exe"];
const IMAGEPATH_BACKUP_KEY: &str = "SOFTWARE\\WUBlocker";
const NULL_IMAGE_PATH: &str = "%SystemRoot%\\System32\\svchost.exe -k WUBlockerNullified";
const DEFAULT_IMAGE_PATH: &str = "%SystemRoot%\\system32\\svchost.exe -k wusvcs -p";

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
}

fn system32(name: &str) -> PathBuf {
    Path::new(&system_root()).join("System32").join(name)
}

fn bak_of(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(SUFFIX);
    PathBuf::from(s)
}

fn repair_acl(path: &Path) {
    if path.exists() {
        facl::undeny(&path.to_string_lossy());
    }
}

fn harden_binary(path: &Path) {
    if !path.exists() {
        return;
    }
    let bak = bak_of(path);
    facl::undeny(&path.to_string_lossy());

    let moved = if !bak.exists() {
        std::fs::rename(path, &bak).is_ok()
    } else {
        std::fs::remove_file(path).is_ok()
    };

    if moved {
        if bak.exists() {
            facl::deny(&bak.to_string_lossy(), "", facl::FULL);
        }
    } else {
        facl::deny(&path.to_string_lossy(), "", facl::FULL);
    }
}

fn restore_binary(path: &Path) {
    let bak = bak_of(path);
    if bak.exists() {
        repair_acl(&bak);
        repair_acl(path);
        let done = if !path.exists() {
            std::fs::rename(&bak, path).is_ok()
        } else {
            std::fs::remove_file(&bak).is_ok()
        };
        if done {
            repair_acl(path);
            return;
        }

        let b = bak.clone();
        let f = path.to_path_buf();
        let _ = ti::run_as_trusted_installer(move || {
            if !f.exists() && b.exists() {
                let _ = std::fs::rename(&b, &f);
            } else if b.exists() {
                let _ = std::fs::remove_file(&b);
            }
        });
        repair_acl(path);
    } else if path.exists() {
        repair_acl(path);
    }
}

pub fn harden_binaries() {
    for name in WAAS_BINARIES {
        harden_binary(&system32(name));
    }
}

pub fn restore_binaries() {
    for name in WAAS_BINARIES {
        restore_binary(&system32(name));
    }
}

pub fn null_imagepath() {
    let cs = "SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc";
    if reg::exists(cs) {
        if let Some(orig) = reg::get_expand_string(cs, "ImagePath") {
            if !orig.is_empty() && !orig.contains("WUBlockerNullified") {
                reg::create_key(IMAGEPATH_BACKUP_KEY);
                reg::set_string(IMAGEPATH_BACKUP_KEY, "WaaSMedicImagePathBackup", &orig);
            }
        }
    }
    for path in svc::all_controlset_paths("WaaSMedicSvc") {
        reg::set_expand_string(&path, "ImagePath", NULL_IMAGE_PATH);
        let p = path.clone();
        let _ = ti::run_as_trusted_installer(move || {
            reg::set_expand_string(&p, "ImagePath", NULL_IMAGE_PATH)
        });
    }
}

pub fn restore_imagepath() {
    let orig = reg::get_string(IMAGEPATH_BACKUP_KEY, "WaaSMedicImagePathBackup")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_IMAGE_PATH.to_string());

    for path in svc::all_controlset_paths("WaaSMedicSvc") {
        let _ = reg::remove_system_deny(&path);
        let ok = reg::set_expand_string(&path, "ImagePath", &orig)
            && reg::get_expand_string(&path, "ImagePath").as_deref() == Some(orig.as_str());
        if !ok {
            let p = path.clone();
            let o = orig.clone();
            let _ =
                ti::run_as_trusted_installer(move || reg::set_expand_string(&p, "ImagePath", &o));
        }
    }
    let _ = reg::delete_value(IMAGEPATH_BACKUP_KEY, "WaaSMedicImagePathBackup");
}

fn waas_services_dir() -> PathBuf {
    Path::new(&system_root()).join("WaaS").join("Services")
}

fn replace_all(text: &str, pairs: &[(&str, &str)]) -> (String, bool) {
    let mut out = text.to_string();
    let mut changed = false;
    for (from, to) in pairs {
        if out.contains(from) {
            out = out.replace(from, to);
            changed = true;
        }
    }
    (out, changed)
}

pub fn harden_xml() {
    for name in UPFC_BINARIES {
        harden_binary(&system32(name));
    }

    let dir = waas_services_dir();
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("xml") {
                continue;
            }
            facl::undeny(&p.to_string_lossy());
            let bak = bak_of(&p);
            if !bak.exists() {
                let _ = std::fs::copy(&p, &bak);
            }
            if let Ok(text) = std::fs::read_to_string(&p) {
                let (new, changed) = replace_all(
                    &text,
                    &[
                        ("start=\"demand\"", "start=\"disabled\""),
                        ("start=\"auto\"", "start=\"disabled\""),
                        ("start=\"delayedAuto\"", "start=\"disabled\""),
                        ("<enabled>true</enabled>", "<enabled>false</enabled>"),
                    ],
                );
                if changed {
                    let _ = std::fs::write(&p, new);
                }
            }
        }
    }

    facl::deny(&dir.to_string_lossy(), "OICI", facl::WRITE_DELETE);
}

pub fn restore_xml() {
    for name in UPFC_BINARIES {
        restore_binary(&system32(name));
    }

    let dir = waas_services_dir();
    if !dir.exists() {
        return;
    }
    repair_acl(&dir);

    if let Ok(entries) = std::fs::read_dir(&dir) {
        let paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();

        for bak in paths
            .iter()
            .filter(|p| p.to_string_lossy().ends_with(SUFFIX))
        {
            let orig = PathBuf::from(bak.to_string_lossy().trim_end_matches(SUFFIX).to_string());
            repair_acl(bak);
            repair_acl(&orig);
            let done = std::fs::copy(bak, &orig).is_ok() && std::fs::remove_file(bak).is_ok();
            if done {
                repair_acl(&orig);
            } else {
                let b = bak.clone();
                let o = orig.clone();
                let _ = ti::run_as_trusted_installer(move || {
                    if std::fs::copy(&b, &o).is_ok() {
                        let _ = std::fs::remove_file(&b);
                    }
                });
                repair_acl(&orig);
            }
        }

        for p in paths.iter().filter(|p| {
            p.extension().and_then(|x| x.to_str()) == Some("xml")
                && !p.to_string_lossy().ends_with(SUFFIX)
        }) {
            repair_acl(p);
            if let Ok(text) = std::fs::read_to_string(p) {
                let (new, changed) = replace_all(
                    &text,
                    &[
                        ("start=\"disabled\"", "start=\"demand\""),
                        ("<enabled>false</enabled>", "<enabled>true</enabled>"),
                    ],
                );
                if changed {
                    let _ = std::fs::write(p, new);
                }
            }
        }
    }
}
