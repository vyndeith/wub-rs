use crate::{facl, reg, sid};
use std::path::{Path, PathBuf};
use windows::core::BSTR;
use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskService, TaskScheduler, TASK_CREATE_OR_UPDATE, TASK_LOGON_NONE,
    TASK_STATE_DISABLED,
};
use windows::Win32::System::Variant::VARIANT;

const TASKCACHE_TREE: &str =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree";

pub const UPDATE_TASKS: [&str; 15] = [
    "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
    "\\Microsoft\\Windows\\WindowsUpdate\\UpdatesDeployment",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan Static Task",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateModelTask",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\MusUx_UpdateInterval",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot_AC",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot_BAT",
    "\\Microsoft\\Windows\\InstallService\\ScanForUpdates",
    "\\Microsoft\\Windows\\InstallService\\ScanForUpdatesAsUser",
    "\\Microsoft\\Windows\\WaaSMedic\\PerformRemediation",
    "\\Microsoft\\Windows\\WindowsUpdate\\sih",
    "\\Microsoft\\Windows\\WindowsUpdate\\sihboot",
];

pub fn split_path(full: &str) -> (String, String) {
    match full.rfind('\\') {
        Some(0) => ("\\".to_string(), full[1..].to_string()),
        Some(i) => (full[..i].to_string(), full[i + 1..].to_string()),
        None => ("\\".to_string(), full.to_string()),
    }
}

fn connect() -> Option<ITaskService> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let svc: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).ok()?;
        let empty = VARIANT::default();
        svc.Connect(&empty, &empty, &empty, &empty).ok()?;
        Some(svc)
    }
}

fn with_task<R>(full: &str, f: impl FnOnce(&IRegisteredTask) -> R) -> Option<R> {
    let (folder, name) = split_path(full);
    unsafe {
        let svc = connect()?;
        let folder = svc.GetFolder(&BSTR::from(folder)).ok()?;
        let task = folder.GetTask(&BSTR::from(name)).ok()?;
        Some(f(&task))
    }
}

pub fn task_exists(full: &str) -> bool {
    with_task(full, |_| ()).is_some()
}

pub fn set_task_enabled(full: &str, on: bool) -> bool {
    let v: VARIANT_BOOL = if on { VARIANT_TRUE } else { VARIANT_FALSE };
    with_task(full, |t| unsafe { t.SetEnabled(v).is_ok() }).unwrap_or(false)
}

pub fn task_disabled(full: &str) -> Option<bool> {
    with_task(full, |t| unsafe { t.State().ok() })?.map(|s| s == TASK_STATE_DISABLED)
}

pub fn task_xml(full: &str) -> Option<String> {
    with_task(full, |t| unsafe { t.Xml().ok() })
        .flatten()
        .map(|b| b.to_string())
}

pub fn task_file_path_of(task: &str) -> PathBuf {
    task_file_path(task)
}

pub fn register_task(full: &str, xml: &str) -> bool {
    let (folder, name) = split_path(full);
    unsafe {
        let svc = match connect() {
            Some(s) => s,
            None => return false,
        };
        let f = match svc.GetFolder(&BSTR::from(folder)) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let empty = VARIANT::default();
        f.RegisterTask(
            &BSTR::from(name),
            &BSTR::from(xml),
            TASK_CREATE_OR_UPDATE.0,
            &empty,
            &empty,
            TASK_LOGON_NONE,
            &empty,
        )
        .is_ok()
    }
}

fn task_file_path(task: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    Path::new(&root)
        .join("System32")
        .join("Tasks")
        .join(task.trim_start_matches('\\'))
}

fn decode_xml(raw: &[u8]) -> String {
    if raw.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(&raw[3..]).into_owned()
    } else {
        String::from_utf8_lossy(raw).into_owned()
    }
}

fn patch_xml(path: &Path, from: &str, to: &str) -> bool {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let text = decode_xml(&raw);
    if !text.contains(from) {
        return true;
    }
    let mut out = vec![0xEF, 0xBB, 0xBF];
    out.extend_from_slice(text.replace(from, to).as_bytes());
    std::fs::write(path, out).is_ok()
}

pub fn ensure_file_deny(task: &str) -> bool {
    let path = task_file_path(task);
    if !path.exists() {
        return false;
    }
    let p = path.to_string_lossy().to_string();

    facl::undeny(&p);
    let _ = patch_xml(&path, "<Enabled>true</Enabled>", "<Enabled>false</Enabled>");
    facl::deny(&p, "", facl::MODIFY)
}

pub fn remove_file_deny(task: &str) -> bool {
    let path = task_file_path(task);
    if !path.exists() {
        return false;
    }
    facl::undeny(&path.to_string_lossy());
    let _ = patch_xml(&path, "<Enabled>false</Enabled>", "<Enabled>true</Enabled>");
    true
}

fn is_self_healing(task: &str) -> bool {
    task.starts_with("\\Microsoft\\Windows\\WaaSMedic\\")
        || task.starts_with("\\Microsoft\\Windows\\UpdateOrchestrator\\")
        || task.ends_with("\\sih")
        || task.ends_with("\\sihboot")
}

fn task_cache_paths(task: &str) -> Vec<String> {
    vec![
        format!("{TASKCACHE_TREE}\\Microsoft\\Windows\\WaaSMedic"),
        format!("{TASKCACHE_TREE}\\Microsoft\\Windows\\UpdateOrchestrator"),
        format!("{TASKCACHE_TREE}{task}"),
    ]
}

pub fn disable() {
    for &task in UPDATE_TASKS.iter() {
        if !task_exists(task) {
            continue;
        }
        let self_healing = is_self_healing(task);

        if self_healing {
            ensure_file_deny(task);
            for cache in task_cache_paths(task) {
                if !reg::exists(&cache) {
                    continue;
                }
                let extra = if cache.contains("WaaSMedic") {
                    sid::service_sid("WaaSMedicSvc")
                } else {
                    String::new()
                };
                let _ = reg::add_system_deny(&cache, &extra);
            }
        }

        if set_task_enabled(task, false) {
            if !self_healing {
                ensure_file_deny(task);
            }
            continue;
        }

        ensure_file_deny(task);
    }
}

pub fn enable() {
    for &task in UPDATE_TASKS.iter() {
        remove_file_deny(task);
    }

    let mut cache_paths = vec![
        format!("{TASKCACHE_TREE}\\Microsoft\\Windows\\WaaSMedic"),
        format!("{TASKCACHE_TREE}\\Microsoft\\Windows\\UpdateOrchestrator"),
    ];
    for &task in UPDATE_TASKS.iter() {
        cache_paths.push(format!("{TASKCACHE_TREE}{task}"));
    }
    cache_paths.sort();
    cache_paths.dedup();
    for p in &cache_paths {
        if reg::exists(p) {
            let _ = reg::remove_system_deny(p);
        }
    }

    for &task in UPDATE_TASKS.iter() {
        if task_exists(task) {
            set_task_enabled(task, true);
        }
    }
}
