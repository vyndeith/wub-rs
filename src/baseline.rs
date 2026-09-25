use crate::codec::{Reader, Writer};
use crate::{consts, facl, reg, regtree, svc, tasks};
use std::path::{Path, PathBuf};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};

const SCHEMA: u32 = 3;
const MUTABLE_SVC_VALUES: [&str; 14] = [
    "Start",
    "DelayedAutoStart",
    "FailureActions",
    "FailureCommand",
    "ImagePath",
    "ObjectName",
    "Type",
    "ErrorControl",
    "ServiceSidType",
    "RequiredPrivileges",
    "DependOnService",
    "DependOnGroup",
    "LaunchProtected",
    "SvcHostSplitDisable",
];
const EXTRA_SVC_TARGETS: [&str; 4] = ["InstallService", "ClipSVC", "AppXSvc", "TokenBroker"];
const TASKCACHE_TREE: &str =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree";

fn baseline_dir() -> PathBuf {
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    Path::new(&pd).join("WUBlocker").join("DynamicBaseline")
}

fn manifest_path() -> PathBuf {
    baseline_dir().join("manifest.bin")
}

pub fn exists() -> bool {
    manifest_path().exists()
}

fn owner_dacl() -> windows::Win32::Security::OBJECT_SECURITY_INFORMATION {
    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
}

fn service_targets() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in consts::UPDATE_SERVICES
        .iter()
        .chain(consts::OPTIONAL_SERVICES.iter())
        .chain(EXTRA_SVC_TARGETS.iter())
    {
        if !out.iter().any(|x| x == s) {
            out.push((*s).to_string());
        }
    }
    out
}

fn policy_targets() -> [&'static str; 8] {
    [
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        "SOFTWARE\\Policies\\Microsoft\\WindowsStore",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
        "SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching",
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing",
    ]
}

struct RegKeyExact {
    path: String,
    exists: bool,
    acl: Option<String>,
    export: Option<Vec<u8>>,
}

struct ControlSetRecord {
    path: String,
    acl: Option<String>,
    values: Vec<(String, u32, Vec<u8>)>,
    trigger: RegKeyExact,
}

struct ServiceBaseline {
    name: String,
    exists: bool,
    sc_sddl: Option<String>,
    controlsets: Vec<ControlSetRecord>,
}

struct TaskBaseline {
    path: String,
    exists: bool,
    disabled: bool,
    xml: Option<String>,
    file_copy: Option<Vec<u8>>,
    file_acl: Option<String>,
    cache_path: String,
    cache_acl: Option<String>,
}

struct FileBaseline {
    path: String,
    exists: bool,
    copy: Option<Vec<u8>>,
    acl: Option<String>,
}

struct WaasXml {
    path: String,
    copy: Vec<u8>,
    acl: Option<String>,
}

struct Dynamic {
    services: Vec<ServiceBaseline>,
    tasks: Vec<TaskBaseline>,
    policy: Vec<RegKeyExact>,
    files: Vec<FileBaseline>,
    waas_xml: Vec<WaasXml>,
}

fn w_values(w: &mut Writer, v: &[(String, u32, Vec<u8>)]) {
    w.u32(v.len() as u32);
    for (n, t, d) in v {
        w.str(n);
        w.u32(*t);
        w.bytes(d);
    }
}

fn r_values(r: &mut Reader) -> Option<Vec<(String, u32, Vec<u8>)>> {
    let n = r.u32()?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let name = r.str()?;
        let t = r.u32()?;
        let d = r.bytes()?.to_vec();
        out.push((name, t, d));
    }
    Some(out)
}

fn w_regkey(w: &mut Writer, k: &RegKeyExact) {
    w.str(&k.path);
    w.bool(k.exists);
    w.opt_str(k.acl.as_deref());
    w.opt_bytes(k.export.as_deref());
}

fn r_regkey(r: &mut Reader) -> Option<RegKeyExact> {
    Some(RegKeyExact {
        path: r.str()?,
        exists: r.bool()?,
        acl: r.opt_str()?,
        export: r.opt_bytes()?,
    })
}

fn serialize(b: &Dynamic) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(SCHEMA);

    w.u32(b.services.len() as u32);
    for s in &b.services {
        w.str(&s.name);
        w.bool(s.exists);
        w.opt_str(s.sc_sddl.as_deref());
        w.u32(s.controlsets.len() as u32);
        for cs in &s.controlsets {
            w.str(&cs.path);
            w.opt_str(cs.acl.as_deref());
            w_values(&mut w, &cs.values);
            w_regkey(&mut w, &cs.trigger);
        }
    }

    w.u32(b.tasks.len() as u32);
    for t in &b.tasks {
        w.str(&t.path);
        w.bool(t.exists);
        w.bool(t.disabled);
        w.opt_str(t.xml.as_deref());
        w.opt_bytes(t.file_copy.as_deref());
        w.opt_str(t.file_acl.as_deref());
        w.str(&t.cache_path);
        w.opt_str(t.cache_acl.as_deref());
    }

    w.u32(b.policy.len() as u32);
    for k in &b.policy {
        w_regkey(&mut w, k);
    }

    w.u32(b.files.len() as u32);
    for f in &b.files {
        w.str(&f.path);
        w.bool(f.exists);
        w.opt_bytes(f.copy.as_deref());
        w.opt_str(f.acl.as_deref());
    }

    w.u32(b.waas_xml.len() as u32);
    for x in &b.waas_xml {
        w.str(&x.path);
        w.bytes(&x.copy);
        w.opt_str(x.acl.as_deref());
    }

    w.into_bytes()
}

fn deserialize(blob: &[u8]) -> Option<Dynamic> {
    let mut r = Reader::new(blob);
    if r.u32()? != SCHEMA {
        return None;
    }

    let ns = r.u32()?;
    let mut services = Vec::with_capacity(ns as usize);
    for _ in 0..ns {
        let name = r.str()?;
        let exists = r.bool()?;
        let sc_sddl = r.opt_str()?;
        let ncs = r.u32()?;
        let mut controlsets = Vec::with_capacity(ncs as usize);
        for _ in 0..ncs {
            controlsets.push(ControlSetRecord {
                path: r.str()?,
                acl: r.opt_str()?,
                values: r_values(&mut r)?,
                trigger: r_regkey(&mut r)?,
            });
        }
        services.push(ServiceBaseline {
            name,
            exists,
            sc_sddl,
            controlsets,
        });
    }

    let nt = r.u32()?;
    let mut tasks_v = Vec::with_capacity(nt as usize);
    for _ in 0..nt {
        tasks_v.push(TaskBaseline {
            path: r.str()?,
            exists: r.bool()?,
            disabled: r.bool()?,
            xml: r.opt_str()?,
            file_copy: r.opt_bytes()?,
            file_acl: r.opt_str()?,
            cache_path: r.str()?,
            cache_acl: r.opt_str()?,
        });
    }

    let np = r.u32()?;
    let mut policy = Vec::with_capacity(np as usize);
    for _ in 0..np {
        policy.push(r_regkey(&mut r)?);
    }

    let nf = r.u32()?;
    let mut files = Vec::with_capacity(nf as usize);
    for _ in 0..nf {
        files.push(FileBaseline {
            path: r.str()?,
            exists: r.bool()?,
            copy: r.opt_bytes()?,
            acl: r.opt_str()?,
        });
    }

    let nx = r.u32()?;
    let mut waas_xml = Vec::with_capacity(nx as usize);
    for _ in 0..nx {
        waas_xml.push(WaasXml {
            path: r.str()?,
            copy: r.bytes()?.to_vec(),
            acl: r.opt_str()?,
        });
    }

    Some(Dynamic {
        services,
        tasks: tasks_v,
        policy,
        files,
        waas_xml,
    })
}

fn backup_reg_key_exact(path: &str) -> RegKeyExact {
    let exists = reg::exists(path);
    RegKeyExact {
        path: path.to_string(),
        exists,
        acl: if exists {
            reg::get_key_sddl(path, owner_dacl())
        } else {
            None
        },
        export: if exists { regtree::capture(path) } else { None },
    }
}

fn save_service(name: &str) -> ServiceBaseline {
    let exists = reg::exists(&format!("SYSTEM\\CurrentControlSet\\Services\\{name}"));
    let mut rec = ServiceBaseline {
        name: name.to_string(),
        exists,
        sc_sddl: None,
        controlsets: Vec::new(),
    };
    if !exists {
        return rec;
    }
    let sddl = svc::get_sddl(name);
    if sddl.contains("D:") {
        rec.sc_sddl = Some(sddl);
    }
    for rel in svc::all_controlset_paths(name) {
        rec.controlsets.push(ControlSetRecord {
            acl: reg::get_key_sddl(&rel, owner_dacl()),
            values: reg::values(&rel),
            trigger: backup_reg_key_exact(&format!("{rel}\\TriggerInfo")),
            path: rel,
        });
    }
    rec
}

fn save_task(task: &str) -> TaskBaseline {
    let file = tasks::task_file_path_of(task);
    TaskBaseline {
        path: task.to_string(),
        exists: tasks::task_exists(task),
        disabled: tasks::task_disabled(task) == Some(true),
        xml: tasks::task_xml(task),
        file_copy: std::fs::read(&file).ok(),
        file_acl: if file.exists() {
            facl::sddl_of(&file.to_string_lossy())
        } else {
            None
        },
        cache_path: format!("{TASKCACHE_TREE}{task}"),
        cache_acl: reg::get_key_sddl(&format!("{TASKCACHE_TREE}{task}"), owner_dacl()),
    }
}

fn save_file(path: &Path) -> FileBaseline {
    let exists = path.exists();
    FileBaseline {
        path: path.to_string_lossy().to_string(),
        exists,
        copy: if exists {
            std::fs::read(path).ok()
        } else {
            None
        },
        acl: if exists {
            facl::sddl_of(&path.to_string_lossy())
        } else {
            None
        },
    }
}

fn save_waas_xml() -> Vec<WaasXml> {
    let mut out = Vec::new();
    let dir = Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()))
        .join("WaaS")
        .join("Services");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("xml") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&p) {
                out.push(WaasXml {
                    acl: facl::sddl_of(&p.to_string_lossy()),
                    copy: bytes,
                    path: p.to_string_lossy().to_string(),
                });
            }
        }
    }
    out
}

fn sys32(name: &str) -> PathBuf {
    Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()))
        .join("System32")
        .join(name)
}

pub fn save_dynamic(refresh: bool) {
    let dir = baseline_dir();
    let _ = std::fs::create_dir_all(&dir);
    let manifest = manifest_path();
    if manifest.exists() && !refresh {
        return;
    }

    let b = Dynamic {
        services: service_targets().iter().map(|s| save_service(s)).collect(),
        tasks: tasks::UPDATE_TASKS.iter().map(|t| save_task(t)).collect(),
        policy: policy_targets()
            .iter()
            .map(|p| backup_reg_key_exact(p))
            .collect(),
        files: [
            sys32("WaaSMedicSvc.dll"),
            sys32("upfc.exe"),
            sys32("SIHClient.exe"),
        ]
        .iter()
        .map(|p| save_file(p))
        .collect(),
        waas_xml: save_waas_xml(),
    };

    if std::fs::write(&manifest, serialize(&b)).is_err() {
        crate::log::error("could not write dynamic baseline manifest", None);
    }
}

fn restore_reg_key_exact(k: &RegKeyExact) {
    crate::token::enable_registry_privileges();
    if k.exists {
        if reg::exists(&k.path) {
            let _ = reg::remove_system_deny(&k.path);
            reg::delete_tree(&k.path);
        }
        if let Some(export) = &k.export {
            regtree::restore(&k.path, export);
        }
        if let Some(acl) = &k.acl {
            reg::apply_sddl(&k.path, acl, owner_dacl());
        }
    } else if reg::exists(&k.path) {
        let _ = reg::remove_system_deny(&k.path);
        reg::delete_tree(&k.path);
    }
}

fn restore_service(s: &ServiceBaseline) {
    if !s.exists {
        return;
    }
    if !reg::exists(&format!("SYSTEM\\CurrentControlSet\\Services\\{}", s.name)) {
        return;
    }
    svc::unlock_dacl(&s.name);
    svc::remove_deny_all_controlsets(&s.name);

    if let Some(sddl) = &s.sc_sddl {
        if !svc::set_dacl(&s.name, sddl) {
            svc::set_all_controlsets_security(&s.name, sddl);
        }
    }

    for cs in &s.controlsets {
        if !reg::exists(&cs.path) {
            continue;
        }
        let _ = reg::remove_system_deny(&cs.path);
        for mutable in MUTABLE_SVC_VALUES {
            if !cs.values.iter().any(|(n, _, _)| n == mutable) {
                reg::delete_value(&cs.path, mutable);
            }
        }
        for (name, t, data) in &cs.values {
            reg::set_value_raw(&cs.path, name, *t, data);
        }
        restore_reg_key_exact(&cs.trigger);
        if let Some(acl) = &cs.acl {
            reg::apply_sddl(&cs.path, acl, owner_dacl());
        }
    }

    let cur = format!("SYSTEM\\CurrentControlSet\\Services\\{}", s.name);
    if let Some(start) = reg::get_dword(&cur, "Start") {
        svc::config_start_type(&s.name, start);
    }
}

fn restore_task(t: &TaskBaseline) {
    if !t.exists {
        return;
    }
    let file = tasks::task_file_path_of(&t.path);
    if t.file_acl.is_some() && file.exists() {
        facl::undeny(&file.to_string_lossy());
    }

    if let Some(xml) = &t.xml {
        tasks::register_task(&t.path, xml);
    } else if let Some(bytes) = &t.file_copy {
        if let Some(parent) = file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&file, bytes);
    }

    tasks::set_task_enabled(&t.path, !t.disabled);

    if let Some(acl) = &t.file_acl {
        if file.exists() {
            facl::apply_sddl(&file.to_string_lossy(), acl);
        }
    }
    if let Some(acl) = &t.cache_acl {
        reg::apply_sddl(&t.cache_path, acl, owner_dacl());
    }
}

fn restore_file(f: &FileBaseline) {
    if !f.exists {
        return;
    }
    let path = Path::new(&f.path);
    if !path.exists() {
        if let Some(bytes) = &f.copy {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, bytes);
        }
    }
    if let Some(acl) = &f.acl {
        if path.exists() {
            facl::apply_sddl(&f.path, acl);
        }
    }
}

fn restore_waas_xml(x: &WaasXml) {
    if std::fs::write(&x.path, &x.copy).is_ok() {
        if let Some(acl) = &x.acl {
            facl::apply_sddl(&x.path, acl);
        }
    }
}

pub fn restore_dynamic() -> bool {
    let blob = match std::fs::read(manifest_path()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let b = match deserialize(&blob) {
        Some(b) => b,
        None => return false,
    };
    for x in &b.waas_xml {
        restore_waas_xml(x);
    }
    for f in &b.files {
        restore_file(f);
    }
    for s in &b.services {
        restore_service(s);
    }
    for t in &b.tasks {
        restore_task(t);
    }
    for k in &b.policy {
        restore_reg_key_exact(k);
    }
    true
}
