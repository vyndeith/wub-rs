use crate::handle::ScHandle;
use crate::{consts, reg, regtree, sddl, sid, ti, token};
use std::time::{Duration, Instant};
use windows::core::PWSTR;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_MARKED_FOR_DELETE};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, ControlService, EnumDependentServicesW,
    OpenSCManagerW, OpenServiceW, QueryServiceObjectSecurity, QueryServiceStatus,
    SetServiceObjectSecurity, StartServiceW, ENUM_SERVICE_STATUSW, ENUM_SERVICE_TYPE, SC_ACTION,
    SC_ACTION_NONE, SC_MANAGER_CONNECT, SERVICE_ACTIVE, SERVICE_CHANGE_CONFIG,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONFIG_TRIGGER_INFO, SERVICE_CONTROL_STOP, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_ERROR,
    SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_NO_CHANGE,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_START_TYPE, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STOP, SERVICE_STOPPED, SERVICE_TRIGGER_INFO,
};

pub fn all_controlset_paths(service: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for cs in reg::subkeys("SYSTEM") {
        if is_controlset(&cs) {
            let p = format!("SYSTEM\\{cs}\\Services\\{service}");
            if reg::exists(&p) {
                paths.push(p);
            }
        }
    }
    let cc = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
    if reg::exists(&cc) && !paths.contains(&cc) {
        paths.push(cc);
    }
    paths
}

fn is_controlset(name: &str) -> bool {
    let rest = match name.strip_prefix("ControlSet") {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

fn extra_sid(service: &str) -> String {
    if consts::SERVICES.contains(&service) {
        sid::service_sid(service)
    } else {
        String::new()
    }
}

fn change_start_type(service: &str, reg_value: u32) -> windows::core::Result<()> {
    unsafe {
        let scm = ScHandle(OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        )?);
        let name = HSTRING::from(service);
        let svc = ScHandle(OpenServiceW(
            scm.get(),
            PCWSTR(name.as_ptr()),
            SERVICE_CHANGE_CONFIG,
        )?);
        ChangeServiceConfigW(
            svc.get(),
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_START_TYPE(reg_value),
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
}

fn ti_write_start(rel: &str, reg_value: u32, extra: &str) -> bool {
    if !reg::set_dword(rel, "Start", reg_value) {
        return false;
    }
    let si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let _ = reg::apply_sddl(rel, consts::ALLOW_SDDL, si);
    if reg_value == 4 {
        let mut deny = String::from(consts::DENY_SDDL);
        if !extra.is_empty() {
            deny.push_str(&format!("(D;OICI;KA;;;{extra})"));
        }
        let _ = reg::apply_sddl(rel, &deny, si);
    }
    true
}

pub fn config_start_type(service: &str, reg_value: u32) -> bool {
    change_start_type(service, reg_value).is_ok()
}

pub fn set_start_type(service: &str, reg_value: u32) -> bool {
    let rel = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
    let extra = extra_sid(service);

    let err = match change_start_type(service, reg_value) {
        Ok(()) => {
            if reg_value == 4 {
                let _ = reg::add_system_deny(&rel, &extra);
            }
            return true;
        }
        Err(e) => e,
    };

    let denied = err.code() == ERROR_ACCESS_DENIED.to_hresult()
        || err.code() == ERROR_SERVICE_MARKED_FOR_DELETE.to_hresult();

    if denied {
        if !reg::exists(&rel) {
            return false;
        }
        if reg::set_dword(&rel, "Start", reg_value) {
            if reg_value == 4 {
                let _ = reg::add_system_deny(&rel, &extra);
            }
            return true;
        }
        if reg::grant_key_access(&rel) && reg::set_dword(&rel, "Start", reg_value) {
            if reg_value == 4 {
                let _ = reg::add_system_deny(&rel, &extra);
            }
            return true;
        }
        return false;
    }

    let rel2 = rel.clone();
    let extra2 = extra.clone();
    matches!(
        ti::run_as_trusted_installer(move || ti_write_start(&rel2, reg_value, &extra2)),
        Ok(true)
    )
}

fn open_service(scm: &ScHandle, name: &str, access: u32) -> Option<ScHandle> {
    let n = HSTRING::from(name);
    unsafe {
        OpenServiceW(scm.get(), PCWSTR(n.as_ptr()), access)
            .ok()
            .map(ScHandle)
    }
}

fn state(svc: &ScHandle) -> Option<SERVICE_STATUS_CURRENT_STATE> {
    let mut st = SERVICE_STATUS::default();
    unsafe { QueryServiceStatus(svc.get(), &mut st).ok()? };
    Some(st.dwCurrentState)
}

fn try_stop(svc: &ScHandle) -> bool {
    let mut st = SERVICE_STATUS::default();
    if unsafe { ControlService(svc.get(), SERVICE_CONTROL_STOP, &mut st) }.is_err() {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if state(svc) == Some(SERVICE_STOPPED) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn active_dependents(svc: &ScHandle) -> Vec<String> {
    unsafe {
        let mut needed = 0u32;
        let mut count = 0u32;
        let _ = EnumDependentServicesW(svc.get(), SERVICE_ACTIVE, None, 0, &mut needed, &mut count);
        if needed == 0 {
            return Vec::new();
        }
        let elem = size_of::<ENUM_SERVICE_STATUSW>();
        let n = needed as usize / elem + 1;
        let mut buf: Vec<ENUM_SERVICE_STATUSW> = Vec::with_capacity(n);
        let cb = (n * elem) as u32;
        if EnumDependentServicesW(
            svc.get(),
            SERVICE_ACTIVE,
            Some(buf.as_mut_ptr()),
            cb,
            &mut needed,
            &mut count,
        )
        .is_err()
        {
            return Vec::new();
        }
        std::slice::from_raw_parts(buf.as_ptr(), count as usize)
            .iter()
            .filter_map(|e| e.lpServiceName.to_string().ok())
            .collect()
    }
}

pub fn stop_service(name: &str) -> bool {
    let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        Ok(h) => ScHandle(h),
        Err(_) => return false,
    };
    match open_service(&scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS) {
        Some(svc) => state(&svc) == Some(SERVICE_STOPPED) || try_stop(&svc),
        None => false,
    }
}

pub fn start_service(name: &str) -> bool {
    let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        Ok(h) => ScHandle(h),
        Err(_) => return false,
    };
    match open_service(&scm, name, SERVICE_START) {
        Some(svc) => unsafe { StartServiceW(svc.get(), None).is_ok() },
        None => false,
    }
}

pub fn stop_update_services() {
    let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        Ok(h) => ScHandle(h),
        Err(_) => return,
    };
    for &name in consts::UPDATE_SERVICES
        .iter()
        .chain(consts::OPTIONAL_SERVICES.iter())
    {
        let svc = match open_service(
            &scm,
            name,
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS,
        ) {
            Some(s) => s,
            None => continue,
        };
        if state(&svc) == Some(SERVICE_STOPPED) {
            continue;
        }
        if try_stop(&svc) {
            continue;
        }
        for dep in active_dependents(&svc) {
            if let Some(d) = open_service(&scm, &dep, SERVICE_STOP | SERVICE_QUERY_STATUS) {
                let _ = try_stop(&d);
            }
        }
        let _ = try_stop(&svc);
    }
}

pub fn set_all_controlsets_disabled(service: &str) {
    let extra = extra_sid(service);
    let dr = "DCRPWPWDWO";
    let mut deny_aces = format!(
        "(D;;{dr};;;SY)(D;;{dr};;;{ti})(D;;{dr};;;LS)(D;;{dr};;;NS)",
        ti = consts::TI_SID
    );
    if !extra.is_empty() {
        deny_aces.push_str(&format!("(D;;{dr};;;{extra})"));
    }
    let svc_sddl = format!("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA){deny_aces}");
    let svc_bytes = sddl::to_bytes(&svc_sddl);

    for path in all_controlset_paths(service) {
        reg::set_dword(&path, "Start", 4);
        reg::set_dword(&path, "DelayedAutoStart", 0);
        if let Some(ref bytes) = svc_bytes {
            reg::set_binary(&path, "Security", bytes);
            let p = path.clone();
            let b = bytes.clone();
            let _ = ti::run_as_trusted_installer(move || reg::set_binary(&p, "Security", &b));
        }
        let _ = reg::add_system_deny(&path, &extra);
    }
}

pub fn remove_deny_all_controlsets(service: &str) {
    for path in all_controlset_paths(service) {
        let _ = reg::remove_system_deny(&path);
    }
}

fn query_service_sd(svc: &ScHandle, si: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut needed = 0u32;
        let _ = QueryServiceObjectSecurity(svc.get(), si, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let words = (needed as usize).div_ceil(4);
        let mut buf: Vec<u32> = vec![0; words];
        let psd = PSECURITY_DESCRIPTOR(buf.as_mut_ptr() as *mut core::ffi::c_void);
        QueryServiceObjectSecurity(svc.get(), si, Some(psd), (words * 4) as u32, &mut needed)
            .ok()?;
        Some(std::slice::from_raw_parts(buf.as_ptr() as *const u8, needed as usize).to_vec())
    }
}

pub fn get_sddl(service: &str) -> String {
    let _ = token::enable_privilege("SeSecurityPrivilege");
    let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        Ok(h) => ScHandle(h),
        Err(_) => return String::new(),
    };
    const READ_CONTROL: u32 = 0x0002_0000;
    const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
    const DACL_SACL: u32 = 0x4 | 0x8;
    const DACL_ONLY: u32 = 0x4;
    for &(acc, si) in &[
        (READ_CONTROL | ACCESS_SYSTEM_SECURITY, DACL_SACL),
        (READ_CONTROL, DACL_ONLY),
    ] {
        if let Some(svc) = open_service(&scm, service, acc) {
            if let Some(bytes) = query_service_sd(&svc, si) {
                if let Some(s) = sddl::from_bytes(&bytes, OBJECT_SECURITY_INFORMATION(si)) {
                    if !s.is_empty() {
                        return s;
                    }
                }
            }
        }
    }
    String::new()
}

pub fn set_dacl(service: &str, sddl_str: &str) -> bool {
    let bytes = match sddl::to_bytes(sddl_str) {
        Some(b) => b,
        None => return false,
    };
    let psd = PSECURITY_DESCRIPTOR(bytes.as_ptr() as *mut core::ffi::c_void);
    const SC_MANAGER_ALL: u32 = 0xF003F;
    const SERVICE_ALL: u32 = 0xF01FF;
    const WRITE_DAC_READ: u32 = 0x0004_0000 | 0x0002_0000;
    for ma in [SC_MANAGER_ALL, SC_MANAGER_CONNECT] {
        let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), ma) } {
            Ok(h) => ScHandle(h),
            Err(_) => continue,
        };
        for sa in [SERVICE_ALL, WRITE_DAC_READ] {
            if let Some(svc) = open_service(&scm, service, sa) {
                if unsafe { SetServiceObjectSecurity(svc.get(), DACL_SECURITY_INFORMATION, psd) }
                    .is_ok()
                {
                    return true;
                }
            }
        }
    }
    false
}

pub fn set_all_controlsets_security(service: &str, sddl_str: &str) -> bool {
    let bytes = match sddl::to_bytes(sddl_str) {
        Some(b) => b,
        None => return false,
    };
    let mut all_ok = true;
    for path in all_controlset_paths(service) {
        if !reg::set_binary(&path, "Security", &bytes) {
            all_ok = false;
        }
        let p = path.clone();
        let b = bytes.clone();
        let ti_ok = matches!(
            ti::run_as_trusted_installer(move || reg::set_binary(&p, "Security", &b)),
            Ok(true)
        );
        if !ti_ok {
            all_ok = false;
        }
    }
    all_ok
}

pub(crate) fn has_deny_ace(sddl_str: &str, sid: &str) -> bool {
    sddl_str.match_indices("(D;").any(|(i, _)| {
        let rest = &sddl_str[i + 1..];
        match rest.find(')') {
            Some(close) => {
                let p: Vec<&str> = rest[..close].split(';').collect();
                p.len() == 6
                    && p[0] == "D"
                    && !p[2].is_empty()
                    && p[3].is_empty()
                    && p[4].is_empty()
                    && p[5] == sid
            }
            None => false,
        }
    })
}

pub fn test_dacl_locked(service: &str) -> bool {
    if has_deny_ace(&get_sddl(service), "SY") {
        return true;
    }
    let reg_path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
    has_deny_ace(&reg::read_service_sddl(&reg_path), "SY")
}

fn insert_deny_aces(saved: &str, deny: &str) -> String {
    match saved.find("D:") {
        Some(dpos) => {
            let after = &saved[dpos + 2..];
            let flag = ["NO_ACCESS_CONTROL", "PAI", "AI", "P"]
                .iter()
                .find(|f| after.starts_with(**f) && after[f.len()..].starts_with('('))
                .copied()
                .unwrap_or("");
            let cut = dpos + 2 + flag.len();
            format!("{}{}{}", &saved[..cut], deny, &saved[cut..])
        }
        None => format!("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA){deny}"),
    }
}

fn default_service_sddl(service: &str) -> String {
    match service {
        "wuauserv" => "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)",
        "BITS" => "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;PU)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)",
        "UsoSvc" => "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)",
        "WaaSMedicSvc" => "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)",
        "DoSvc" => "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)",
        "uhssvc" => "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)",
        _ => "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)",
    }
    .to_string()
}

pub fn lock_dacl(service: &str, extra_sid: &str) -> bool {
    let backup = consts::SVC_DACL_BACKUP_KEY;
    let reg_path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");

    if reg::get_string(backup, service).is_none() {
        let mut existing = get_sddl(service);
        if !existing.contains("D:") {
            existing = reg::read_service_sddl(&reg_path);
        }
        if existing.contains("D:") {
            reg::set_string(backup, service, &existing);
        }
    }
    let saved = reg::get_string(backup, service)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| get_sddl(service));

    let dr = "DCRPWPWDWO";
    let mut deny = format!(
        "(D;;{dr};;;SY)(D;;{dr};;;{ti})(D;;{dr};;;LS)(D;;{dr};;;NS)",
        ti = consts::TI_SID
    );
    if !extra_sid.is_empty() {
        deny.push_str(&format!("(D;;{dr};;;{extra_sid})"));
    }
    let new_sddl = insert_deny_aces(&saved, &deny);

    if set_dacl(service, &new_sddl) {
        if let Some(bytes) = sddl::to_bytes(&new_sddl) {
            reg::set_binary(&reg_path, "Security", &bytes);
            let p = reg_path.clone();
            let b = bytes.clone();
            let _ = ti::run_as_trusted_installer(move || reg::set_binary(&p, "Security", &b));
        }
        return true;
    }

    let s2 = service.to_string();
    let n2 = new_sddl.clone();
    if matches!(
        ti::run_as_trusted_installer(move || set_dacl(&s2, &n2)),
        Ok(true)
    ) {
        return true;
    }

    if let Some(bytes) = sddl::to_bytes(&new_sddl) {
        if reg::set_binary(&reg_path, "Security", &bytes) {
            return true;
        }
        let p = reg_path.clone();
        let b = bytes.clone();
        if matches!(
            ti::run_as_trusted_installer(move || reg::set_binary(&p, "Security", &b)),
            Ok(true)
        ) {
            return true;
        }
    }
    false
}

pub fn unlock_dacl(service: &str) -> bool {
    let backup = consts::SVC_DACL_BACKUP_KEY;
    let reg_path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");

    let mut saved = reg::get_string(backup, service);
    if let Some(ref s) = saved {
        if s.contains("(D;;DCRPWPWDWO;;;SY)") {
            saved = None;
        }
    }
    let saved = saved
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_service_sddl(service));

    let finish = |sddl_used: &str| {
        let _ = set_all_controlsets_security(service, sddl_used);
        let _ = reg::delete_value(backup, service);
    };

    if set_dacl(service, &saved) {
        std::thread::sleep(Duration::from_millis(150));
        if !test_dacl_locked(service) {
            finish(&saved);
            return true;
        }
    }

    if let Some(bytes) = sddl::to_bytes(&saved) {
        if reg::set_binary(&reg_path, "Security", &bytes) {
            std::thread::sleep(Duration::from_millis(150));
            if !test_dacl_locked(service) {
                finish(&saved);
                return true;
            }
        }
        let p = reg_path.clone();
        let b = bytes.clone();
        if matches!(
            ti::run_as_trusted_installer(move || reg::set_binary(&p, "Security", &b)),
            Ok(true)
        ) {
            std::thread::sleep(Duration::from_millis(150));
            if !test_dacl_locked(service) {
                finish(&saved);
                return true;
            }
        }
    }

    let s3 = service.to_string();
    let sd3 = saved.clone();
    if matches!(
        ti::run_as_trusted_installer(move || set_dacl(&s3, &sd3)),
        Ok(true)
    ) {
        finish(&saved);
        return true;
    }
    false
}

fn clear_scm_triggers(service: &str) {
    let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        Ok(h) => ScHandle(h),
        Err(_) => return,
    };
    let svc = match open_service(&scm, service, SERVICE_CHANGE_CONFIG) {
        Some(s) => s,
        None => return,
    };
    let info = SERVICE_TRIGGER_INFO {
        cTriggers: 0,
        pTriggers: std::ptr::null_mut(),
        pReserved: std::ptr::null_mut(),
    };
    unsafe {
        let _ = ChangeServiceConfig2W(
            svc.get(),
            SERVICE_CONFIG_TRIGGER_INFO,
            Some(&info as *const _ as *const core::ffi::c_void),
        );
    }
}

pub fn remove_triggers(service: &str) {
    reg::create_key(consts::TRIGGER_BACKUP_KEY);
    let mut backup_done = false;
    for rel in all_controlset_paths(service) {
        let trigger = format!("{rel}\\TriggerInfo");
        if !reg::exists(&trigger) {
            continue;
        }
        if !backup_done {
            if let Some(blob) = regtree::capture(&trigger) {
                if reg::set_binary(consts::TRIGGER_BACKUP_KEY, service, &blob) {
                    backup_done = true;
                }
            }
        }
        token::enable_registry_privileges();
        let _ = reg::grant_key_access(&trigger);
        if !reg::delete_tree(&trigger) {
            let t = trigger.clone();
            let _ = ti::run_as_trusted_installer(move || reg::delete_tree(&t));
        }
    }
    clear_scm_triggers(service);
}

fn clear_scm_failure_actions(service: &str) {
    let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        Ok(h) => ScHandle(h),
        Err(_) => return,
    };
    let svc = match open_service(&scm, service, SERVICE_CHANGE_CONFIG) {
        Some(s) => s,
        None => return,
    };
    let mut actions = [SC_ACTION {
        Type: SC_ACTION_NONE,
        Delay: 0,
    }; 3];
    let fa = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 0,
        lpRebootMsg: PWSTR::null(),
        lpCommand: PWSTR::null(),
        cActions: 3,
        lpsaActions: actions.as_mut_ptr(),
    };
    let flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: false.into(),
    };
    unsafe {
        let _ = ChangeServiceConfig2W(
            svc.get(),
            SERVICE_CONFIG_FAILURE_ACTIONS,
            Some(&fa as *const _ as *const core::ffi::c_void),
        );
        let _ = ChangeServiceConfig2W(
            svc.get(),
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            Some(&flag as *const _ as *const core::ffi::c_void),
        );
    }
}

pub fn neutralize_recovery(service: &str) {
    reg::create_key(consts::FAILURE_BACKUP_KEY);
    let mut backup_done = false;
    for rel in all_controlset_paths(service) {
        if !reg::exists(&rel) {
            continue;
        }
        if !backup_done {
            if let Some(fa) = reg::get_binary(&rel, "FailureActions") {
                if !fa.is_empty() && reg::set_binary(consts::FAILURE_BACKUP_KEY, service, &fa) {
                    backup_done = true;
                }
            }
        }
        if !reg::set_binary(&rel, "FailureActions", &[0u8; 36]) {
            let r = rel.clone();
            let _ = ti::run_as_trusted_installer(move || {
                reg::set_binary(&r, "FailureActions", &[0u8; 36])
            });
        }
        let _ = reg::delete_value(&rel, "FailureCommand");
    }
    clear_scm_failure_actions(service);
}

pub fn restore_recovery(service: &str) {
    let fa = match reg::get_binary(consts::FAILURE_BACKUP_KEY, service) {
        Some(b) => b,
        None => return,
    };
    let mut restored = false;
    for rel in all_controlset_paths(service) {
        if !reg::exists(&rel) {
            continue;
        }
        if reg::set_binary(&rel, "FailureActions", &fa) {
            restored = true;
        } else {
            let r = rel.clone();
            let f = fa.clone();
            if matches!(
                ti::run_as_trusted_installer(move || reg::set_binary(&r, "FailureActions", &f)),
                Ok(true)
            ) {
                restored = true;
            }
        }
    }
    if restored {
        let _ = reg::delete_value(consts::FAILURE_BACKUP_KEY, service);
    }
}

pub fn save_start_config(service: &str) {
    reg::create_key(consts::SERVICE_CONFIG_BACKUP_KEY);
    let start_name = format!("{service}.Start");
    if reg::get_dword(consts::SERVICE_CONFIG_BACKUP_KEY, &start_name).is_some() {
        return;
    }
    let rel = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
    if !reg::exists(&rel) {
        return;
    }
    let start = reg::get_dword(&rel, "Start").unwrap_or(0);
    reg::set_dword(consts::SERVICE_CONFIG_BACKUP_KEY, &start_name, start);

    let delayed = reg::get_dword(&rel, "DelayedAutoStart");
    reg::set_dword(
        consts::SERVICE_CONFIG_BACKUP_KEY,
        &format!("{service}.DelayedAutoStartExists"),
        delayed.is_some() as u32,
    );
    if let Some(d) = delayed {
        reg::set_dword(
            consts::SERVICE_CONFIG_BACKUP_KEY,
            &format!("{service}.DelayedAutoStart"),
            d,
        );
    }
}

pub fn restore_config(service: &str, default_start: u32, default_delayed: Option<u32>) -> bool {
    let backup = consts::SERVICE_CONFIG_BACKUP_KEY;
    let mut start_value = default_start;
    let mut delayed_exists = default_delayed.is_some();
    let mut delayed_value = default_delayed;
    let mut used_backup = false;

    if let Some(v) = reg::get_dword(backup, &format!("{service}.Start")) {
        start_value = v;
        used_backup = true;
    }
    if let Some(ex) = reg::get_dword(backup, &format!("{service}.DelayedAutoStartExists")) {
        delayed_exists = ex == 1;
        delayed_value = if delayed_exists {
            reg::get_dword(backup, &format!("{service}.DelayedAutoStart"))
        } else {
            None
        };
        used_backup = true;
    }

    let mut all_ok = true;
    for rel in all_controlset_paths(service) {
        if !reg::exists(&rel) {
            continue;
        }
        let _ = reg::remove_system_deny(&rel);
        if !reg::set_dword(&rel, "Start", start_value) {
            all_ok = false;
        }
        if delayed_exists {
            if !reg::set_dword(&rel, "DelayedAutoStart", delayed_value.unwrap_or(0)) {
                all_ok = false;
            }
        } else {
            let _ = reg::delete_value(&rel, "DelayedAutoStart");
        }
        if reg::get_dword(&rel, "Start") != Some(start_value) {
            all_ok = false;
        }
    }

    if all_ok && used_backup {
        for suffix in ["Start", "DelayedAutoStartExists", "DelayedAutoStart"] {
            let _ = reg::delete_value(backup, &format!("{service}.{suffix}"));
        }
    }
    all_ok
}

pub fn restore_triggers(service: &str) {
    let blob = match reg::get_binary(consts::TRIGGER_BACKUP_KEY, service) {
        Some(b) => b,
        None => return,
    };
    let paths = all_controlset_paths(service);
    if paths.is_empty() {
        return;
    }
    let mut restored = false;
    for rel in &paths {
        let target = format!("{rel}\\TriggerInfo");
        if regtree::restore(&target, &blob) {
            restored = true;
        }
    }
    if restored {
        let _ = reg::delete_value(consts::TRIGGER_BACKUP_KEY, service);
    }
}

fn each_update_service() -> impl Iterator<Item = &'static str> {
    consts::UPDATE_SERVICES
        .iter()
        .chain(consts::OPTIONAL_SERVICES.iter())
        .copied()
}

fn service_exists(name: &str) -> bool {
    reg::exists(&format!("SYSTEM\\CurrentControlSet\\Services\\{name}"))
}

fn enable_config(name: &str) -> Option<(u32, Option<u32>)> {
    match name {
        "wuauserv" | "UsoSvc" | "WaaSMedicSvc" | "DoSvc" => Some((3, None)),
        "BITS" => Some((2, Some(1))),
        "uhssvc" => Some((2, None)),
        _ => None,
    }
}

pub fn disable_all() {
    for s in each_update_service() {
        if !service_exists(s) {
            continue;
        }
        save_start_config(s);
        remove_triggers(s);
        neutralize_recovery(s);
        let extra = extra_sid(s);
        lock_dacl(s, &extra);
        set_start_type(s, 4);
        set_all_controlsets_disabled(s);
    }
    if service_exists("WaaSMedicSvc") {
        crate::waas::harden_binaries();
        crate::waas::null_imagepath();
    }
    crate::waas::harden_xml();
}

pub fn enable_all() {
    crate::waas::restore_binaries();
    crate::waas::restore_xml();

    for s in each_update_service() {
        if service_exists(s) {
            unlock_dacl(s);
        }
    }
    for s in each_update_service() {
        if !service_exists(s) {
            continue;
        }
        remove_deny_all_controlsets(s);
        let cc = format!("SYSTEM\\CurrentControlSet\\Services\\{s}");
        let _ = reg::remove_system_deny(&cc);
    }

    crate::waas::restore_imagepath();

    for s in each_update_service() {
        let (start, delayed) = match enable_config(s) {
            Some(c) => c,
            None => continue,
        };
        if !service_exists(s) {
            continue;
        }
        restore_triggers(s);
        restore_recovery(s);
        set_start_type(s, start);
        restore_config(s, start, delayed);
    }
}
