use crate::handle::RegKey;
use crate::sddl;
use crate::{consts, token};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteKeyW, RegDeleteTreeW, RegEnumKeyExW,
    RegEnumValueW, RegGetKeySecurity, RegGetValueW, RegOpenKeyExW, RegQueryInfoKeyW,
    RegQueryValueExW, RegSetKeySecurity, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS,
    KEY_READ, KEY_WRITE, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_BACKUP_RESTORE,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RRF_NOEXPAND,
    RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

const NON_VOLATILE: u32 = 0;
const BACKUP_RESTORE: u32 = REG_OPTION_BACKUP_RESTORE.0;

fn open(path: &str, attempts: &[(u32, REG_SAM_FLAGS)]) -> Option<RegKey> {
    let sub = HSTRING::from(path);
    for &(opt, sam) in attempts {
        let mut hkey = HKEY::default();
        let ret = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub.as_ptr()),
                Some(opt),
                sam,
                &mut hkey,
            )
        };
        if ret == ERROR_SUCCESS {
            return Some(RegKey(hkey));
        }
    }
    None
}

pub fn exists(path: &str) -> bool {
    open(
        path,
        &[(NON_VOLATILE, KEY_READ), (BACKUP_RESTORE, KEY_READ)],
    )
    .is_some()
}

pub fn values(path: &str) -> Vec<(String, u32, Vec<u8>)> {
    let key = match open(
        path,
        &[(NON_VOLATILE, KEY_READ), (BACKUP_RESTORE, KEY_READ)],
    ) {
        Some(k) => k,
        None => return Vec::new(),
    };
    let mut nvalues = 0u32;
    let mut max_name = 0u32;
    let mut max_data = 0u32;
    unsafe {
        let _ = RegQueryInfoKeyW(
            key.get(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&mut nvalues),
            Some(&mut max_name),
            Some(&mut max_data),
            None,
            None,
        );
    }
    let mut out = Vec::new();
    for i in 0..nvalues {
        let mut name = vec![0u16; max_name as usize + 1];
        let mut nlen = name.len() as u32;
        let mut data = vec![0u8; max_data as usize];
        let mut dlen = data.len() as u32;
        let mut vtype = 0u32;
        let r = unsafe {
            RegEnumValueW(
                key.get(),
                i,
                Some(PWSTR(name.as_mut_ptr())),
                &mut nlen,
                None,
                Some(&mut vtype),
                Some(data.as_mut_ptr()),
                Some(&mut dlen),
            )
        };
        if r != ERROR_SUCCESS {
            break;
        }
        data.truncate(dlen as usize);
        out.push((
            String::from_utf16_lossy(&name[..nlen as usize]),
            vtype,
            data,
        ));
    }
    out
}

pub fn set_value_raw(path: &str, name: &str, vtype: u32, data: &[u8]) -> bool {
    let key = match open(
        path,
        &[
            (NON_VOLATILE, KEY_ALL_ACCESS),
            (BACKUP_RESTORE, KEY_ALL_ACCESS),
        ],
    ) {
        Some(k) => k,
        None => return false,
    };
    let n = HSTRING::from(name);
    unsafe {
        RegSetValueExW(
            key.get(),
            PCWSTR(n.as_ptr()),
            None,
            REG_VALUE_TYPE(vtype),
            Some(data),
        ) == ERROR_SUCCESS
    }
}

pub fn subkeys(path: &str) -> Vec<String> {
    let key = match open(
        path,
        &[(NON_VOLATILE, KEY_READ), (BACKUP_RESTORE, KEY_READ)],
    ) {
        Some(k) => k,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut i = 0u32;
    loop {
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        let ret = unsafe {
            RegEnumKeyExW(
                key.get(),
                i,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if ret != ERROR_SUCCESS {
            break;
        }
        out.push(String::from_utf16_lossy(&buf[..len as usize]));
        i += 1;
    }
    out
}

pub fn get_string(path: &str, name: &str) -> Option<String> {
    let sub = HSTRING::from(path);
    let n = HSTRING::from(name);
    unsafe {
        let mut cb = 0u32;
        let r = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(n.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut cb),
        );
        if r != ERROR_SUCCESS || cb == 0 {
            return None;
        }
        let mut buf = vec![0u16; (cb as usize).div_ceil(2)];
        let r2 = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(n.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut cb),
        );
        if r2 != ERROR_SUCCESS {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

pub fn get_dword(path: &str, name: &str) -> Option<u32> {
    let sub = HSTRING::from(path);
    let n = HSTRING::from(name);
    let mut data = 0u32;
    let mut cb = 4u32;
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(n.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut u32 as *mut core::ffi::c_void),
            Some(&mut cb),
        )
    };
    if r == ERROR_SUCCESS {
        Some(data)
    } else {
        None
    }
}

pub fn get_binary(path: &str, name: &str) -> Option<Vec<u8>> {
    let sub = HSTRING::from(path);
    let n = HSTRING::from(name);
    unsafe {
        let mut cb = 0u32;
        let r = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(n.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            None,
            Some(&mut cb),
        );
        if r != ERROR_SUCCESS || cb == 0 {
            return None;
        }
        let mut buf = vec![0u8; cb as usize];
        let r2 = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(n.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut cb),
        );
        if r2 != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(cb as usize);
        Some(buf)
    }
}

pub fn set_string(path: &str, name: &str, value: &str) -> bool {
    let sub = HSTRING::from(path);
    let mut hkey = HKEY::default();
    let created = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    if created != ERROR_SUCCESS {
        return false;
    }
    let key = RegKey(hkey);
    let n = HSTRING::from(name);
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
    unsafe {
        RegSetValueExW(key.get(), PCWSTR(n.as_ptr()), None, REG_SZ, Some(bytes)) == ERROR_SUCCESS
    }
}

pub fn get_expand_string(path: &str, name: &str) -> Option<String> {
    let sub = HSTRING::from(path);
    let n = HSTRING::from(name);
    unsafe {
        let mut cb = 0u32;
        let flags = RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
        let r = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(n.as_ptr()),
            flags,
            None,
            None,
            Some(&mut cb),
        );
        if r != ERROR_SUCCESS || cb == 0 {
            return None;
        }
        let mut buf = vec![0u16; (cb as usize).div_ceil(2)];
        let r2 = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(n.as_ptr()),
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut cb),
        );
        if r2 != ERROR_SUCCESS {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

pub fn set_expand_string(path: &str, name: &str, value: &str) -> bool {
    let key = match open(
        path,
        &[
            (NON_VOLATILE, KEY_ALL_ACCESS),
            (BACKUP_RESTORE, KEY_ALL_ACCESS),
        ],
    ) {
        Some(k) => k,
        None => return false,
    };
    let n = HSTRING::from(name);
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
    unsafe {
        RegSetValueExW(
            key.get(),
            PCWSTR(n.as_ptr()),
            None,
            REG_EXPAND_SZ,
            Some(bytes),
        ) == ERROR_SUCCESS
    }
}

pub fn delete_value(path: &str, name: &str) -> bool {
    let sub = HSTRING::from(path);
    let n = HSTRING::from(name);
    unsafe {
        RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, PCWSTR(sub.as_ptr()), PCWSTR(n.as_ptr()))
            == ERROR_SUCCESS
    }
}

pub fn create_key(path: &str) -> bool {
    let sub = HSTRING::from(path);
    let mut hkey = HKEY::default();
    let r = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    if r == ERROR_SUCCESS {
        let _ = RegKey(hkey);
        true
    } else {
        false
    }
}

pub fn delete_tree(path: &str) -> bool {
    let sub = HSTRING::from(path);
    unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(sub.as_ptr())) == ERROR_SUCCESS }
}

pub fn delete_key(path: &str) -> bool {
    let sub = HSTRING::from(path);
    unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(sub.as_ptr())) == ERROR_SUCCESS }
}

pub fn key_counts(path: &str) -> Option<(u32, u32)> {
    let key = open(
        path,
        &[(NON_VOLATILE, KEY_READ), (BACKUP_RESTORE, KEY_READ)],
    )?;
    let mut subkeys = 0u32;
    let mut values = 0u32;
    let r = unsafe {
        RegQueryInfoKeyW(
            key.get(),
            None,
            None,
            None,
            Some(&mut subkeys),
            None,
            None,
            Some(&mut values),
            None,
            None,
            None,
            None,
        )
    };
    if r == ERROR_SUCCESS {
        Some((subkeys, values))
    } else {
        None
    }
}

pub fn set_dword(path: &str, value_name: &str, value: u32) -> bool {
    let key = match open(
        path,
        &[
            (NON_VOLATILE, KEY_ALL_ACCESS),
            (BACKUP_RESTORE, KEY_ALL_ACCESS),
        ],
    ) {
        Some(k) => k,
        None => return false,
    };
    let name = HSTRING::from(value_name);
    let data = value.to_le_bytes();
    unsafe {
        RegSetValueExW(
            key.get(),
            PCWSTR(name.as_ptr()),
            None,
            REG_DWORD,
            Some(&data[..]),
        ) == ERROR_SUCCESS
    }
}

pub fn set_binary(path: &str, value_name: &str, data: &[u8]) -> bool {
    let key = match open(
        path,
        &[
            (NON_VOLATILE, KEY_ALL_ACCESS),
            (BACKUP_RESTORE, KEY_ALL_ACCESS),
        ],
    ) {
        Some(k) => k,
        None => return false,
    };
    let name = HSTRING::from(value_name);
    unsafe {
        RegSetValueExW(
            key.get(),
            PCWSTR(name.as_ptr()),
            None,
            REG_BINARY,
            Some(data),
        ) == ERROR_SUCCESS
    }
}

pub fn read_service_sddl(path: &str) -> String {
    let key = match open(
        path,
        &[(NON_VOLATILE, KEY_READ), (BACKUP_RESTORE, KEY_READ)],
    ) {
        Some(k) => k,
        None => return String::new(),
    };
    let name = HSTRING::from("Security");
    let mut cb: u32 = 0;
    unsafe {
        let _ = RegQueryValueExW(
            key.get(),
            PCWSTR(name.as_ptr()),
            None,
            None,
            None,
            Some(&mut cb),
        );
    }
    if cb == 0 {
        return String::new();
    }
    let mut buf = vec![0u8; cb as usize];
    let ret = unsafe {
        RegQueryValueExW(
            key.get(),
            PCWSTR(name.as_ptr()),
            None,
            None,
            Some(buf.as_mut_ptr()),
            Some(&mut cb),
        )
    };
    if ret != ERROR_SUCCESS {
        return String::new();
    }
    sddl::from_bytes(&buf[..cb as usize], DACL_SECURITY_INFORMATION).unwrap_or_default()
}

pub fn apply_sddl(path: &str, sddl_str: &str, si: OBJECT_SECURITY_INFORMATION) -> bool {
    let key = match open(
        path,
        &[
            (NON_VOLATILE, KEY_ALL_ACCESS),
            (BACKUP_RESTORE, KEY_ALL_ACCESS),
        ],
    ) {
        Some(k) => k,
        None => return false,
    };
    let bytes = match sddl::to_bytes(sddl_str) {
        Some(b) => b,
        None => return false,
    };
    let psd =
        windows::Win32::Security::PSECURITY_DESCRIPTOR(bytes.as_ptr() as *mut core::ffi::c_void);
    unsafe { RegSetKeySecurity(key.get(), si, psd) == ERROR_SUCCESS }
}

fn owner_dacl() -> OBJECT_SECURITY_INFORMATION {
    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
}

pub fn get_key_sddl(path: &str, si: OBJECT_SECURITY_INFORMATION) -> Option<String> {
    let key = open(
        path,
        &[(NON_VOLATILE, KEY_READ), (BACKUP_RESTORE, KEY_READ)],
    )?;
    let mut cb = 0u32;
    unsafe {
        let _ = RegGetKeySecurity(key.get(), si, None, &mut cb);
    }
    if cb == 0 {
        return None;
    }
    let words = (cb as usize).div_ceil(4);
    let mut buf: Vec<u32> = vec![0; words];
    let psd = PSECURITY_DESCRIPTOR(buf.as_mut_ptr() as *mut core::ffi::c_void);
    let r = unsafe { RegGetKeySecurity(key.get(), si, Some(psd), &mut cb) };
    if r != ERROR_SUCCESS {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, cb as usize) };
    sddl::from_bytes(bytes, si)
}

pub fn grant_key_access(path: &str) -> bool {
    let si = owner_dacl();
    token::enable_registry_privileges();
    if apply_sddl(path, consts::ALLOW_SDDL, si) {
        return true;
    }
    let p = path.to_string();
    matches!(
        crate::ti::run_as_trusted_installer(move || apply_sddl(&p, consts::ALLOW_SDDL, si)),
        Ok(true)
    )
}

pub fn add_system_deny(path: &str, extra_service_sid: &str) -> bool {
    let mut deny = String::from(consts::DENY_SDDL);
    if !extra_service_sid.is_empty() {
        deny.push_str(&format!("(D;OICI;KA;;;{extra_service_sid})"));
    }
    let si = owner_dacl();

    token::enable_registry_privileges();
    if apply_sddl(path, &deny, si) {
        return true;
    }
    if grant_key_access(path) {
        token::enable_registry_privileges();
        if apply_sddl(path, &deny, si) {
            return true;
        }
    }
    let p = path.to_string();
    let d = deny;
    matches!(
        crate::ti::run_as_trusted_installer(move || apply_sddl(&p, &d, si)),
        Ok(true)
    )
}

pub fn remove_system_deny(path: &str) -> bool {
    let si = owner_dacl();
    token::enable_registry_privileges();
    if apply_sddl(path, consts::ALLOW_SDDL, si) {
        return true;
    }
    if grant_key_access(path) {
        token::enable_registry_privileges();
        if apply_sddl(path, consts::ALLOW_SDDL, si) {
            return true;
        }
    }
    let p = path.to_string();
    matches!(
        crate::ti::run_as_trusted_installer(move || apply_sddl(&p, consts::ALLOW_SDDL, si)),
        Ok(true)
    )
}
