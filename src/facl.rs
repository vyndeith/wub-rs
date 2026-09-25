use crate::{consts, sddl, token};
use windows::core::{BOOL, HSTRING};
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

pub const MODIFY: &str = "0x1301bf";
pub const FULL: &str = "0x1f01ff";
pub const WRITE_DELETE: &str = "0x130116";

pub fn dacl_sddl(path: &str) -> Option<String> {
    let w = HSTRING::from(path);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let r = unsafe {
        GetNamedSecurityInfoW(
            &w,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut psd,
        )
    };
    if r != ERROR_SUCCESS {
        return None;
    }
    let s = sddl::descriptor_to_string(psd, DACL_SECURITY_INFORMATION);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    s
}

pub fn take_ownership(path: &str) -> bool {
    let sd = match sddl::to_bytes("O:BA") {
        Some(b) => b,
        None => return false,
    };
    let mut owner = PSID::default();
    let mut defaulted = BOOL(0);
    unsafe {
        if GetSecurityDescriptorOwner(
            PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut core::ffi::c_void),
            &mut owner,
            &mut defaulted,
        )
        .is_err()
        {
            return false;
        }
        SetNamedSecurityInfoW(
            &HSTRING::from(path),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(owner),
            None,
            None,
            None,
        ) == ERROR_SUCCESS
    }
}

pub fn set_dacl(path: &str, dacl_body: &str) -> bool {
    let sd = match sddl::to_bytes(dacl_body) {
        Some(b) => b,
        None => return false,
    };
    let mut present = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = BOOL(0);
    unsafe {
        if GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut core::ffi::c_void),
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
        .is_err()
        {
            return false;
        }
        SetNamedSecurityInfoW(
            &HSTRING::from(path),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl as *const ACL),
            None,
        ) == ERROR_SUCCESS
    }
}

fn split_dacl(sddl_str: &str) -> (String, Vec<String>) {
    let start = sddl_str.find('(').unwrap_or(sddl_str.len());
    let header = sddl_str[..start].to_string();
    let mut aces = Vec::new();
    let mut rest = &sddl_str[start..];
    while let Some(open) = rest.find('(') {
        rest = &rest[open..];
        match rest.find(')') {
            Some(close) => {
                aces.push(rest[..=close].to_string());
                rest = &rest[close + 1..];
            }
            None => break,
        }
    }
    (header, aces)
}

fn ace_is_deny_for(ace: &str, sid: &str) -> bool {
    let inner = ace.trim_start_matches('(').trim_end_matches(')');
    let p: Vec<&str> = inner.split(';').collect();
    p.len() >= 6 && p[0] == "D" && p[5] == sid
}

fn build_deny(cur: &str, ti: &str, flags: &str, rights: &str) -> String {
    let (header, aces) = split_dacl(cur);
    let mut out = if header.is_empty() {
        "D:".to_string()
    } else {
        header
    };
    out.push_str(&format!(
        "(D;{flags};{rights};;;SY)(D;{flags};{rights};;;{ti})"
    ));
    for a in aces
        .iter()
        .filter(|a| !ace_is_deny_for(a, "SY") && !ace_is_deny_for(a, ti))
    {
        out.push_str(a);
    }
    out.push_str(&format!("(A;{flags};{FULL};;;BA)"));
    out
}

fn build_remove(cur: &str, ti: &str) -> String {
    let (header, aces) = split_dacl(cur);
    let mut out = if header.is_empty() {
        "D:".to_string()
    } else {
        header
    };
    for a in aces
        .iter()
        .filter(|a| !ace_is_deny_for(a, "SY") && !ace_is_deny_for(a, ti))
    {
        out.push_str(a);
    }
    out.push_str(&format!("(A;;{FULL};;;BA)"));
    out
}

pub fn deny(path: &str, ace_flags: &str, rights: &str) -> bool {
    let _ = token::enable_privilege("SeTakeOwnershipPrivilege");
    let _ = token::enable_privilege("SeRestorePrivilege");
    take_ownership(path);
    let cur = dacl_sddl(path).unwrap_or_else(|| "D:".to_string());
    set_dacl(path, &build_deny(&cur, consts::TI_SID, ace_flags, rights))
}

pub fn undeny(path: &str) -> bool {
    let _ = token::enable_privilege("SeTakeOwnershipPrivilege");
    let _ = token::enable_privilege("SeRestorePrivilege");
    take_ownership(path);
    let cur = dacl_sddl(path).unwrap_or_else(|| "D:".to_string());
    set_dacl(path, &build_remove(&cur, consts::TI_SID))
}

pub fn sddl_of(path: &str) -> Option<String> {
    let w = HSTRING::from(path);
    let si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let r =
        unsafe { GetNamedSecurityInfoW(&w, SE_FILE_OBJECT, si, None, None, None, None, &mut psd) };
    if r != ERROR_SUCCESS {
        return None;
    }
    let s = sddl::descriptor_to_string(psd, si);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    s
}

pub fn apply_sddl(path: &str, sddl_str: &str) -> bool {
    let _ = token::enable_privilege("SeTakeOwnershipPrivilege");
    let _ = token::enable_privilege("SeRestorePrivilege");
    let sd = match sddl::to_bytes(sddl_str) {
        Some(b) => b,
        None => return false,
    };
    let psd = PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut core::ffi::c_void);
    let mut owner = PSID::default();
    let mut d1 = BOOL(0);
    let mut present = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut d2 = BOOL(0);
    unsafe {
        if GetSecurityDescriptorOwner(psd, &mut owner, &mut d1).is_err()
            || GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut d2).is_err()
        {
            return false;
        }
        let owner_arg = if owner.0.is_null() { None } else { Some(owner) };
        SetNamedSecurityInfoW(
            &HSTRING::from(path),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            owner_arg,
            None,
            Some(dacl as *const ACL),
            None,
        ) == ERROR_SUCCESS
    }
}
