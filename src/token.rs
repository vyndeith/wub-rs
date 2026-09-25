use crate::error::Result;
use crate::handle::Handle;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn enable_privilege(name: &str) -> Result<()> {
    let mut raw = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut raw,
        )?;
    }
    let token = Handle(raw);

    let wide = HSTRING::from(name);
    let mut luid = LUID::default();
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid)? };

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { AdjustTokenPrivileges(token.get(), false, Some(&tp), 0, None, None)? };
    Ok(())
}

pub fn enable_registry_privileges() {
    let _ = enable_privilege("SeTakeOwnershipPrivilege");
    let _ = enable_privilege("SeRestorePrivilege");
    let _ = enable_privilege("SeBackupPrivilege");
}
