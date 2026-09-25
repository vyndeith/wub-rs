use crate::error::Result;
use windows::core::{BOOL, HSTRING, PCWSTR};
use windows::Win32::Security::{
    AllocateAndInitializeSid, CheckTokenMembership, FreeSid, PSID, SID_IDENTIFIER_AUTHORITY,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};

const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x20;
const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x220;
const SW_SHOWNORMAL: i32 = 1;

pub fn is_elevated() -> Result<bool> {
    let nt_authority = SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 5],
    };
    let mut admins = PSID::default();
    unsafe {
        AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admins,
        )?;
    }

    let mut is_member = BOOL(0);
    let check = unsafe { CheckTokenMembership(None, admins, &mut is_member) };
    unsafe { FreeSid(admins) };
    check?;
    Ok(is_member.as_bool())
}

pub fn relaunch_elevated() -> Result<()> {
    let exe = std::env::current_exe()?;
    let params: String = std::env::args()
        .skip(1)
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(" ");

    let verb = HSTRING::from("runas");
    let file = HSTRING::from(exe.as_os_str());
    let args = HSTRING::from(params);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: if args.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(args.as_ptr())
        },
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };

    unsafe { ShellExecuteExW(&mut info) }?;
    Ok(())
}
