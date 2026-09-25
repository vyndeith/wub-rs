use crate::error::{Error, Result};
use crate::handle::{Handle, ScHandle};
use crate::log;
use crate::token::{enable_privilege, enable_registry_privileges};
use std::time::{Duration, Instant};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf, SecurityImpersonation,
    TokenImpersonation, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Services::{
    ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, StartServiceW,
    SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_STATUS, SERVICE_STOP,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct ImpersonationGuard;

impl ImpersonationGuard {
    fn new(token: &Handle) -> Result<Self> {
        unsafe { ImpersonateLoggedOnUser(token.get())? };
        Ok(ImpersonationGuard)
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

pub fn run_as_trusted_installer<F, R>(action: F) -> Result<R>
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || impersonate_loop(action))
            .join()
            .unwrap_or_else(|_| Err(Error::last()))
    })
}

fn impersonate_loop<F, R>(action: F) -> Result<R>
where
    F: FnOnce() -> R,
{
    let _ = enable_privilege("SeDebugPrivilege");

    let (_scm, svc) = match ti_service() {
        Some(x) => x,
        None => {
            log::error("TrustedInstaller service not found", None);
            return Err(Error::last());
        }
    };

    let sys_access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE;
    let mut action = Some(action);

    for _ in 0..5 {
        if !is_running(&svc) {
            unsafe {
                let _ = StartServiceW(svc.get(), None);
            }
            wait_until(Duration::from_secs(8), || is_running(&svc));
        }

        let mut ti_pid = wait_for_pid(Duration::from_secs(3), "TrustedInstaller.exe");
        if ti_pid.is_none() {
            stop(&svc);
            std::thread::sleep(Duration::from_millis(300));
            unsafe {
                let _ = StartServiceW(svc.get(), None);
            }
            ti_pid = wait_for_pid(Duration::from_secs(3), "TrustedInstaller.exe");
            if ti_pid.is_none() {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        }
        let ti_pid = ti_pid.unwrap();

        let winlogon_pid = match find_pid("winlogon.exe") {
            Some(p) => p,
            None => {
                log::error("winlogon.exe not found", None);
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };

        let h_winlogon = match open_process(winlogon_pid) {
            Some(h) => h,
            None => {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };

        let h_sys = match open_token(&h_winlogon, sys_access)
            .or_else(|| open_token(&h_winlogon, TOKEN_ALL_ACCESS))
        {
            Some(h) => h,
            None => {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };

        let h_sys_imp = match dup_impersonation(&h_sys) {
            Some(h) => h,
            None => continue,
        };

        let sys_guard = match ImpersonationGuard::new(&h_sys_imp) {
            Ok(g) => g,
            Err(_) => continue,
        };

        let h_ti_proc = match open_process(ti_pid) {
            Some(h) => h,
            None => {
                drop(sys_guard);
                continue;
            }
        };

        let h_ti_tok = match open_token(&h_ti_proc, TOKEN_ALL_ACCESS)
            .or_else(|| open_token(&h_ti_proc, sys_access))
        {
            Some(h) => h,
            None => {
                drop(sys_guard);
                continue;
            }
        };

        let h_ti_imp = match dup_impersonation(&h_ti_tok) {
            Some(h) => h,
            None => {
                drop(sys_guard);
                continue;
            }
        };

        drop(sys_guard);
        let _ti_guard = match ImpersonationGuard::new(&h_ti_imp) {
            Ok(g) => g,
            Err(_) => continue,
        };

        enable_registry_privileges();
        let r = (action.take().unwrap())();
        return Ok(r);
    }

    log::error("all TrustedInstaller impersonation attempts failed", None);
    Err(Error::last())
}

fn ti_service() -> Option<(ScHandle, ScHandle)> {
    unsafe {
        let scm =
            ScHandle(OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).ok()?);
        let name = HSTRING::from("TrustedInstaller");
        let svc = ScHandle(
            OpenServiceW(
                scm.get(),
                PCWSTR(name.as_ptr()),
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
            )
            .ok()?,
        );
        Some((scm, svc))
    }
}

fn is_running(svc: &ScHandle) -> bool {
    let mut st = SERVICE_STATUS::default();
    unsafe {
        QueryServiceStatus(svc.get(), &mut st).is_ok() && st.dwCurrentState == SERVICE_RUNNING
    }
}

fn stop(svc: &ScHandle) {
    let mut st = SERVICE_STATUS::default();
    unsafe {
        let _ = ControlService(svc.get(), SERVICE_CONTROL_STOP, &mut st);
    }
}

fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !ready() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_pid(timeout: Duration, exe: &str) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(p) = find_pid(exe) {
            return Some(p);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn find_pid(exe: &str) -> Option<u32> {
    unsafe {
        let snap = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?);
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap.get(), &mut entry).is_err() {
            return None;
        }
        loop {
            let end = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
            if name.eq_ignore_ascii_case(exe) {
                return Some(entry.th32ProcessID);
            }
            if Process32NextW(snap.get(), &mut entry).is_err() {
                return None;
            }
        }
    }
}

fn open_process(pid: u32) -> Option<Handle> {
    unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
            .or_else(|_| OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))
            .ok()
            .map(Handle)
    }
}

fn open_token(proc: &Handle, access: TOKEN_ACCESS_MASK) -> Option<Handle> {
    let mut tok = HANDLE::default();
    unsafe { OpenProcessToken(proc.get(), access, &mut tok).ok()? };
    Some(Handle(tok))
}

fn dup_impersonation(tok: &Handle) -> Option<Handle> {
    let mut new = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            tok.get(),
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut new,
        )
        .ok()?
    };
    Some(Handle(new))
}
