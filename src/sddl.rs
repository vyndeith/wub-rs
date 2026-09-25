use core::ffi::c_void;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

pub fn to_bytes(sddl: &str) -> Option<Vec<u8>> {
    let s = HSTRING::from(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let mut size: u32 = 0;
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(s.as_ptr()),
            1,
            &mut psd,
            Some(&mut size),
        )
        .ok()?;
        let bytes = std::slice::from_raw_parts(psd.0 as *const u8, size as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        Some(bytes)
    }
}

pub fn from_bytes(sd: &[u8], si: OBJECT_SECURITY_INFORMATION) -> Option<String> {
    descriptor_to_string(PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut c_void), si)
}

pub fn descriptor_to_string(
    psd: PSECURITY_DESCRIPTOR,
    si: OBJECT_SECURITY_INFORMATION,
) -> Option<String> {
    let mut pstr = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, 1, si, &mut pstr, None).ok()?;
        let s = pstr.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(pstr.0 as *mut c_void)));
        s
    }
}
