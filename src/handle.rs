use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Registry::{RegCloseKey, HKEY};
use windows::Win32::System::Services::{CloseServiceHandle, SC_HANDLE};

pub struct Handle(pub HANDLE);

impl Handle {
    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

pub struct RegKey(pub HKEY);

impl RegKey {
    pub fn get(&self) -> HKEY {
        self.0
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

pub struct ScHandle(pub SC_HANDLE);

impl ScHandle {
    pub fn get(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}
