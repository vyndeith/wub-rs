# wublocker

A native Windows library to block and unblock Windows Update at every layer, using the
Win32 API directly (no `sc.exe` / `reg.exe` / `schtasks.exe` / `icacls.exe` calls for the
core logic).

This is the library-only branch. The application (CLI and GUI) lives on the `main` branch.

## Warning

This library is destructive by design. `disable` breaks Windows Update: it disables and
locks the update services, denies SYSTEM and TrustedInstaller access to them, sets policy
keys, disables the scheduled tasks, and neutralizes WaaSMedic (the component that
self-heals these changes). The calling process must run elevated (administrator).

## Usage

```rust
use wublocker::{disable, enable, check, is_elevated, Options};

fn main() {
    if !is_elevated() {
        eprintln!("run elevated");
        return;
    }
    disable(&Options::default());
    // enable(&Options::default());
    // check();
}
```

`Options` fields (all default false):

- `deep_repair`       run `DISM /RestoreHealth` and `sfc /scannow` on enable (very slow)
- `refresh_baseline`  overwrite the saved baseline with the current machine state
- `no_cache_reset`    skip renaming SoftwareDistribution and catroot2 on enable
- `no_store_repair`   skip the Microsoft Store repair on enable

Progress and errors go to stderr by default. Redirect them with a sink:

```rust
wublocker::set_sink(|line| { /* forward line somewhere */ });
```

Services handled: wuauserv, UsoSvc, BITS, WaaSMedicSvc, DoSvc, uhssvc.

The library does not self-elevate; that is the caller's responsibility. It contains no CLI
or GUI code.

## Notes

Windows only. Requires administrator rights at runtime.
