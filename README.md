# wub-rs

A small native Windows executable that blocks and unblocks Windows Update at every layer.
Rust port of a PowerShell Windows Update blocker, using the Win32 API directly (no
`sc.exe` / `reg.exe` / `schtasks.exe` / `icacls.exe` calls for the core logic).

## Warning

This tool is destructive by design. `Disable` breaks Windows Update: it disables and locks
the update services, denies SYSTEM and TrustedInstaller access to them, sets policy keys,
disables the scheduled tasks, and neutralizes WaaSMedic (the component that self-heals
these changes). Run it inside a VM or on a machine you can restore, not on a system you
care about. It requires administrator rights and elevates itself.

The build is unsigned, so SmartScreen and some antivirus products will flag it. That is
expected for this kind of tool.

## Usage

```
wu-blocker.exe Disable
wu-blocker.exe Enable
```

With no argument it prompts for D or E.

Flags (Enable only, all optional):

- `--no-store-repair`   skip the Microsoft Store repair (wsreset + AppX re-registration, slow)
- `--no-cache-reset`    skip renaming SoftwareDistribution and catroot2
- `--deep-repair`       also run `DISM /RestoreHealth` and `sfc /scannow` (very slow)

Flag (Disable only):

- `--refresh-baseline`  overwrite the saved baseline with the current machine state

A reboot after `Disable` is recommended so the service control manager fully settles the
disabled state.

## How it works

`Disable`:

1. Save a baseline of the current state (services, tasks, policy keys, files, WaaS XML) to
   `%ProgramData%\WUBlocker\DynamicBaseline\` so `Enable` can restore it exactly.
2. Stop the update services.
3. For every update service, across all control sets: back up its start config, remove
   trigger and recovery info, lock the service DACL, set start type to disabled, and apply
   a deny ACL for SYSTEM and TrustedInstaller.
4. Write the Windows Update group policy keys (no auto update, WSUS pointed at localhost,
   Store auto download disabled, driver search disabled).
5. Disable the update scheduled tasks and deny write access to their task files.
6. Rename the WaaSMedic binaries, null its ImagePath, and harden upfc.exe and the WaaS XML.

`Enable` reverses all of the above, restores the exact baseline where available, resets the
Windows Update cache, repairs the Microsoft Store, optionally runs component repair, and
starts the update services again.

Services handled: wuauserv, UsoSvc, BITS, WaaSMedicSvc, DoSvc, uhssvc.

## Build

Requires a Rust toolchain (stable, MSVC target).

```
cargo build --release
```

The output is `target/release/wu-blocker.exe`. The C runtime is linked statically
(`.cargo/config.toml`), so the exe is self-contained and needs no VC++ redistributable.

Prebuilt binaries are produced by the GitHub Actions build workflow (see the Actions tab).

## Verify

`verify-block.ps1` checks every layer after a `Disable` and prints a PASS/FAIL summary. Run
it elevated:

```
powershell -ExecutionPolicy Bypass -File verify-block.ps1
```
