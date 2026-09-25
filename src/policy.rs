use crate::reg;

const WU: &str = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
const AU: &str = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";
const STORE: &str = "SOFTWARE\\Policies\\Microsoft\\WindowsStore";
const LEGACY_AU: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update";
const DRIVER_SEARCH: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching";
const DRIVER_POLICY: &str = "SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching";
const DEVICE_META: &str = "SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata";

pub fn set_block() {
    reg::create_key(WU);
    reg::create_key(AU);
    for (n, v) in [
        ("NoAutoUpdate", 1),
        ("AUOptions", 1),
        ("UseWUServer", 1),
        ("ScheduledInstallDay", 0),
        ("ScheduledInstallTime", 0),
    ] {
        reg::set_dword(AU, n, v);
    }
    for (n, v) in [
        ("DisableWindowsUpdateAccess", 1),
        ("ExcludeWUDriversInQualityUpdate", 1),
        ("SetDisableUXWUAccess", 1),
        ("SetDisablePauseUpdates", 1),
    ] {
        reg::set_dword(WU, n, v);
    }
    reg::set_string(WU, "WUServer", "http://localhost");
    reg::set_string(WU, "WUStatusServer", "http://localhost");

    reg::create_key(STORE);
    reg::set_dword(STORE, "AutoDownload", 2);
    reg::set_dword(STORE, "DisableOSUpgrade", 1);

    reg::create_key(LEGACY_AU);
    reg::set_dword(LEGACY_AU, "AUOptions", 1);
    reg::set_dword(LEGACY_AU, "IncludeRecommendedUpdates", 0);

    reg::create_key(DRIVER_SEARCH);
    reg::set_dword(DRIVER_SEARCH, "SearchOrderConfig", 0);
    reg::set_dword(DRIVER_SEARCH, "DontSearchWindowsUpdate", 1);

    reg::create_key(DRIVER_POLICY);
    reg::set_dword(DRIVER_POLICY, "DriverUpdateWizardWuSearchEnabled", 0);
    reg::set_dword(DRIVER_POLICY, "DontPromptForWindowsUpdate", 1);

    reg::create_key(DEVICE_META);
    reg::set_dword(DEVICE_META, "PreventDeviceMetadataFromNetwork", 1);
}

pub fn remove_block() {
    if reg::exists(AU) {
        reg::delete_tree(AU);
    }

    if reg::exists(WU) {
        for v in [
            "DisableWindowsUpdateAccess",
            "ExcludeWUDriversInQualityUpdate",
            "SetDisableUXWUAccess",
            "SetDisablePauseUpdates",
            "WUServer",
            "WUStatusServer",
        ] {
            reg::delete_value(WU, v);
        }
        if reg::key_counts(WU) == Some((0, 0)) {
            reg::delete_key(WU);
        }
    }

    if reg::exists(STORE) {
        reg::delete_value(STORE, "AutoDownload");
        reg::delete_value(STORE, "DisableOSUpgrade");
    }

    if reg::exists(LEGACY_AU) {
        reg::delete_value(LEGACY_AU, "AUOptions");
        reg::delete_value(LEGACY_AU, "IncludeRecommendedUpdates");
    }

    if reg::exists(DRIVER_SEARCH) {
        reg::delete_value(DRIVER_SEARCH, "SearchOrderConfig");
        reg::delete_value(DRIVER_SEARCH, "DontSearchWindowsUpdate");
    }

    if reg::exists(DRIVER_POLICY) {
        reg::delete_value(DRIVER_POLICY, "DriverUpdateWizardWuSearchEnabled");
        reg::delete_value(DRIVER_POLICY, "DontPromptForWindowsUpdate");
    }

    if reg::exists(DEVICE_META) {
        reg::delete_value(DEVICE_META, "PreventDeviceMetadataFromNetwork");
    }
}
