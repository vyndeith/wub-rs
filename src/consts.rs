pub const TI_SID: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

pub const DENY_SDDL: &str = concat!(
    "O:BAD:PAI(A;OICI;KA;;;BA)",
    "(D;OICI;KA;;;SY)",
    "(D;OICI;KA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)",
    "(D;OICI;KA;;;LS)",
    "(D;OICI;KA;;;NS)",
);

pub const ALLOW_SDDL: &str = "O:BAD:PAI(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)";

pub const SERVICES: [&str; 5] = ["wuauserv", "BITS", "WaaSMedicSvc", "UsoSvc", "DoSvc"];

pub const UPDATE_SERVICES: [&str; 5] = ["wuauserv", "UsoSvc", "BITS", "WaaSMedicSvc", "DoSvc"];
pub const OPTIONAL_SERVICES: [&str; 1] = ["uhssvc"];

pub const SVC_DACL_BACKUP_KEY: &str = "SOFTWARE\\WUBlocker\\ServiceSDDL";
pub const TRIGGER_BACKUP_KEY: &str = "SOFTWARE\\WUBlocker\\TriggerBackup";
pub const FAILURE_BACKUP_KEY: &str = "SOFTWARE\\WUBlocker\\FailureBackup";
pub const SERVICE_CONFIG_BACKUP_KEY: &str = "SOFTWARE\\WUBlocker\\ServiceConfigBackup";
