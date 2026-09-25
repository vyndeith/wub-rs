use crate::handle::RegKey;
use std::iter::once;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegSetValueExW,
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_OPTION_BACKUP_RESTORE,
    REG_OPTION_NON_VOLATILE, REG_VALUE_TYPE,
};

#[derive(Debug, PartialEq, Clone)]
pub struct Node {
    values: Vec<(Vec<u16>, u32, Vec<u8>)>,
    subkeys: Vec<(Vec<u16>, Node)>,
}

pub fn capture(path: &str) -> Option<Vec<u8>> {
    let key = open_read_hklm(path)?;
    Some(serialize(&read_node(&key)))
}

pub fn restore(path: &str, blob: &[u8]) -> bool {
    match deserialize(blob) {
        Some(node) => match create_hklm(path) {
            Some(key) => write_into(&key, &node),
            None => false,
        },
        None => false,
    }
}

fn open_read_hklm(path: &str) -> Option<RegKey> {
    let sub = HSTRING::from(path);
    for opt in [REG_OPTION_NON_VOLATILE.0, REG_OPTION_BACKUP_RESTORE.0] {
        let mut hk = HKEY::default();
        let r = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub.as_ptr()),
                Some(opt),
                KEY_READ,
                &mut hk,
            )
        };
        if r == ERROR_SUCCESS {
            return Some(RegKey(hk));
        }
    }
    None
}

fn create_hklm(path: &str) -> Option<RegKey> {
    let sub = HSTRING::from(path);
    for opt in [REG_OPTION_NON_VOLATILE, REG_OPTION_BACKUP_RESTORE] {
        let mut hk = HKEY::default();
        let r = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub.as_ptr()),
                None,
                PCWSTR::null(),
                opt,
                KEY_WRITE,
                None,
                &mut hk,
                None,
            )
        };
        if r == ERROR_SUCCESS {
            return Some(RegKey(hk));
        }
    }
    None
}

fn read_node(key: &RegKey) -> Node {
    Node {
        values: enum_values(key),
        subkeys: enum_subnodes(key),
    }
}

fn enum_values(key: &RegKey) -> Vec<(Vec<u16>, u32, Vec<u8>)> {
    let mut nvalues = 0u32;
    let mut max_name = 0u32;
    let mut max_data = 0u32;
    unsafe {
        let _ = RegQueryInfoKeyW(
            key.get(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&mut nvalues),
            Some(&mut max_name),
            Some(&mut max_data),
            None,
            None,
        );
    }
    let mut out = Vec::new();
    for i in 0..nvalues {
        let mut name = vec![0u16; max_name as usize + 1];
        let mut nlen = name.len() as u32;
        let mut data = vec![0u8; max_data as usize];
        let mut dlen = data.len() as u32;
        let mut vtype = 0u32;
        let r = unsafe {
            RegEnumValueW(
                key.get(),
                i,
                Some(PWSTR(name.as_mut_ptr())),
                &mut nlen,
                None,
                Some(&mut vtype),
                Some(data.as_mut_ptr()),
                Some(&mut dlen),
            )
        };
        if r != ERROR_SUCCESS {
            break;
        }
        name.truncate(nlen as usize);
        data.truncate(dlen as usize);
        out.push((name, vtype, data));
    }
    out
}

fn enum_subnodes(key: &RegKey) -> Vec<(Vec<u16>, Node)> {
    let mut out = Vec::new();
    let mut i = 0u32;
    loop {
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        let r = unsafe {
            RegEnumKeyExW(
                key.get(),
                i,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if r != ERROR_SUCCESS {
            break;
        }
        let name = buf[..len as usize].to_vec();
        if let Some(child) = open_child(key, &name) {
            out.push((name, read_node(&child)));
        }
        i += 1;
    }
    out
}

fn open_child(key: &RegKey, name: &[u16]) -> Option<RegKey> {
    let namez: Vec<u16> = name.iter().copied().chain(once(0)).collect();
    for opt in [REG_OPTION_NON_VOLATILE.0, REG_OPTION_BACKUP_RESTORE.0] {
        let mut hk = HKEY::default();
        let r = unsafe {
            RegOpenKeyExW(
                key.get(),
                PCWSTR(namez.as_ptr()),
                Some(opt),
                KEY_READ,
                &mut hk,
            )
        };
        if r == ERROR_SUCCESS {
            return Some(RegKey(hk));
        }
    }
    None
}

fn write_into(key: &RegKey, node: &Node) -> bool {
    let mut ok = true;
    for (name, vtype, data) in &node.values {
        let namez: Vec<u16> = name.iter().copied().chain(once(0)).collect();
        let r = unsafe {
            RegSetValueExW(
                key.get(),
                PCWSTR(namez.as_ptr()),
                None,
                REG_VALUE_TYPE(*vtype),
                Some(data),
            )
        };
        if r != ERROR_SUCCESS {
            ok = false;
        }
    }
    for (name, child) in &node.subkeys {
        let namez: Vec<u16> = name.iter().copied().chain(once(0)).collect();
        let mut hk = HKEY::default();
        let r = unsafe {
            RegCreateKeyExW(
                key.get(),
                PCWSTR(namez.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut hk,
                None,
            )
        };
        if r == ERROR_SUCCESS {
            if !write_into(&RegKey(hk), child) {
                ok = false;
            }
        } else {
            ok = false;
        }
    }
    ok
}

fn serialize(node: &Node) -> Vec<u8> {
    let mut buf = Vec::new();
    ser_node(node, &mut buf);
    buf
}

fn ser_node(node: &Node, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(node.values.len() as u32).to_le_bytes());
    for (name, vtype, data) in &node.values {
        put_bytes(buf, &u16_to_bytes(name));
        buf.extend_from_slice(&vtype.to_le_bytes());
        put_bytes(buf, data);
    }
    buf.extend_from_slice(&(node.subkeys.len() as u32).to_le_bytes());
    for (name, child) in &node.subkeys {
        put_bytes(buf, &u16_to_bytes(name));
        ser_node(child, buf);
    }
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

fn deserialize(blob: &[u8]) -> Option<Node> {
    let mut cur = Cursor { b: blob, pos: 0 };
    let node = de_node(&mut cur)?;
    if cur.pos == blob.len() {
        Some(node)
    } else {
        None
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        if end > self.b.len() {
            return None;
        }
        let v = u32::from_le_bytes(self.b[self.pos..end].try_into().ok()?);
        self.pos = end;
        Some(v)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let end = self.pos.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Some(s)
    }
}

fn de_node(cur: &mut Cursor) -> Option<Node> {
    let vc = cur.u32()?;
    let mut values = Vec::with_capacity(vc as usize);
    for _ in 0..vc {
        let name = bytes_to_u16(cur.bytes()?);
        let vtype = cur.u32()?;
        let data = cur.bytes()?.to_vec();
        values.push((name, vtype, data));
    }
    let sc = cur.u32()?;
    let mut subkeys = Vec::with_capacity(sc as usize);
    for _ in 0..sc {
        let name = bytes_to_u16(cur.bytes()?);
        let child = de_node(cur)?;
        subkeys.push((name, child));
    }
    Some(Node { values, subkeys })
}

fn u16_to_bytes(s: &[u16]) -> Vec<u8> {
    s.iter().flat_map(|u| u.to_le_bytes()).collect()
}

fn bytes_to_u16(b: &[u8]) -> Vec<u16> {
    b.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}
