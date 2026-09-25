use sha1::{Digest, Sha1};

pub fn service_sid(name: &str) -> String {
    let upper = name.to_uppercase();
    let utf16: Vec<u8> = upper.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

    let hash = Sha1::digest(&utf16);
    let rids: [u32; 5] = std::array::from_fn(|i| {
        u32::from_le_bytes([
            hash[i * 4],
            hash[i * 4 + 1],
            hash[i * 4 + 2],
            hash[i * 4 + 3],
        ])
    });

    format!(
        "S-1-5-80-{}-{}-{}-{}-{}",
        rids[0], rids[1], rids[2], rids[3], rids[4]
    )
}
