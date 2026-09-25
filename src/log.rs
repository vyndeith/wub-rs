pub fn error(msg: &str, err: Option<&crate::error::Error>) {
    match err {
        Some(e) => eprintln!("[x] {msg}: {e}"),
        None => eprintln!("[x] {msg}"),
    }
}

pub fn state(msg: &str) {
    eprintln!("[*] {msg}");
}
