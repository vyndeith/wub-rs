use std::sync::Mutex;

type Sink = Box<dyn Fn(&str) + Send + 'static>;
static SINK: Mutex<Option<Sink>> = Mutex::new(None);

pub fn set_sink<F: Fn(&str) + Send + 'static>(f: F) {
    if let Ok(mut g) = SINK.lock() {
        *g = Some(Box::new(f));
    }
}

pub fn clear_sink() {
    if let Ok(mut g) = SINK.lock() {
        *g = None;
    }
}

fn emit(line: &str) {
    if let Ok(g) = SINK.lock() {
        if let Some(sink) = g.as_ref() {
            sink(line);
            return;
        }
    }
    eprintln!("{line}");
}

pub fn error(msg: &str, err: Option<&crate::error::Error>) {
    match err {
        Some(e) => emit(&format!("[x] {msg}: {e}")),
        None => emit(&format!("[x] {msg}")),
    }
}

pub fn state(msg: &str) {
    emit(&format!("[*] {msg}"));
}
