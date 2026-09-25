pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bool(&mut self, b: bool) {
        self.buf.push(b as u8);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    pub fn opt_str(&mut self, s: Option<&str>) {
        match s {
            Some(v) => {
                self.bool(true);
                self.str(v);
            }
            None => self.bool(false),
        }
    }

    pub fn opt_bytes(&mut self, b: Option<&[u8]>) {
        match b {
            Some(v) => {
                self.bool(true);
                self.bytes(v);
            }
            None => self.bool(false),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    pub fn u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        if end > self.b.len() {
            return None;
        }
        let v = u32::from_le_bytes(self.b[self.pos..end].try_into().ok()?);
        self.pos = end;
        Some(v)
    }

    pub fn bool(&mut self) -> Option<bool> {
        if self.pos >= self.b.len() {
            return None;
        }
        let v = self.b[self.pos] != 0;
        self.pos += 1;
        Some(v)
    }

    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let end = self.pos.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Some(s)
    }

    pub fn str(&mut self) -> Option<String> {
        Some(String::from_utf8_lossy(self.bytes()?).into_owned())
    }

    pub fn opt_str(&mut self) -> Option<Option<String>> {
        if self.bool()? {
            Some(Some(self.str()?))
        } else {
            Some(None)
        }
    }

    pub fn opt_bytes(&mut self) -> Option<Option<Vec<u8>>> {
        if self.bool()? {
            Some(Some(self.bytes()?.to_vec()))
        } else {
            Some(None)
        }
    }
}
