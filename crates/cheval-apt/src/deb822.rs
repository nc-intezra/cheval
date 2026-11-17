//! Streaming parser for Debian control-file ("deb822") paragraphs.
//!
//! Tolerant by design: non-UTF-8 bytes are replaced, CRLF is accepted, comments are
//! skipped, and whitespace around the colon is ignored (some third-party repositories
//! emit `SHA256 :` or `SHA256:<space>`).
use std::io::{self, BufRead};

#[derive(Debug, Default, Clone)]
pub struct Paragraph {
    fields: Vec<(String, String)>,
}

impl Paragraph {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
    pub fn fields(&self) -> &[(String, String)] {
        &self.fields
    }
}

pub struct Paragraphs<R: BufRead> {
    r: R,
    buf: Vec<u8>,
    done: bool,
}

impl<R: BufRead> Paragraphs<R> {
    pub fn new(r: R) -> Self {
        Self { r, buf: Vec::with_capacity(256), done: false }
    }
}

impl<R: BufRead> Iterator for Paragraphs<R> {
    type Item = io::Result<Paragraph>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut para = Paragraph::default();
        loop {
            self.buf.clear();
            match self.r.read_until(b'\n', &mut self.buf) {
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
                Ok(0) => {
                    self.done = true;
                    return if para.is_empty() { None } else { Some(Ok(para)) };
                }
                Ok(_) => {}
            }
            let line = String::from_utf8_lossy(&self.buf);
            let line = line.trim_end_matches(['\n', '\r']);
            if line.trim().is_empty() {
                if para.is_empty() {
                    continue;
                }
                return Some(Ok(para));
            }
            if line.starts_with('#') {
                continue;
            }
            if line.starts_with([' ', '\t']) {
                if let Some((_, v)) = para.fields.last_mut() {
                    if !v.is_empty() {
                        v.push('\n');
                    }
                    v.push_str(line.trim());
                }
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                para.fields.push((k.trim().to_string(), v.trim().to_string()));
            }
            // Lines without a colon are ignored rather than fatal.
        }
    }
}

pub fn parse_one(text: &str) -> Paragraph {
    Paragraphs::new(text.as_bytes()).next().and_then(|r| r.ok()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic() {
        let t =
            "Package: a\nVersion: 1\nDescription: x\n more\n .\n end\n\n\n# c\nPackage: b\r\nFilename : pool/b.deb\r\n";
        let v: Vec<_> = Paragraphs::new(t.as_bytes()).map(|p| p.unwrap()).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].get("package"), Some("a"));
        assert_eq!(v[0].get("Description"), Some("x\nmore\n.\nend"));
        assert_eq!(v[1].get("Filename"), Some("pool/b.deb"));
    }
}
