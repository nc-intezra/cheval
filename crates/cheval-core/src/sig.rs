//! OpenPGP verification of Release files (pure Rust, no gpg/gpgv needed).
use anyhow::{Context, Result, anyhow, bail};
use pgp::composed::{CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey};
use pgp::packet::Signature;
use pgp::types::KeyDetails;
use std::io::Cursor;
use std::path::Path;

pub struct Keyring {
    keys: Vec<SignedPublicKey>,
}

const KEY_HEADER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

fn parse_keys(data: &[u8], out: &mut Vec<SignedPublicKey>) -> Result<()> {
    let is_armored = data.windows(KEY_HEADER.len()).take(4096).any(|w| w == KEY_HEADER.as_bytes());
    if is_armored {
        let text = String::from_utf8_lossy(data);
        // A file may hold several concatenated armor blocks.
        for block in text.split(KEY_HEADER).skip(1) {
            let block = format!("{KEY_HEADER}{block}");
            let (iter, _) = SignedPublicKey::from_armor_many(Cursor::new(block.into_bytes()))
                .map_err(|e| anyhow!("armored key: {e}"))?;
            for k in iter {
                out.push(k.map_err(|e| anyhow!("armored key: {e}"))?);
            }
        }
    } else {
        for k in
            SignedPublicKey::from_bytes_many(Cursor::new(data.to_vec())).map_err(|e| anyhow!("binary keyring: {e}"))?
        {
            out.push(k.map_err(|e| anyhow!("binary keyring: {e}"))?);
        }
    }
    Ok(())
}

impl Keyring {
    /// Load a keyring from a file (binary or armored) or every key file in a directory.
    pub fn load(path: &Path) -> Result<Keyring> {
        let mut keys = Vec::new();
        if path.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(path)?.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| e.file_name());
            for e in entries {
                let p = e.path();
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
                if p.is_file() && matches!(ext, "gpg" | "asc" | "pgp" | "key" | "pub") {
                    let data = std::fs::read(&p)?;
                    parse_keys(&data, &mut keys).with_context(|| format!("keyring {}", p.display()))?;
                }
            }
        } else {
            let data = std::fs::read(path).with_context(|| format!("keyring {}", path.display()))?;
            parse_keys(&data, &mut keys).with_context(|| format!("keyring {}", path.display()))?;
        }
        if keys.is_empty() {
            bail!("keyring {} contains no public keys", path.display());
        }
        Ok(Keyring { keys })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Keyring> {
        let mut keys = Vec::new();
        parse_keys(data, &mut keys)?;
        if keys.is_empty() {
            bail!("no public keys found");
        }
        Ok(Keyring { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn fingerprints(&self) -> Vec<String> {
        self.keys.iter().map(|k| hex::encode_upper(k.fingerprint().as_bytes())).collect()
    }

    /// Returns the fingerprint of the certificate whose (sub)key made the signature.
    fn check(&self, sig: &Signature, data: &[u8]) -> Option<String> {
        for key in &self.keys {
            let fp = hex::encode_upper(key.fingerprint().as_bytes());
            if sig.verify(&key.primary_key, data).is_ok() {
                return Some(fp);
            }
            for sub in &key.public_subkeys {
                if sig.verify(sub, data).is_ok() {
                    return Some(fp);
                }
            }
        }
        None
    }

    /// Verify an InRelease file. Returns the signed body (LF line endings) and the
    /// fingerprint of the signing certificate. Only the returned body may be trusted.
    pub fn verify_cleartext(&self, text: &str) -> Result<(String, String)> {
        let (msg, _) =
            CleartextSignedMessage::from_string(text).map_err(|e| anyhow!("not a valid clear-signed file: {e}"))?;
        let signed = msg.signed_text();
        for sig in msg.signatures() {
            if let Some(fp) = self.check(sig, signed.as_bytes()) {
                return Ok((signed.replace("\r\n", "\n"), fp));
            }
        }
        bail!(
            "no signature matches the configured keyring ({} signature(s), {} key(s))",
            msg.signatures().len(),
            self.keys.len()
        )
    }

    /// Verify a detached signature (Release.gpg) over `data` (Release).
    pub fn verify_detached(&self, sig: &[u8], data: &[u8]) -> Result<String> {
        let armored = sig.starts_with(b"-----BEGIN");
        let sigs: Vec<DetachedSignature> = if armored {
            let (iter, _) = DetachedSignature::from_armor_many(Cursor::new(sig.to_vec()))
                .map_err(|e| anyhow!("bad detached signature: {e}"))?;
            iter.filter_map(|s| s.ok()).collect()
        } else {
            DetachedSignature::from_bytes_many(Cursor::new(sig.to_vec()))
                .map_err(|e| anyhow!("bad detached signature: {e}"))?
                .filter_map(|s| s.ok())
                .collect()
        };
        if sigs.is_empty() {
            bail!("Release.gpg contains no signatures");
        }
        for s in &sigs {
            if let Some(fp) = self.check(&s.signature, data) {
                return Ok(fp);
            }
        }
        bail!("no signature matches the configured keyring ({} signature(s))", sigs.len())
    }
}

/// Extract the body of a clear-signed file WITHOUT verifying it.
/// Plain (unsigned) input is returned unchanged.
pub fn strip_cleartext(text: &str) -> String {
    const BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
    const SIG: &str = "-----BEGIN PGP SIGNATURE-----";
    let Some(start) = text.find(BEGIN) else {
        return text.to_string();
    };
    let mut out = String::new();
    let mut in_headers = true;
    for line in text[start + BEGIN.len()..].lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
            }
            continue;
        }
        if line.starts_with(SIG) {
            break;
        }
        out.push_str(line.strip_prefix("- ").unwrap_or(line));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strip() {
        let t = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: X\n- -dash\n-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n";
        assert_eq!(strip_cleartext(t), "Origin: X\n-dash\n");
        assert_eq!(strip_cleartext("Origin: Y\n"), "Origin: Y\n");
    }
}
