use std::{
    fs::{self, DirBuilder, File},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use zeroize::Zeroizing;

const SERVICE: &str = "io.github.Peaks2000.LinuxMessages";
const VAULT_CONTEXT: &[u8] = b"linux-imessage Apple session v1";
const MAX_SECRET_FILE: u64 = 128 * 1024;

pub fn data_dir() -> Result<PathBuf> {
    Ok(
        directories::ProjectDirs::from("io.github", "Peaks2000", "LinuxMessages")
            .context("Could not find the Linux user directories")?
            .data_dir()
            .to_owned(),
    )
}

pub fn private_dir(path: &Path) -> Result<PathBuf> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .with_context(|| format!("Could not create {}", path.display()))?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.mode() & 0o077 == 0,
        "{} must be a private directory (chmod 700)",
        path.display()
    );
    Ok(path.canonicalize()?)
}

pub fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path).with_context(|| format!("Could not open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.mode() & 0o077 == 0,
        "{} must be a private file (chmod 600)",
        path.display()
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_SECRET_FILE + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_SECRET_FILE,
        "Private input is too large"
    );
    Ok(bytes)
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, account).context("Could not access Linux Secret Service")
}

pub fn read_password(account: &str) -> Result<Zeroizing<String>> {
    entry(account)?
        .get_password()
        .map(Zeroizing::new)
        .context("Could not read the password from Linux Secret Service")
}

pub fn save_password(account: &str, secret: &str) -> Result<()> {
    entry(account)?
        .set_password(secret)
        .context("Could not save the password to Linux Secret Service")
}

pub fn forget_secret(account: &str) -> Result<()> {
    match entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error).context("Could not remove the entry from Linux Secret Service"),
    }
}

pub fn import_session(root: &Path, source: &Path, key_file: Option<&Path>) -> Result<()> {
    let bytes = read_private(source)?;
    save_session(root, &bytes, key_file)
}

pub fn save_session(root: &Path, bytes: &[u8], key_file: Option<&Path>) -> Result<()> {
    crate::apple::Identity::parse(bytes).context("Invalid Apple session")?;
    let vault = root.join("apple-session.enc");
    match key_file {
        Some(path) => {
            let key = read_private(path)?;
            ensure!(key.len() == 32, "The vault key must be 32 raw bytes");
            let mut nonce = [0; 12];
            let mut tag = [0; 16];
            rand_bytes(&mut nonce)?;
            let encrypted = encrypt_aead(
                Cipher::aes_256_gcm(),
                &key,
                Some(&nonce),
                VAULT_CONTEXT,
                bytes,
                &mut tag,
            )?;
            let blob = [b"LIM1".as_slice(), &nonce, &tag, &encrypted].concat();
            write_private(&vault, &blob)
        }
        None => {
            ensure!(
                !vault.exists(),
                "This data directory already uses an encrypted file vault"
            );
            entry(&format!("apple:{}", root.display()))?
                .set_secret(bytes)
                .context("Could not save the session to Linux Secret Service")
        }
    }
}

pub fn load_session(root: &Path, key_file: Option<&Path>) -> Result<crate::apple::Identity> {
    let vault = root.join("apple-session.enc");
    let secret = match key_file {
        Some(path) => {
            let key = read_private(path)?;
            ensure!(key.len() == 32, "The vault key must be 32 raw bytes");
            let blob = read_private(&vault)?;
            ensure!(
                blob.len() > 32 && blob.starts_with(b"LIM1"),
                "Unrecognized vault format"
            );
            Zeroizing::new(
                decrypt_aead(
                    Cipher::aes_256_gcm(),
                    &key,
                    Some(&blob[4..16]),
                    VAULT_CONTEXT,
                    &blob[32..],
                    &blob[16..32],
                )
                .context("Could not authenticate the encrypted Apple session")?,
            )
        }
        None => {
            ensure!(
                !vault.exists(),
                "Supply the vault key file for this data directory"
            );
            Zeroizing::new(entry(&format!("apple:{}", root.display()))?.get_secret()
                .context("No Apple session could be read. Run messages-server import-session or use the demo")?)
        }
    };
    crate::apple::Identity::parse(&secret)
}
