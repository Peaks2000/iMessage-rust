use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use serde::{Deserialize, Serialize};
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
    read_private_limited(path, MAX_SECRET_FILE)
}

pub fn read_private_limited(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path).with_context(|| format!("Could not open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.mode() & 0o077 == 0,
        "{} must be a private file (chmod 600)",
        path.display()
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "Private input is too large");
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

#[derive(Deserialize, Serialize)]
pub struct SavedAppleAccount {
    pub account: String,
    pub password: Zeroizing<String>,
    pub contacts: Option<crate::apple::IcloudContactsGrant>,
}

fn apple_account_key(root: &Path, identity: &crate::apple::Identity) -> String {
    format!("apple-account:{}:{}", root.display(), identity.profile_id())
}

pub fn load_apple_account(
    root: &Path,
    identity: &crate::apple::Identity,
) -> Result<Option<SavedAppleAccount>> {
    match entry(&apple_account_key(root, identity))?.get_secret() {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            serde_json::from_slice(&bytes).context("Could not read the remembered Apple Account")
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => {
            Err(error).context("Could not read the Apple Account from Linux Secret Service")
        }
    }
}

pub fn save_apple_account(
    root: &Path,
    identity: &crate::apple::Identity,
    account: &SavedAppleAccount,
) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(account)?);
    entry(&apple_account_key(root, identity))?
        .set_secret(&bytes)
        .context("Could not remember the Apple Account in Linux Secret Service")
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

pub(crate) fn read_activation(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match entry(account)?.get_secret() {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => {
            Err(error).context("Could not read the Apple push identity from Linux Secret Service")
        }
    }
}

pub(crate) fn save_activation(account: &str, bytes: &[u8]) -> Result<()> {
    entry(account)?
        .set_secret(bytes)
        .context("Could not save the Apple push identity to Linux Secret Service")
}

pub fn check_desktop_session_storage(root: &Path) -> Result<()> {
    ensure!(
        !root.join("apple-session.enc").exists(),
        "This data directory uses an encrypted server vault. Connect in Server mode to use it"
    );
    match entry(&format!("apple:{}", root.display()))?.get_secret() {
        Ok(secret) => drop(Zeroizing::new(secret)),
        Err(keyring::Error::NoEntry) => {}
        Err(error) => {
            return Err(error)
                .context("Could not access Linux Secret Service for Apple session storage");
        }
    }
    Ok(())
}

pub fn import_session(root: &Path, source: &Path, key_file: Option<&Path>) -> Result<()> {
    let bytes = read_private(source)?;
    save_session(root, &bytes, key_file)
}

pub fn save_session(root: &Path, bytes: &[u8], key_file: Option<&Path>) -> Result<()> {
    crate::apple::Identity::parse(bytes).context("Invalid Apple session")?;
    let _lock = lock_session_storage(root)?;
    write_session(root, bytes, key_file)
}

/// Add FaceTime to the current desktop session after verifying the existing registration.
pub fn save_facetime_upgrade(
    root: &Path,
    prior: &crate::apple::Identity,
    bytes: &[u8],
) -> Result<()> {
    let upgraded = crate::apple::Identity::parse(bytes).context("Invalid FaceTime session")?;
    ensure!(
        upgraded.facetime_registered() && upgraded.same_messaging_registration(prior)?,
        "FaceTime registration does not match the saved iMessage device"
    );
    let _lock = lock_session_storage(root)?;
    let saved = load_local_session(root)?
        .context("The saved iMessage session was removed during FaceTime setup")?;
    ensure!(
        saved.same_messaging_registration(prior)?,
        "The saved Apple session changed during FaceTime setup"
    );
    if saved.same_facetime_registration(&upgraded) {
        return Ok(());
    }
    ensure!(
        saved.same_facetime_registration(prior),
        "The saved FaceTime registration changed during setup"
    );
    write_session(root, bytes, None)
}

fn lock_session_storage(root: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .mode(0o600)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("session-storage.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).context("Apple session storage is busy")?;
    Ok(lock)
}

fn write_session(root: &Path, bytes: &[u8], key_file: Option<&Path>) -> Result<()> {
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

/// Load a registered desktop session. A clean installation has no keyring entry.
pub fn load_local_session(root: &Path) -> Result<Option<crate::apple::Identity>> {
    ensure!(
        !root.join("apple-session.enc").exists(),
        "Supply the vault key file for this data directory"
    );
    match entry(&format!("apple:{}", root.display()))?.get_secret() {
        Ok(secret) => Ok(Some(crate::apple::Identity::parse(&Zeroizing::new(
            secret,
        ))?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => {
            Err(error).context("Could not read the Apple session from Linux Secret Service")
        }
    }
}

pub fn load_session(root: &Path, key_file: Option<&Path>) -> Result<crate::apple::Identity> {
    let Some(path) = key_file else {
        return load_local_session(root)?
            .context("There is no registered iMessage session on this computer");
    };
    let vault = root.join("apple-session.enc");
    let key = read_private(path)?;
    ensure!(key.len() == 32, "The vault key must be 32 raw bytes");
    let blob = read_private(&vault)?;
    ensure!(
        blob.len() > 32 && blob.starts_with(b"LIM1"),
        "Unrecognized vault format"
    );
    let secret = Zeroizing::new(
        decrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(&blob[4..16]),
            VAULT_CONTEXT,
            &blob[32..],
            &blob[16..32],
        )
        .context("Could not authenticate the encrypted Apple session")?,
    );
    crate::apple::Identity::parse(&secret)
}
