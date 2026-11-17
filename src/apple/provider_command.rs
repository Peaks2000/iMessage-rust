use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};
use zeroize::Zeroizing;

pub(super) fn executable(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .context("Could not find the device helper executable")?;
    let metadata = path.metadata()?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "The device helper must be an executable file"
    );
    Ok(path)
}

pub(super) async fn run(
    helper: &Path,
    arguments: &[&str],
    description: &str,
    input: &[u8],
    maximum: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    timeout(Duration::from_secs(50), async {
        let mut child = Command::new(helper)
            .args(arguments)
            .stdin(if input.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Could not run the device helper for {description}"))?;
        let mut stdout = child
            .stdout
            .take()
            .context("Device helper stdout is unavailable")?
            .take(maximum + 1);
        let mut bytes = Zeroizing::new(Vec::new());
        tokio::try_join!(
            async {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(input).await?;
                    stdin.shutdown().await?;
                }
                Ok::<_, anyhow::Error>(())
            },
            async {
                stdout.read_to_end(&mut bytes).await?;
                ensure!(
                    bytes.len() as u64 <= maximum,
                    "The device helper response is too large"
                );
                Ok::<_, anyhow::Error>(())
            }
        )?;
        ensure!(
            child.wait().await?.success(),
            "The device helper failed during {description}"
        );
        Ok(bytes)
    })
    .await
    .with_context(|| format!("The device helper timed out during {description}"))?
}
