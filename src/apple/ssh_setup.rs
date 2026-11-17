use std::{
    io::{Read, Write},
    os::unix::net::UnixStream as BlockingStream,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::{Child, Command},
    time::{interval, timeout},
};
use zeroize::Zeroizing;

use super::{SmsPrompts, provider_command};

const SSH: &str = "/usr/bin/ssh";
const ASKPASS_SOCKET: &str = "IMESSAGE_SSH_ASKPASS_SOCKET";
const MAX_PROMPT: u64 = 8 * 1024;
const MAX_RESPONSE: u64 = 1023;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(180);
const HELPER: &[u8] = include_bytes!("../../tools/macos-device-helper");
const INSTALL_HELPER: &str = r#"
    if [ "$(/usr/bin/uname -s)" != Darwin ]; then
        /bin/cat >/dev/null
        printf 'not-macos'
        exit
    fi
    umask 077
    dir="$HOME/.local/bin"
    /bin/mkdir -p "$dir" || exit 1
    target="$dir/imessage-mac-device"
    if [ -d "$target" ]; then exit 1; fi
    work=$(/usr/bin/mktemp "$dir/.imessage-device.XXXXXXXX") || exit 1
    trap '/bin/rm -f -- "$work"' EXIT
    /bin/cat > "$work" || exit 1
    /bin/chmod 700 "$work" || exit 1
    /bin/mv -f "$work" "$target" || exit 1
    printf 'installed'
"#;

pub enum SshPrompt {
    VerifyHost { host: String, fingerprint: String },
    Login { host: String, message: String },
}

pub(super) struct MacConnection {
    host: String,
    control: PathBuf,
    _master: Child,
    _directory: tempfile::TempDir,
}

impl MacConnection {
    pub(super) async fn open(
        root: &Path,
        host: &str,
        prompts: &mut impl SmsPrompts,
    ) -> Result<Self> {
        let host = checked_host(host)?.to_owned();
        let known_hosts = root.join("ssh-known-hosts");
        let known_hosts = known_hosts
            .to_str()
            .context("SSH requires a UTF-8 app data path")?;
        ensure!(
            !known_hosts.contains(['\0', '\n', '\r']),
            "Invalid SSH known-hosts path"
        );
        let known_hosts = known_hosts
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%");
        let known_hosts =
            format!("UserKnownHostsFile=\"{known_hosts}\" ~/.ssh/known_hosts ~/.ssh/known_hosts2");
        let directory = tempfile::Builder::new()
            .prefix("imessage-ssh-")
            .tempdir_in("/tmp")?;
        let control = directory.path().join("control");
        let socket = directory.path().join("askpass");
        let listener = UnixListener::bind(&socket)?;
        let mut command = Command::new(SSH);
        if prompts.prefers_ssh_password() {
            command.arg("-oPreferredAuthentications=password,keyboard-interactive,publickey");
        }
        let mut master = command
            .args(["-N", "-T", "-M", "-S"])
            .arg(&control)
            .arg("-o")
            .arg(known_hosts)
            .args([
                "-oBatchMode=no",
                "-oPasswordAuthentication=yes",
                "-oKbdInteractiveAuthentication=yes",
                "-oStrictHostKeyChecking=ask",
                "-oFingerprintHash=sha256",
                "-oConnectTimeout=10",
                "-oControlPersist=no",
                "-oForkAfterAuthentication=no",
                "-oClearAllForwardings=yes",
                "-oForwardAgent=no",
                "-oForwardX11=no",
                "-oPermitLocalCommand=no",
                "--",
                &host,
            ])
            .env("SSH_ASKPASS", std::env::current_exe()?)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env(ASKPASS_SOCKET, socket)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Could not start OpenSSH for Mac setup")?;
        let mut stderr = master
            .stderr
            .take()
            .context("OpenSSH stderr is unavailable")?
            .take(8192);
        let errors = tokio::spawn(async move {
            let mut output = Vec::new();
            let _ = stderr.read_to_end(&mut output).await;
            output
        });
        timeout(CONNECT_TIMEOUT, async {
            let mut poll = interval(Duration::from_millis(80));
            loop {
                tokio::select! {
                    status = master.wait() => {
                        status?;
                        let error = errors.await.unwrap_or_default();
                        if String::from_utf8_lossy(&error).contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
                            bail!("The Mac's SSH fingerprint changed. Verify the Mac before updating its trusted SSH key");
                        }
                        bail!("Could not sign in to the Mac. Check Remote Login, the Mac address and the Mac login credentials");
                    }
                    incoming = listener.accept() => {
                        let (stream, _) = incoming?;
                        answer_askpass(stream, &host, prompts).await?;
                    }
                    _ = poll.tick() => {
                        if control.try_exists()? {
                            return Ok(());
                        }
                    }
                }
            }
        }).await.context("Mac SSH sign-in timed out")??;
        Ok(Self {
            host,
            control,
            _master: master,
            _directory: directory,
        })
    }

    pub(super) async fn install_helper(&self) -> Result<()> {
        let script = INSTALL_HELPER.replace('\'', "'\"'\"'");
        let command = format!("/bin/sh -c '{script}'");
        let result = self
            .command(&command, "Mac helper installation", HELPER, 128)
            .await?;
        match result.as_slice() {
            b"installed" => Ok(()),
            b"not-macos" => bail!("The SSH address did not connect to a Mac"),
            _ => bail!("The Mac did not confirm installation of the iMessage helper"),
        }
    }

    pub(super) async fn run(
        &self,
        operation: &str,
        input: &[u8],
        maximum: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let remote = format!("~/.local/bin/imessage-mac-device {operation}");
        self.command(&remote, operation, input, maximum)
            .await
            .with_context(|| format!("The Mac could not complete the {operation} step"))
    }

    async fn command(
        &self,
        remote: &str,
        description: &str,
        input: &[u8],
        maximum: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let socket = self
            .control
            .to_str()
            .context("Invalid SSH control socket path")?;
        provider_command::run(
            Path::new(SSH),
            &[
                "-T",
                "-S",
                socket,
                "-oControlMaster=no",
                "-oBatchMode=yes",
                "-oProxyCommand=/usr/bin/false",
                "-oForwardAgent=no",
                "-oForwardX11=no",
                "--",
                &self.host,
                remote,
            ],
            description,
            input,
            maximum,
        )
        .await
    }
}

fn checked_host(host: &str) -> Result<&str> {
    let host = host.trim();
    let plain = host.strip_prefix("ssh://").unwrap_or(host);
    ensure!(
        (1..=320).contains(&plain.len())
            && !plain.starts_with('-')
            && plain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._@:-[]".contains(&byte)),
        "Enter a Mac address such as user@mac.local",
    );
    if host.starts_with("ssh://") {
        let url = url::Url::parse(host).context("Invalid Mac SSH address")?;
        ensure!(
            url.host().is_some() && url.password().is_none(),
            "Enter the Mac password when the app prompts"
        );
    }
    Ok(host)
}

async fn answer_askpass(
    stream: UnixStream,
    host: &str,
    prompts: &mut impl SmsPrompts,
) -> Result<()> {
    let mut stream = stream.take(MAX_PROMPT + 1);
    let mut message = String::new();
    timeout(Duration::from_secs(3), stream.read_to_string(&mut message)).await??;
    ensure!(
        message.len() as u64 <= MAX_PROMPT,
        "OpenSSH sent an oversized prompt"
    );
    message.retain(|c| !c.is_control() || c == '\n');
    let interaction = if message.contains("Are you sure you want to continue connecting") {
        let fingerprint = message
            .split_whitespace()
            .find(|word| word.starts_with("SHA256:"))
            .map(|word| word.trim_end_matches('.'))
            .context("OpenSSH did not provide the Mac's fingerprint")?;
        SshPrompt::VerifyHost {
            host: host.to_owned(),
            fingerprint: fingerprint.to_owned(),
        }
    } else {
        SshPrompt::Login {
            host: host.to_owned(),
            message,
        }
    };
    let answer = prompts.ssh_prompt(interaction).await?;
    ensure!(
        valid_answer(&answer),
        "Enter a single-line SSH password or response"
    );
    stream.into_inner().write_all(answer.as_bytes()).await?;
    Ok(())
}

fn valid_answer(answer: &str) -> bool {
    (1..=MAX_RESPONSE as usize).contains(&answer.len()) && !answer.contains(['\0', '\r', '\n'])
}

/// Run the same desktop executable as OpenSSH's askpass helper over a private socket.
/// The SSH password travels over the private socket and OpenSSH askpass pipe.
pub fn run_ssh_askpass() -> Result<bool> {
    let Some(path) = std::env::var_os(ASKPASS_SOCKET) else {
        return Ok(false);
    };
    let prompt = std::env::args_os().nth(1).context("No OpenSSH prompt")?;
    let prompt = prompt.to_string_lossy();
    ensure!(prompt.len() as u64 <= MAX_PROMPT, "Invalid OpenSSH prompt");
    let mut stream = BlockingStream::connect(path)?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.write_all(prompt.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut answer = Zeroizing::new(String::new());
    stream.take(MAX_RESPONSE + 1).read_to_string(&mut answer)?;
    ensure!(valid_answer(&answer), "OpenSSH prompt was canceled");
    let mut output = std::io::stdout().lock();
    output.write_all(answer.as_bytes())?;
    output.write_all(b"\n")?;
    Ok(true)
}
