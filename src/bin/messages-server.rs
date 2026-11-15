use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::{Parser, Subcommand};
use linux_imessage::{
    api::{self, AccessPolicy},
    apple::{SmsPrompts, TrustedPhone, login_device_sms},
    engine::Engine,
    install_tls_provider, storage,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Serve the Linux Messages engine or provision its credentials")]
struct Args {
    /// Override the per-user data directory
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Store an already provisioned Apple device session
    ImportSession {
        #[arg(value_name = "PRIVATE_PLIST")]
        session: PathBuf,
        /// Use a separate 32-byte encryption key file instead of Secret Service
        #[arg(long)]
        vault_key_file: Option<PathBuf>,
    },
    /// Request a legacy IDS certificate using existing Apple authentication and validation material
    RegisterSession {
        #[arg(value_name = "PRIVATE_REGISTRATION_PLIST")]
        registration: PathBuf,
        /// Use a separate 32-byte encryption key file instead of Secret Service
        #[arg(long)]
        vault_key_file: Option<PathBuf>,
    },
    /// Sign in to Apple with SMS verification and register the supplied device
    Login {
        #[arg(value_name = "PRIVATE_DEVICE_PLIST")]
        device: PathBuf,
        /// Executable that supplies fresh Anisette headers as JSON
        #[arg(long)]
        anisette_helper: PathBuf,
        /// Use a separate 32-byte encryption key file instead of Secret Service
        #[arg(long)]
        vault_key_file: Option<PathBuf>,
    },
    /// Create or replace the server's single username and password
    SetPassword {
        #[arg(long)]
        username: String,
    },
    /// Run the HTTP API
    Serve {
        #[arg(long, default_value = "127.0.0.1:7848")]
        bind: SocketAddr,
        /// Use sample conversations and local-only text messages
        #[arg(long)]
        demo: bool,
        /// Use the password saved by set-password
        #[arg(long)]
        require_login: bool,
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        #[arg(long, conflicts_with = "demo")]
        vault_key_file: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = storage::private_dir(&args.data_dir.map_or_else(storage::data_dir, Ok)?)?;
    match args.command {
        Command::ImportSession {
            session,
            vault_key_file,
        } => {
            storage::import_session(&root, &session, vault_key_file.as_deref())?;
            println!("Apple device session stored");
            Ok(())
        }
        Command::RegisterSession {
            registration,
            vault_key_file,
        } => {
            let input = storage::read_private(&registration)?;
            install_tls_provider();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let session = runtime.block_on(linux_imessage::apple::register_device(&input))?;
            storage::save_session(&root, &session, vault_key_file.as_deref())?;
            println!("Apple IDS registration stored");
            Ok(())
        }
        Command::Login {
            device,
            anisette_helper,
            vault_key_file,
        } => {
            let input = storage::read_private(&device)?;
            if let Some(path) = &vault_key_file {
                ensure!(
                    storage::read_private(path)?.len() == 32,
                    "The vault key must be 32 raw bytes"
                );
            }
            let account = Zeroizing::new(rpassword::prompt_password(
                "Apple Account email or phone: ",
            )?);
            let password = Zeroizing::new(rpassword::prompt_password("Apple Account password: ")?);
            install_tls_provider();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let session = runtime.block_on(login_device_sms(
                &input,
                &anisette_helper,
                &account,
                password,
                &mut TerminalSms,
            ))?;
            storage::save_session(&root, &session, vault_key_file.as_deref())?;
            println!("Apple Account signed in and iMessage device session stored");
            Ok(())
        }
        Command::SetPassword { username } => {
            api::validate_username(&username)?;
            let password = Zeroizing::new(rpassword::prompt_password("Server password: ")?);
            let confirmed = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
            ensure!(*password == *confirmed, "The passwords do not match");
            api::save_account(&root.join("server-account.json"), &username, &password)?;
            println!("Saved server login for {username}");
            Ok(())
        }
        Command::Serve {
            bind,
            demo,
            require_login,
            tls_cert,
            tls_key,
            vault_key_file,
        } => {
            let tls = tls_cert.as_deref().zip(tls_key.as_deref());
            ensure!(
                bind.ip().is_loopback() || (require_login && tls.is_some()),
                "A network listener requires --require-login, --tls-cert, and --tls-key"
            );
            let access = if require_login {
                AccessPolicy::from_file(&root.join("server-account.json"))
                    .context("Could not load the server account. Run set-password first")?
            } else {
                AccessPolicy::loopback()
            };
            let identity = if demo {
                None
            } else {
                Some(storage::load_session(&root, vault_key_file.as_deref())?)
            };
            install_tls_provider();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let engine = Engine::start(&root, identity)?;
                serve(bind, tls, api::router(engine, access)).await
            })
        }
    }
}

struct TerminalSms;

impl SmsPrompts for TerminalSms {
    fn choose_phone(&mut self, phones: &[TrustedPhone]) -> Result<usize> {
        for (index, phone) in phones.iter().enumerate() {
            println!("{}  ••••{}", index + 1, phone.last_two_digits);
        }
        loop {
            let answer =
                rpassword::prompt_password("Choose a trusted number or press Enter to cancel: ")?;
            ensure!(!answer.trim().is_empty(), "Apple sign-in canceled");
            if let Some(index) = answer
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|number| number.checked_sub(1))
                && index < phones.len()
            {
                return Ok(index);
            }
            println!("Enter one of the listed choices");
        }
    }

    fn read_code(&mut self) -> Result<Zeroizing<String>> {
        loop {
            let code = Zeroizing::new(rpassword::prompt_password(
                "Apple SMS code (press Enter to cancel): ",
            )?);
            let trimmed = code.trim();
            ensure!(!trimmed.is_empty(), "Apple sign-in canceled");
            if trimmed.len() == 6 && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
                return Ok(code);
            }
            println!("Enter the six digits from Apple's text message");
        }
    }
}

async fn serve(bind: SocketAddr, tls: Option<(&Path, &Path)>, app: axum::Router) -> Result<()> {
    let listener =
        std::net::TcpListener::bind(bind).with_context(|| format!("Could not bind {bind}"))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let handle = Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.graceful_shutdown(Some(Duration::from_secs(5)));
        }
    });
    if let Some((cert, key)) = tls {
        let tls_config = RustlsConfig::from_pem_file(cert, key)
            .await
            .context("Could not load the server TLS certificate and key")?;
        println!("Listening on https://{address}");
        axum_server::from_tcp_rustls(listener, tls_config)?
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        println!("Listening on http://{address}");
        axum_server::from_tcp(listener)?
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    }
    Ok(())
}
