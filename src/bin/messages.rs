use std::path::PathBuf;

use clap::Parser;
use eframe::egui;

#[path = "messages/apple_setup.rs"]
mod apple_setup;
#[path = "messages/chrome.rs"]
mod chrome;
#[path = "messages/connection.rs"]
mod connection;
#[path = "messages/window.rs"]
mod window;

#[derive(Parser)]
#[command(about = "A Linux desktop client for the experimental iMessage engine")]
struct Args {
    /// Start with sample conversations for this launch
    #[arg(long)]
    demo: bool,
    /// Override the per-user data directory
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    if linux_imessage::apple::run_ssh_askpass()? {
        return Ok(());
    }
    let args = Args::parse();
    let root = linux_imessage::storage::private_dir(
        &args
            .data_dir
            .map_or_else(linux_imessage::storage::data_dir, Ok)?,
    )?;
    linux_imessage::install_tls_provider();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("io.github.Peaks2000.LinuxMessages")
            .with_inner_size([932., 700.])
            .with_decorations(false)
            .with_min_inner_size([700., 480.]),
        ..Default::default()
    };
    eframe::run_native(
        "Messages for Linux",
        options,
        Box::new(move |context| {
            Ok(Box::new(window::MessagesApp::new(
                &context.egui_ctx,
                root,
                args.demo,
            )))
        }),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
}
