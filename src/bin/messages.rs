use std::path::PathBuf;

use clap::Parser;
use eframe::egui;

#[path = "messages/attachments.rs"]
mod attachments;
#[path = "messages/carddav.rs"]
mod carddav;
#[path = "messages/chrome.rs"]
mod chrome;
#[path = "messages/clipboard.rs"]
mod clipboard;
#[path = "messages/connection.rs"]
mod connection;
#[path = "messages/contacts.rs"]
mod contacts;
#[path = "messages/links.rs"]
mod links;
#[path = "messages/mac_setup.rs"]
mod mac_setup;
#[path = "messages/session_import.rs"]
mod session_import;
#[path = "messages/window.rs"]
mod window;

#[derive(Parser)]
#[command(about = "A Linux desktop client for the experimental iMessage engine")]
struct Args {
    /// Open the optional Mac-assisted setup
    #[arg(long)]
    mac_setup: bool,
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
            .with_transparent(true)
            .with_min_inner_size([700., 480.]),
        ..Default::default()
    };
    clipboard::run("Messages for Linux", options, move |context, clipboard| {
        Box::new(window::MessagesApp::new(
            &context.egui_ctx,
            root,
            args.mac_setup,
            clipboard,
        ))
    })
}
