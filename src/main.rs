mod app;
mod error;
mod network;
mod oui;
mod tui;
mod ui;

use app::AppState;
use error::LazyarpError;
use network::interface::{check_permissions, select_interface};
use network::scanner::run_scanner;
use pnet_datalink;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\nError: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), anyhow::Error> {
    // 1. Select the best network interface
    let selected = match select_interface() {
        Ok(iface) => iface,
        Err(LazyarpError::NoSuitableInterface) => {
            eprintln!("{}", LazyarpError::NoSuitableInterface);
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    };

    // 2. Check that we have permission to open a raw socket
    let interfaces = pnet_datalink::interfaces();
    let net_iface = interfaces
        .into_iter()
        .find(|i| i.name == selected.name)
        .expect("Interface disappeared between selection and check");

    if let Err(e) = check_permissions(&net_iface) {
        eprintln!("{e}");
        std::process::exit(1);
    }

    // 3. Build shared state
    let rescan_notify = Arc::new(Notify::new());
    let state = Arc::new(Mutex::new(AppState::new(
        selected.name.clone(),
        Arc::clone(&rescan_notify),
    )));

    // 4. Spawn the ARP scanner (runs forever in background)
    let scanner_state = Arc::clone(&state);
    let scanner_iface = selected.clone();
    tokio::spawn(async move {
        run_scanner(scanner_iface, scanner_state).await;
    });

    // 5. Run the TUI (blocks until user quits)
    tui::run(state).await?;

    Ok(())
}
