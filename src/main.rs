mod app;
mod error;
mod network;
mod oui;
mod tui;
mod ui;

use app::AppState;
use error::LazyarpError;
use network::interface::{check_permissions, select_interface};
use network::scanner::{run_scanner, ScanMode};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

#[tokio::main]
async fn main() {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("lazyarp {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

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

    // 2. Detect scan mode: Active if we can open a raw socket, Passive otherwise
    let interfaces = pnet_datalink::interfaces();
    let net_iface = interfaces
        .into_iter()
        .find(|i| i.name == selected.name)
        .expect("Interface disappeared between selection and check");

    let mode = match check_permissions(&net_iface) {
        Ok(_) => ScanMode::Active,
        Err(LazyarpError::InsufficientPermissions) => ScanMode::Passive,
        Err(e) => return Err(e.into()),
    };

    let passive = matches!(mode, ScanMode::Passive);

    // 3. Build shared state
    let rescan_notify = Arc::new(Notify::new());
    let state = Arc::new(Mutex::new(AppState::new(
        selected.name.clone(),
        Arc::clone(&rescan_notify),
        passive,
    )));

    // 4. Spawn the ARP scanner (runs forever in background)
    let scanner_state = Arc::clone(&state);
    let scanner_iface = selected.clone();
    tokio::spawn(async move {
        run_scanner(scanner_iface, scanner_state, mode).await;
    });

    // 5. Spawn the mDNS passive listener
    let mdns_state = Arc::clone(&state);
    let iface_ip = selected.ip;
    tokio::spawn(async move {
        network::mdns::run_mdns_listener(mdns_state, iface_ip).await;
    });

    // 6. Spawn the SSDP/UPnP listener
    let ssdp_state = Arc::clone(&state);
    tokio::spawn(async move {
        network::ssdp::run_ssdp_listener(ssdp_state).await;
    });

    // 7. Run the TUI (blocks until user quits)
    tui::run(state).await?;

    Ok(())
}
