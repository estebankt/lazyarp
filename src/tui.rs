use crate::app::SharedState;
use crate::network::port_scanner::scan_ports;
use crate::ui::app_ui::render;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;

#[derive(Debug)]
pub enum EventAction {
    Continue,
    Quit,
    TriggerPortScan(std::net::Ipv4Addr),
}

pub async fn run(state: SharedState) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, state).await;

    // Always restore terminal, even on error
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: SharedState,
) -> anyhow::Result<()> {
    let mut event_stream = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(16)); // ~60fps

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                terminal.draw(|f| {
                    // Lock briefly only during render
                    if let Ok(s) = state.try_lock() {
                        render(f, &s);
                    }
                })?;
            }
            maybe_event = event_stream.next() => {
                let event = match maybe_event {
                    Some(Ok(e)) => e,
                    _ => continue,
                };
                match handle_event(event, &state).await {
                    EventAction::Quit => break,
                    EventAction::TriggerPortScan(ip) => {
                        let state_clone = std::sync::Arc::clone(&state);
                        tokio::spawn(async move {
                            let open_ports = scan_ports(ip).await;
                            let mut s = state_clone.lock().await;
                            // Find device by IP and update ports
                            for device in s.devices.values_mut() {
                                if device.ip == ip {
                                    device.open_ports = open_ports.clone();
                                    device.port_scan_done = true;
                                    break;
                                }
                            }
                            let port_count = open_ports.len();
                            s.push_log(format!("Port scan {ip}: {port_count} open port(s)"));
                        });
                    }
                    EventAction::Continue => {}
                }
            }
        }
    }

    Ok(())
}

async fn handle_event(event: Event, state: &SharedState) -> EventAction {
    let Event::Key(key) = event else {
        return EventAction::Continue;
    };

    // Ctrl+C always quits
    if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
        return EventAction::Quit;
    }

    let mut s = state.lock().await;

    // If in filter mode, handle text input
    if s.filter_mode {
        match key.code {
            KeyCode::Esc => {
                s.filter_mode = false;
                s.filter.clear();
                s.clamp_selection();
            }
            KeyCode::Enter => {
                s.filter_mode = false;
                s.clamp_selection();
            }
            KeyCode::Backspace => {
                s.filter.pop();
                s.clamp_selection();
            }
            KeyCode::Char(c) => {
                s.filter.push(c);
                s.clamp_selection();
            }
            _ => {}
        }
        return EventAction::Continue;
    }

    // Normal mode keybindings
    match key.code {
        KeyCode::Char('q') => return EventAction::Quit,

        KeyCode::Char('j') | KeyCode::Down => {
            let len = s.visible_devices().len();
            if len > 0 {
                s.selected_index = Some(match s.selected_index {
                    None => 0,
                    Some(i) => (i + 1).min(len - 1),
                });
            }
            // Trigger port scan on newly selected device if not yet done
            if let Some(device) = s.selected_device() {
                if !device.port_scan_done {
                    let ip = device.ip;
                    drop(s);
                    return EventAction::TriggerPortScan(ip);
                }
            }
        }

        KeyCode::Char('k') | KeyCode::Up => {
            let len = s.visible_devices().len();
            if len > 0 {
                s.selected_index = Some(match s.selected_index {
                    None => 0,
                    Some(i) => i.saturating_sub(1),
                });
            }
            if let Some(device) = s.selected_device() {
                if !device.port_scan_done {
                    let ip = device.ip;
                    drop(s);
                    return EventAction::TriggerPortScan(ip);
                }
            }
        }

        KeyCode::Enter => {
            // Force port scan on current device
            if let Some(device) = s.selected_device() {
                if !device.port_scan_done {
                    let ip = device.ip;
                    drop(s);
                    return EventAction::TriggerPortScan(ip);
                }
            }
        }

        KeyCode::Char('/') => {
            s.filter_mode = true;
            s.filter.clear();
        }

        KeyCode::Esc => {
            s.filter.clear();
            s.clamp_selection();
        }

        KeyCode::Char('r') => {
            s.rescan_notify.notify_one();
            s.push_log("Manual rescan triggered".to_string());
        }

        _ => {}
    }

    EventAction::Continue
}
