use crate::app::{AppState, DeviceStatus};
use crate::network::port_scanner::port_service;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render_device_details(f: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .title(" Device Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let Some(device) = state.selected_device() else {
        let paragraph = Paragraph::new("No device selected.\n\nUse j/k to navigate the list.")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    };

    let status_str = match device.status {
        DeviceStatus::Active => ("● Active", Color::Green),
        DeviceStatus::Inactive => ("○ Inactive", Color::DarkGray),
    };

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("  IP Address : ", Style::default().fg(Color::Gray)),
            Span::styled(
                device.ip.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  MAC Address: ", Style::default().fg(Color::Gray)),
            Span::styled(device.mac_str.clone(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("  Vendor     : ", Style::default().fg(Color::Gray)),
            Span::styled(
                device.vendor.as_deref().unwrap_or("Unknown"),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Status     : ", Style::default().fg(Color::Gray)),
            Span::styled(status_str.0, Style::default().fg(status_str.1)),
        ]),
        Line::from(vec![
            Span::styled("  Last Seen  : ", Style::default().fg(Color::Gray)),
            Span::styled(
                device.last_seen.format("%H:%M:%S UTC").to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Open Ports",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::UNDERLINED),
        )),
    ];

    if !device.port_scan_done {
        lines.push(Line::from(Span::styled(
            "  Scanning…",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::DIM),
        )));
    } else if device.open_ports.is_empty() {
        lines.push(Line::from(Span::styled(
            "  None detected",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for &port in &device.open_ports {
            let svc = port_service(port);
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{port:5}"),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {svc}"), Style::default().fg(Color::White)),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Keys: j/k=navigate  /=filter  r=rescan  Enter=portscan  q=quit",
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::DIM),
    )));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}
