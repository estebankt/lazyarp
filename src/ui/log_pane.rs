use crate::app::{AppState, ScanStatus};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render_log_pane(f: &mut Frame, state: &AppState, area: Rect) {
    let scan_indicator = match state.scan_status {
        ScanStatus::Scanning => Span::styled(
            " [SCANNING] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        ScanStatus::Done => Span::styled(" [DONE] ", Style::default().fg(Color::Green)),
        ScanStatus::Idle => Span::styled(" [IDLE] ", Style::default().fg(Color::DarkGray)),
    };

    let title = Line::from(vec![
        Span::raw(" lazyarp "),
        scan_indicator,
        Span::styled(
            format!(" iface: {} ", state.interface_name),
            Style::default().fg(Color::Gray),
        ),
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    // Show the last log entry
    let content = if let Some(entry) = state.logs.last() {
        let ts = entry.timestamp.format("%H:%M:%S").to_string();
        Line::from(vec![
            Span::styled(
                format!("[{ts}] "),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::DIM),
            ),
            Span::styled(entry.message.clone(), Style::default().fg(Color::White)),
        ])
    } else {
        Line::from(Span::styled(
            "Starting…",
            Style::default().fg(Color::DarkGray),
        ))
    };

    let paragraph = Paragraph::new(content).block(block);
    f.render_widget(paragraph, area);
}
