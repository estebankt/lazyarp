use crate::app::{AppState, DeviceStatus};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

pub fn render_device_list(f: &mut Frame, state: &AppState, area: Rect) {
    let devices = state.visible_devices();

    let title = if state.filter_mode {
        format!(" Devices [/{}] ", state.filter)
    } else if state.filter.is_empty() {
        format!(" Devices ({}) ", devices.len())
    } else {
        format!(" Devices [{}/{}] ", devices.len(), state.filter)
    };

    let items: Vec<ListItem> = devices
        .iter()
        .map(|d| {
            let (bullet, bullet_color) = match d.status {
                DeviceStatus::Active => ("●", Color::Green),
                DeviceStatus::Inactive => ("○", Color::DarkGray),
            };
            let vendor_str = d
                .vendor
                .as_deref()
                .map(|v| {
                    // Truncate long vendor names
                    if v.len() > 16 {
                        format!(" {}…", &v[..15])
                    } else {
                        format!(" {v}")
                    }
                })
                .unwrap_or_default();

            let line = Line::from(vec![
                Span::styled(bullet, Style::default().fg(bullet_color)),
                Span::raw(" "),
                Span::styled(
                    d.ip.to_string(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(vendor_str, Style::default().fg(Color::Gray)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let block = Block::default()
        .title(title.as_str())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut list_state = ListState::default();
    list_state.select(state.selected_index);

    f.render_stateful_widget(list, area, &mut list_state);
}
