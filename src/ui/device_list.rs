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

            let type_tag = d.device_type.tag();

            // Prefer hostname over vendor for the display label
            let truncate = |s: &str| -> String {
                if s.chars().count() > 16 {
                    let end = s.char_indices().nth(15).map(|(i, _)| i).unwrap_or(s.len());
                    format!(" {}…", &s[..end])
                } else {
                    format!(" {s}")
                }
            };
            let display_name = d
                .hostname
                .as_deref()
                .map(truncate)
                .or_else(|| d.vendor.as_deref().map(truncate))
                .unwrap_or_default();

            let line = Line::from(vec![
                Span::styled(bullet, Style::default().fg(bullet_color)),
                Span::raw(format!("{type_tag} ")),
                Span::styled(
                    d.ip.to_string(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(display_name, Style::default().fg(Color::Gray)),
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
