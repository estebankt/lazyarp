use crate::app::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    Frame,
};

use super::{
    device_details::render_device_details, device_list::render_device_list,
    log_pane::render_log_pane,
};

pub fn render(f: &mut Frame, state: &AppState) {
    let size = f.area();

    // Outer layout: main area (top) + log pane (bottom, 3 lines)
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(size);

    let main_area = outer[0];
    let log_area = outer[1];

    // Inner layout: device list (35%) | device details (65%)
    let inner = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(main_area);

    let list_area = inner[0];
    let details_area = inner[1];

    render_device_list(f, state, list_area);
    render_device_details(f, state, details_area);
    render_log_pane(f, state, log_area);
}
