use std::path::Path;
use std::time::{Duration, Instant};

use openshield_core::{
    CounterValue, Direction, Event, EventKind, Mode, Rule, RuleOrigin, TransportProtocol,
};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState, Tabs, Wrap,
    },
};

use crate::app::{
    App, CommandMode, ConnectionState, FormField, Overlay, RuleForm, View, peer_label,
};
use crate::i18n::I18n;

const MAX_SINGLE_LINE_CHARS: usize = 1_024;
const MAX_MESSAGE_CHARS: usize = 4_096;
const COUNTERS_STALE_AFTER: Duration = Duration::from_secs(3);

pub fn draw(frame: &mut Frame<'_>, app: &App, observe_path: &Path, control_path: &Path) {
    let areas = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(frame.area());

    draw_tabs(frame, app, areas[0]);
    match app.view {
        View::Status => draw_status(frame, app, observe_path, control_path, areas[1]),
        View::Rules => draw_rules(frame, app, areas[1]),
        View::Events => draw_events(frame, app, areas[1]),
        View::Help => draw_help(frame, app, areas[1]),
    }
    draw_footer(frame, app, areas[2]);
    draw_overlay(frame, app);
}

fn draw_tabs(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let titles = [View::Status, View::Rules, View::Events, View::Help]
        .into_iter()
        .map(|view| Line::from(view.title(&app.i18n)))
        .collect::<Vec<_>>();
    let selected = match app.view {
        View::Status => 0,
        View::Rules => 1,
        View::Events => 2,
        View::Help => 3,
    };
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(Block::default().borders(Borders::ALL).title(" OpenShield "))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider(" | ");
    frame.render_widget(tabs, area);
}

#[allow(clippy::too_many_lines)]
fn draw_status(
    frame: &mut Frame<'_>,
    app: &App,
    observe_path: &Path,
    control_path: &Path,
    area: Rect,
) {
    let i18n = &app.i18n;
    let now = Instant::now();
    let counters_age = app.counters_age(now);
    let connection = policy_health_span(&app.connection, i18n);
    let telemetry = telemetry_health_span(app, now, counters_age, i18n);
    let access = access_span(app.read_only, i18n);
    let (mode, revision, rule_count, inbound_count) = app.snapshot.as_ref().map_or_else(
        || (i18n.tr("common.unknown").to_owned(), 0, 0, 0),
        |snapshot| {
            (
                mode_label(snapshot.mode, i18n).to_owned(),
                snapshot.revision,
                snapshot.rules.len(),
                snapshot
                    .rules
                    .iter()
                    .filter(|rule| rule.spec.enabled && rule.spec.direction == Direction::Inbound)
                    .count(),
            )
        },
    );
    let mode_style = app
        .snapshot
        .as_ref()
        .map_or_else(Style::default, |snapshot| mode_style(snapshot.mode));
    let revision = revision.to_string();
    let rule_count = rule_count.to_string();
    let inbound_count = inbound_count.to_string();
    let mut lines = vec![
        Line::from(vec![Span::raw(i18n.tr("status.policy")), connection]),
        Line::from(vec![Span::raw(i18n.tr("status.telemetry")), telemetry]),
        Line::from(vec![Span::raw(i18n.tr("status.access")), access]),
        Line::from(vec![
            Span::raw(i18n.tr("status.mode")),
            Span::styled(mode, mode_style.add_modifier(Modifier::BOLD)),
        ]),
        Line::from(i18n.format("status.revision", &[("revision", revision.as_str())])),
        Line::from(i18n.format(
            "status.rule_counts",
            &[
                ("rules", rule_count.as_str()),
                ("inbound", inbound_count.as_str()),
            ],
        )),
        Line::from(""),
        Line::from(Span::styled(
            i18n.tr("status.inbound_policy"),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
    ];
    if let Some(counters) = &app.counters {
        let age = counters_age.map_or_else(
            || i18n.tr("status.age_unknown").to_owned(),
            |age| {
                let duration = duration_label(age, i18n);
                i18n.format("status.age", &[("duration", duration.as_str())])
            },
        );
        lines.extend([
            Line::from(Span::styled(
                i18n.format("status.counters_title", &[("age", age.as_str())]),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            counter_line(i18n.tr("status.counter_accepted_in"), counters.accepted_in),
            counter_line(
                i18n.tr("status.counter_accepted_out"),
                counters.accepted_out,
            ),
            counter_line(i18n.tr("status.counter_dropped_in"), counters.dropped_in),
            counter_line(i18n.tr("status.counter_dropped_out"), counters.dropped_out),
            counter_line(i18n.tr("status.counter_learned_out"), counters.learned_out),
            Line::from(""),
        ]);
    } else {
        lines.push(Line::from(i18n.tr("status.counters_waiting")));
        lines.push(Line::from(""));
    }
    lines.extend([
        Line::from(i18n.format(
            "status.observe_socket",
            &[(
                "path",
                one_line(&observe_path.display().to_string()).as_str(),
            )],
        )),
        Line::from(i18n.format(
            "status.control_socket",
            &[(
                "path",
                one_line(&control_path.display().to_string()).as_str(),
            )],
        )),
    ]);
    let text = Text::from(lines);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(i18n.tr("status.title")),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn policy_health_span(state: &ConnectionState, i18n: &I18n) -> Span<'static> {
    match state {
        ConnectionState::Connecting => Span::styled(
            i18n.tr("health.connecting").to_owned(),
            Style::default().fg(Color::Yellow),
        ),
        ConnectionState::Connected => Span::styled(
            i18n.tr("health.connected").to_owned(),
            Style::default().fg(Color::Green),
        ),
        ConnectionState::Disconnected(reason) => Span::styled(
            i18n.format(
                "health.disconnected",
                &[("reason", one_line(reason).as_str())],
            ),
            Style::default().fg(Color::Red),
        ),
    }
}

fn telemetry_health_span(
    app: &App,
    now: Instant,
    counters_age: Option<Duration>,
    i18n: &I18n,
) -> Span<'static> {
    match &app.telemetry {
        ConnectionState::Connecting => Span::styled(
            i18n.tr("health.connecting").to_owned(),
            Style::default().fg(Color::Yellow),
        ),
        ConnectionState::Connected => {
            let stale_age = counters_age.or_else(|| app.telemetry_connection_age(now));
            match stale_age {
                Some(age) if age >= COUNTERS_STALE_AFTER => Span::styled(
                    i18n.format(
                        "health.telemetry_stale",
                        &[("duration", duration_label(age, i18n).as_str())],
                    ),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Some(_) if counters_age.is_some() => Span::styled(
                    i18n.tr("health.subscription_active").to_owned(),
                    Style::default().fg(Color::Green),
                ),
                _ => Span::styled(
                    i18n.tr("health.subscription_waiting").to_owned(),
                    Style::default().fg(Color::Yellow),
                ),
            }
        }
        ConnectionState::Disconnected(reason) => Span::styled(
            i18n.format(
                "health.telemetry_disconnected",
                &[("reason", one_line(reason).as_str())],
            ),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}

fn access_span(read_only: bool, i18n: &I18n) -> Span<'static> {
    if read_only {
        Span::styled(
            i18n.tr("access.read_only").to_owned(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            i18n.tr("access.privileged").to_owned(),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    }
}

fn draw_rules(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let rows = app.snapshot.as_ref().map_or_else(Vec::new, |snapshot| {
        snapshot
            .rules
            .iter()
            .map(|rule| {
                let port = rule.spec.port.map_or_else(
                    || "—".to_owned(),
                    |range| {
                        if range.start() == range.end() {
                            range.start().to_string()
                        } else {
                            format!("{}-{}", range.start(), range.end())
                        }
                    },
                );
                let interface = rule
                    .spec
                    .interface
                    .as_ref()
                    .map_or("—", |interface| interface.as_str());
                let origin = match rule.spec.origin {
                    RuleOrigin::Manual => i18n.tr("common.manual"),
                    RuleOrigin::Learned => i18n.tr("common.learned"),
                };
                let style = if rule.spec.enabled {
                    Style::default()
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                Row::new(vec![
                    Cell::from(if rule.spec.enabled { "●" } else { "○" }),
                    Cell::from(direction_label(rule.spec.direction, i18n)),
                    Cell::from(protocol_label(rule.spec.protocol, i18n)),
                    Cell::from(peer_label(rule, i18n)),
                    Cell::from(port),
                    Cell::from(interface.to_owned()),
                    Cell::from(application_label(rule, i18n)),
                    Cell::from(rule.spec.name.to_string()),
                    Cell::from(origin),
                ])
                .style(style)
            })
            .collect::<Vec<_>>()
    });

    let header = Row::new([
        i18n.tr("rules.column_enabled"),
        i18n.tr("rules.column_direction"),
        i18n.tr("rules.column_protocol"),
        i18n.tr("rules.column_peer"),
        i18n.tr("rules.column_port"),
        i18n.tr("rules.column_interface"),
        i18n.tr("rules.column_application"),
        i18n.tr("rules.column_name"),
        i18n.tr("rules.column_origin"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(20),
            Constraint::Length(11),
            Constraint::Length(12),
            Constraint::Length(24),
            Constraint::Min(14),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(i18n.tr("rules.title")),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(
        app.snapshot
            .as_ref()
            .filter(|snapshot| !snapshot.rules.is_empty())
            .map(|_| app.selected_rule),
    );
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_events(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let items = app
        .events
        .iter()
        .rev()
        .map(|event| ListItem::new(format_event(event, i18n)))
        .collect::<Vec<_>>();
    let title = if app.dropped_events == 0 {
        i18n.tr("events.title").to_owned()
    } else {
        let count = app.dropped_events.to_string();
        i18n.format("events.title_dropped", &[("count", count.as_str())])
    };
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn application_label(rule: &Rule, i18n: &I18n) -> String {
    rule.spec.application.as_ref().map_or_else(
        || i18n.tr("rules.network_only").to_owned(),
        |selector| {
            if selector.metadata_redacted {
                i18n.tr("rules.application_redacted").to_owned()
            } else {
                selector
                    .executable
                    .as_ref()
                    .map_or_else(|| i18n.tr("common.unknown").to_owned(), ToString::to_string)
            }
        },
    )
}

fn draw_help(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let mut lines = vec![
        Line::from(i18n.tr("help.navigation")),
        Line::from(i18n.tr("help.next_tab")),
        Line::from(i18n.tr("help.select_rule")),
        Line::from(i18n.tr("help.quit")),
        Line::from(i18n.tr("help.open_help")),
        Line::from(""),
        Line::from(Span::styled(
            i18n.tr("help.control_title"),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(i18n.tr("help.select_mode")),
        Line::from(i18n.tr("help.rule_actions")),
        Line::from(i18n.tr("help.toggle_rule")),
        Line::from(""),
        Line::from(i18n.tr("help.editor")),
    ];
    if app.read_only {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            i18n.tr("help.unprivileged"),
            Style::default().fg(Color::Yellow),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(i18n.tr("help.title")),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let message = app.notice.as_deref().map_or_else(
        || match app.view {
            View::Status => i18n.tr("footer.status"),
            View::Rules if app.read_only => i18n.tr("footer.rules_read_only"),
            View::Rules => i18n.tr("footer.rules"),
            View::Events if matches!(app.telemetry, ConnectionState::Connected) => {
                i18n.tr("footer.events_live")
            }
            View::Events => i18n.tr("footer.events_offline"),
            View::Help => i18n.tr("footer.help"),
        },
        str::trim,
    );
    frame.render_widget(
        Paragraph::new(one_line(message))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn draw_overlay(frame: &mut Frame<'_>, app: &App) {
    let i18n = &app.i18n;
    match &app.overlay {
        Overlay::None => {}
        Overlay::ModePicker { selected } => {
            let area = centered_rect(54, 11, frame.area());
            frame.render_widget(Clear, area);
            let modes = [Mode::BlockAll, Mode::Learning, Mode::Enforcing];
            let lines = modes.into_iter().enumerate().map(|(index, mode)| {
                let style = if mode == *selected {
                    mode_style(mode).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(
                    format!("{}. {}", index + 1, mode_label(mode, i18n)),
                    style,
                ))
            });
            let text = Text::from(lines.collect::<Vec<_>>());
            frame.render_widget(
                Paragraph::new(text)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(i18n.tr("overlay.mode_picker")),
                    )
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
        Overlay::ConfirmBlockAll => draw_confirmation(
            frame,
            i18n.tr("overlay.block_all_title"),
            i18n.tr("overlay.block_all_body"),
            Color::Red,
        ),
        Overlay::ConfirmDelete { name, .. } => draw_confirmation(
            frame,
            i18n.tr("overlay.delete_title"),
            &i18n.format("overlay.delete_body", &[("name", one_line(name).as_str())]),
            Color::Yellow,
        ),
        Overlay::Editor(form) => draw_editor(frame, form, i18n),
        Overlay::Message { title, body } => {
            let area = centered_rect(70, 9, frame.area());
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(safe_multiline(body))
                    .block(Block::default().borders(Borders::ALL).title(title.as_str()))
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
    }
}

#[allow(clippy::too_many_lines)]
fn draw_editor(frame: &mut Frame<'_>, form: &RuleForm, i18n: &I18n) {
    let area = centered_rect(86, 29, frame.area());
    frame.render_widget(Clear, area);
    let fields = [
        (
            FormField::Name,
            i18n.tr("editor.field_name"),
            form.name.clone(),
        ),
        (
            FormField::Direction,
            i18n.tr("editor.field_direction"),
            direction_label(form.direction, i18n).to_owned(),
        ),
        (
            FormField::Protocol,
            i18n.tr("editor.field_protocol"),
            protocol_label(form.protocol, i18n).to_owned(),
        ),
        (
            FormField::PeerNetwork,
            i18n.tr("editor.field_peer"),
            form.peer_network.clone(),
        ),
        (
            FormField::Port,
            i18n.tr("editor.field_port"),
            form.port.clone(),
        ),
        (
            FormField::Interface,
            i18n.tr("editor.field_interface"),
            form.interface.clone(),
        ),
        (
            FormField::Application,
            i18n.tr("editor.field_application"),
            if form.bind_application {
                i18n.tr("common.yes")
            } else {
                i18n.tr("common.no")
            }
            .to_owned(),
        ),
        (
            FormField::Executable,
            i18n.tr("editor.field_executable"),
            form.executable.clone(),
        ),
        (
            FormField::CommandMode,
            i18n.tr("editor.field_command_mode"),
            command_mode_label(form.command_mode, i18n).to_owned(),
        ),
        (
            FormField::Arguments,
            i18n.tr("editor.field_arguments"),
            form.arguments.clone(),
        ),
        (
            FormField::Uid,
            i18n.tr("editor.field_uid"),
            form.uid.clone(),
        ),
        (
            FormField::Cgroup,
            i18n.tr("editor.field_cgroup"),
            form.cgroup.clone(),
        ),
        (
            FormField::Enabled,
            i18n.tr("editor.field_enabled"),
            if form.enabled {
                i18n.tr("common.yes")
            } else {
                i18n.tr("common.no")
            }
            .to_owned(),
        ),
    ];
    let mut lines = Vec::with_capacity(fields.len() + 5);
    lines.push(Line::from(vec![
        Span::raw(format!("{:>20}: ", i18n.tr("editor.field_origin"))),
        Span::styled(
            match form.origin {
                RuleOrigin::Manual => i18n.tr("common.manual"),
                RuleOrigin::Learned => i18n.tr("common.learned_immutable"),
            },
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    for (field, label, value) in fields {
        let style = if form.active_field == field {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{label:>20}: "), style),
            Span::styled(
                if value.is_empty() {
                    "—".to_owned()
                } else {
                    value
                },
                style,
            ),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        i18n.tr("editor.help"),
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        i18n.tr("editor.application_help"),
        Style::default().fg(Color::DarkGray),
    )));
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            one_line(error),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if form.id.is_some() {
                        i18n.tr("editor.edit_title")
                    } else {
                        i18n.tr("editor.new_title")
                    }),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_confirmation(frame: &mut Frame<'_>, title: &str, body: &str, color: Color) {
    let area = centered_rect(68, 8, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(body)
            .alignment(Alignment::Center)
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn centered_rect(width_percent: u16, height: u16, area: Rect) -> Rect {
    let vertical_margin = area.height.saturating_sub(height) / 2;
    let vertical = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(vertical_margin),
            Constraint::Min(height.min(area.height)),
            Constraint::Length(vertical_margin),
        ])
        .split(area);
    let horizontal_margin = 100_u16.saturating_sub(width_percent) / 2;
    Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([
            Constraint::Percentage(horizontal_margin),
            Constraint::Percentage(width_percent),
            Constraint::Percentage(horizontal_margin),
        ])
        .split(vertical[1])[1]
}

fn format_event(event: &Event, i18n: &I18n) -> Line<'static> {
    let timestamp = event.occurred_at.format("%H:%M:%S");
    let (text, color) = match &event.kind {
        EventKind::ModeChanged { previous, current } => (
            i18n.format(
                "event.mode_changed",
                &[
                    ("previous", mode_label(*previous, i18n)),
                    ("current", mode_label(*current, i18n)),
                ],
            ),
            mode_color(*current),
        ),
        EventKind::RuleCreated { rule } => (
            i18n.format("event.rule_created", &[("rule", rule.spec.name.as_str())]),
            Color::Green,
        ),
        EventKind::RuleUpdated { rule } => (
            i18n.format("event.rule_updated", &[("rule", rule.spec.name.as_str())]),
            Color::Cyan,
        ),
        EventKind::RuleDeleted { rule } => (
            i18n.format("event.rule_deleted", &[("rule", rule.spec.name.as_str())]),
            Color::Yellow,
        ),
        EventKind::RuleEnabledChanged { rule } => (
            i18n.format(
                "event.rule_enabled",
                &[
                    ("rule", rule.spec.name.as_str()),
                    (
                        "state",
                        if rule.spec.enabled {
                            i18n.tr("event.enabled")
                        } else {
                            i18n.tr("event.disabled")
                        },
                    ),
                ],
            ),
            Color::Cyan,
        ),
        EventKind::CountersUpdated { counters } => {
            (format_counters_event(counters, i18n), Color::DarkGray)
        }
    };
    Line::from(vec![
        Span::styled(
            format!("{timestamp} r{} ", event.revision),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(text, Style::default().fg(color)),
    ])
}

fn format_counters_event(counters: &openshield_core::FirewallCounters, i18n: &I18n) -> String {
    let accepted_in_packets = counters.accepted_in.packets.to_string();
    let accepted_in_bytes = counters.accepted_in.bytes.to_string();
    let dropped_in_packets = counters.dropped_in.packets.to_string();
    let dropped_in_bytes = counters.dropped_in.bytes.to_string();
    let accepted_out_packets = counters.accepted_out.packets.to_string();
    let accepted_out_bytes = counters.accepted_out.bytes.to_string();
    let dropped_out_packets = counters.dropped_out.packets.to_string();
    let dropped_out_bytes = counters.dropped_out.bytes.to_string();
    let learned_packets = counters.learned_out.packets.to_string();
    let learned_bytes = counters.learned_out.bytes.to_string();
    i18n.format(
        "event.counters",
        &[
            ("accepted_in_packets", accepted_in_packets.as_str()),
            ("accepted_in_bytes", accepted_in_bytes.as_str()),
            ("dropped_in_packets", dropped_in_packets.as_str()),
            ("dropped_in_bytes", dropped_in_bytes.as_str()),
            ("accepted_out_packets", accepted_out_packets.as_str()),
            ("accepted_out_bytes", accepted_out_bytes.as_str()),
            ("dropped_out_packets", dropped_out_packets.as_str()),
            ("dropped_out_bytes", dropped_out_bytes.as_str()),
            ("learned_packets", learned_packets.as_str()),
            ("learned_bytes", learned_bytes.as_str()),
        ],
    )
}

pub fn mode_label(mode: Mode, i18n: &I18n) -> &str {
    match mode {
        Mode::BlockAll => i18n.tr("mode.block_all"),
        Mode::Learning => i18n.tr("mode.learning"),
        Mode::Enforcing => i18n.tr("mode.enforcing"),
    }
}

const fn mode_style(mode: Mode) -> Style {
    Style::new().fg(mode_color(mode))
}

const fn mode_color(mode: Mode) -> Color {
    match mode {
        Mode::BlockAll => Color::Red,
        Mode::Learning => Color::Yellow,
        Mode::Enforcing => Color::Green,
    }
}

pub fn direction_label(direction: Direction, i18n: &I18n) -> &str {
    match direction {
        Direction::Inbound => i18n.tr("direction.inbound"),
        Direction::Outbound => i18n.tr("direction.outbound"),
    }
}

pub fn protocol_label(protocol: TransportProtocol, i18n: &I18n) -> &str {
    match protocol {
        TransportProtocol::Any => i18n.tr("common.any"),
        TransportProtocol::Tcp => "TCP",
        TransportProtocol::Udp => "UDP",
        TransportProtocol::Icmp => "ICMP",
        TransportProtocol::IcmpV6 => "ICMPv6",
    }
}

fn command_mode_label(mode: CommandMode, i18n: &I18n) -> &str {
    match mode {
        CommandMode::Any => i18n.tr("editor.command_any"),
        CommandMode::Exact => i18n.tr("editor.command_exact"),
        CommandMode::Prefix => i18n.tr("editor.command_prefix"),
    }
}

fn duration_label(duration: Duration, i18n: &I18n) -> String {
    let seconds = duration.as_secs();
    if seconds == 0 {
        i18n.tr("duration.subsecond").to_owned()
    } else if seconds < 60 {
        let value = seconds.to_string();
        i18n.format("duration.seconds", &[("value", value.as_str())])
    } else if seconds < 3_600 {
        let value = (seconds / 60).to_string();
        i18n.format("duration.minutes", &[("value", value.as_str())])
    } else {
        let value = (seconds / 3_600).to_string();
        i18n.format("duration.hours", &[("value", value.as_str())])
    }
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .take(MAX_SINGLE_LINE_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn safe_multiline(value: &str) -> String {
    value
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .map(|character| match character {
            '\n' => '\n',
            character if character.is_control() => ' ',
            character => character,
        })
        .collect()
}

fn counter_line(label: &str, value: CounterValue) -> Line<'static> {
    Line::from(format!(
        "  {label:<16} {:>12} / {:>16}",
        value.packets, value.bytes
    ))
}
