use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use color_eyre::eyre::Result;
use crossterm::event::{self, Event, KeyCode};
use directories::ProjectDirs;
use lazy_static::lazy_static;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    text::{Line, Text},
    widgets::{Block, Paragraph, Tabs},
    DefaultTerminal, Frame,
};
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::context::{
    ethernet::EthernetContext, network_interface::NetworkInterfaceContext, ContextId, TsndtContext,
};

const DEFAULT_CONTEXT_ID: ContextId = 0;
pub(crate) const TICK_RATE_MS: u64 = 200;

lazy_static! {
    pub static ref PROJECT_NAME: String = env!("CARGO_CRATE_NAME").to_uppercase().to_string();
    pub static ref DATA_FOLDER: Option<PathBuf> =
        std::env::var(format!("{}_DATA", PROJECT_NAME.clone()))
            .ok()
            .map(PathBuf::from);
    pub static ref LOG_ENV: String = format!("{}_LOGLEVEL", PROJECT_NAME.clone());
    pub static ref LOG_FILE: String = format!("{}.log", env!("CARGO_PKG_NAME"));
}

fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "gth828r", env!("CARGO_PKG_NAME"))
}

pub fn get_data_dir() -> PathBuf {
    let directory = if let Some(s) = DATA_FOLDER.clone() {
        s
    } else if let Some(proj_dirs) = project_directory() {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    };
    directory
}

pub fn initialize_logging() -> Result<()> {
    let directory = get_data_dir();
    std::fs::create_dir_all(directory.clone())?;
    let log_path = directory.join(LOG_FILE.clone());
    let log_file = std::fs::File::create(log_path)?;
    std::env::set_var(
        "RUST_LOG",
        std::env::var("RUST_LOG")
            .or_else(|_| std::env::var(LOG_ENV.clone()))
            .unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME"))),
    );
    let file_subscriber = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_writer(log_file)
        .with_target(false)
        .with_ansi(false)
        .with_filter(tracing_subscriber::filter::EnvFilter::from_default_env());
    tracing_subscriber::registry()
        .with(file_subscriber)
        .with(ErrorLayer::default())
        .init();
    Ok(())
}

#[derive(Eq, PartialEq)]
pub(crate) enum AppRunState {
    Running,
    Stopped,
}

pub(crate) struct App {
    contexts: Vec<Box<dyn TsndtContext>>,
    selected_context_id: usize,
    run_state: AppRunState,
}

fn draw(
    tab_titles: Vec<String>,
    selected_tab: usize,
    frame: &mut Frame,
    context_command_help: Vec<String>,
) -> Rect {
    // 3 comes from 1 lines of global application commands and
    // 2 lines for borders for command help block
    let num_commands_lines = 3 + context_command_help.len() as u16;
    let [tabs_area, context_area, commands_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(num_commands_lines),
    ])
    .areas(frame.area());

    render_tabs(tab_titles, selected_tab, frame, tabs_area);
    render_commands(frame, commands_area, context_command_help);
    context_area
}

fn render_tabs(tab_titles: Vec<String>, selected_tab: usize, frame: &mut Frame, area: Rect) {
    let tabs = Tabs::new(tab_titles).select(selected_tab);
    frame.render_widget(tabs, area);
}

fn render_commands(frame: &mut Frame, commands_area: Rect, context_command_help: Vec<String>) {
    let application_line = Line::from(vec!["(q) Quit, (←/→): Change contexts".into()]).centered();
    let context_lines: Vec<Line<'_>> = context_command_help
        .iter()
        .map(|help_text_line| Line::from(help_text_line.clone()).centered())
        .collect();
    let mut help_lines = vec![application_line];
    help_lines.extend(context_lines);
    let command_help_text =
        Paragraph::new(Text::from(help_lines)).block(Block::bordered().title("Commands"));
    frame.render_widget(command_help_text, commands_area);
}

impl App {
    pub(crate) fn new(bpf: &mut aya::Ebpf) -> Self {
        let contexts: Vec<Box<dyn TsndtContext>> = vec![
            Box::new(NetworkInterfaceContext::new(bpf)),
            Box::new(EthernetContext::new()),
        ];

        Self {
            contexts,
            selected_context_id: DEFAULT_CONTEXT_ID,
            run_state: AppRunState::Running,
        }
    }

    pub(crate) fn run(mut self, bpf: &mut aya::Ebpf, mut terminal: DefaultTerminal) -> Result<()> {
        let tick_rate = Duration::from_millis(TICK_RATE_MS);
        let mut last_tick = Instant::now();
        let num_contexts = self.contexts.len();
        while self.run_state == AppRunState::Running {
            let tab_titles: Vec<String> = self
                .contexts
                .iter()
                .map(|ctx| ctx.get_context_name())
                .collect();

            let selected_tab = self.selected_context_id;

            // The app only handles events and renders the terminal for the active context
            let context = self.contexts.get_mut(selected_tab).unwrap();

            terminal.draw(|frame| {
                let context_command_help = context.get_command_help();
                let context_area = draw(tab_titles, selected_tab, frame, context_command_help);
                context.draw(frame, context_area)
            })?;

            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.run_state = AppRunState::Stopped;
                            break;
                        }
                        KeyCode::Right => {
                            if key.modifiers.is_empty() {
                                // modify tab and selected context
                                let candidate = self.selected_context_id + 1;
                                if candidate < num_contexts {
                                    self.selected_context_id += 1;
                                } else {
                                    self.selected_context_id = 0;
                                }
                            }
                        }
                        KeyCode::Left => {
                            if key.modifiers.is_empty() {
                                // modify tab and selected context
                                if self.selected_context_id > 0 {
                                    self.selected_context_id -= 1;
                                } else {
                                    self.selected_context_id = num_contexts - 1;
                                };
                            }
                        }
                        _ => {}
                    }

                    context.handle_key_event(key, bpf)?;
                }
            }
            if last_tick.elapsed() >= tick_rate {
                // Update models at each tick for all contexts, not just the active one
                for context in self.contexts.iter_mut() {
                    context.handle_tick(bpf)?;
                }
                last_tick = Instant::now();
            }
        }

        Ok(())
    }
}
