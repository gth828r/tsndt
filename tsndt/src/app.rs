use std::path::PathBuf;

use color_eyre::eyre::Result;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use ratatui::DefaultTerminal;
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::context::{network_interface::NetworkInterfaceContext, ContextId, TsndtContext};

const DEFAULT_CONTEXT_ID: ContextId = 0;

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

pub(crate) struct App<'a> {
    contexts: Vec<Box<dyn TsndtContext + 'a>>,
}

impl<'a> App<'a> {
    pub(crate) fn new(bpf: &'a mut aya::Ebpf) -> Self {
        let contexts: Vec<Box<dyn TsndtContext + 'a>> =
            vec![Box::new(NetworkInterfaceContext::new(bpf))];

        Self { contexts }
    }

    pub(crate) fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut selected_context = DEFAULT_CONTEXT_ID;
        loop {
            let context = self.contexts.get_mut(selected_context).unwrap();
            let (run_state, next_context) = context.run(&mut terminal)?;

            match run_state {
                crate::context::ContextRunState::Stopped => break,
                crate::context::ContextRunState::_Paused => {
                    if let Some(next_context) = next_context {
                        selected_context = next_context
                    } else {
                        selected_context = DEFAULT_CONTEXT_ID;
                    }
                }
            }
        }

        Ok(())
    }
}
