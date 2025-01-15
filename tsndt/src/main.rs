use app::App;

pub mod app;
pub(crate) mod context;

// TODO: see if we can just put Aya-specific things in tokio runtime, draw in sync runtime
// (see https://www.reddit.com/r/rust/comments/18u0pd0/help_with_tokio_ratatui/)
#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    // 0. Initialize app logging
    app::initialize_logging()?;

    // 1. Load the eBPF program
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tsndt"
    )))
    .unwrap();

    // 2. Fire up the display
    color_eyre::install()?;
    let terminal = ratatui::init();
    let result = App::new(&mut bpf).run(terminal);
    ratatui::restore();
    result
}
