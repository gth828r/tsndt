// A context is comprised of a controller and a view for a specific user function.
// Examples include:
//  * Interface-level monitoring
//  * Network address level monitoring
//  * etc

use color_eyre::eyre::Result;
use crossterm::event::KeyEvent;
use ratatui::{layout::Rect, Frame};

pub(crate) type ContextId = usize;

pub(crate) trait TsndtContext {
    fn handle_key_event(&mut self, key_event: KeyEvent, bpf: &mut aya::Ebpf) -> Result<()>;

    fn handle_tick(&mut self, bpf: &aya::Ebpf) -> Result<()>;

    fn draw(&mut self, frame: &mut Frame, context_area: Rect);

    fn get_context_name(&self) -> String;

    fn get_command_help(&self) -> Vec<String>;
}

pub(crate) mod network_interface;
