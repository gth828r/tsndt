// A context is comprised of a controller and a view for a specific user function.
// Examples include:
//  * Interface-level monitoring
//  * Network address level monitoring
//  * etc

use color_eyre::eyre::Result;
use ratatui::DefaultTerminal;

pub(crate) type ContextId = usize;

pub(crate) enum ContextRunState {
    _Paused,
    Stopped,
}

pub(crate) trait TsndtContext {
    fn run(self: &mut Self, terminal: &mut DefaultTerminal) -> Result<(ContextRunState, Option<ContextId>)>;
}

pub(crate) mod networkinterface;
