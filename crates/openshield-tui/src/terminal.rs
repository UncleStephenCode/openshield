use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

pub type TuiTerminal = Terminal<CrosstermBackend<Stdout>>;
static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct TerminalSession {
    terminal: TuiTerminal,
}

impl TerminalSession {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        TERMINAL_ACTIVE.store(true, Ordering::Release);

        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, Hide) {
            restore();
            return Err(error);
        }

        match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(mut terminal) => {
                if let Err(error) = terminal.clear() {
                    restore();
                    return Err(error);
                }
                Ok(Self { terminal })
            }
            Err(error) => {
                restore();
                Err(error)
            }
        }
    }

    pub fn terminal_mut(&mut self) -> &mut TuiTerminal {
        &mut self.terminal
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        restore();
    }
}

/// Best-effort cleanup is also called from the panic hook because release builds
/// abort on panic and therefore cannot rely solely on `Drop`.
pub fn restore() {
    if !TERMINAL_ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Show, LeaveAlternateScreen);
}

pub fn install_panic_hook() {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        restore();
        previous_hook(panic_info);
    }));
}
