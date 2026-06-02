use std::backtrace::{Backtrace, BacktraceStatus};
use std::fmt::Display;
use std::panic::Location;

pub enum Trace<'l> {
    Location(&'l Location<'l>),
    Backtrace(Backtrace),
}

impl Trace<'_> {
    #[track_caller]
    pub fn capture() -> Self {
        let bt = Backtrace::capture();
        match bt.status() {
            BacktraceStatus::Captured => Trace::Backtrace(bt),
            _ => Trace::Location(Location::caller()),
        }
    }
}

impl Display for Trace<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Trace::Location(loc) => write!(f, "{}:{}:{}", loc.file(), loc.line(), loc.column()),
            Trace::Backtrace(bt) => {
                if f.alternate() {
                    write!(f, "{:#}", bt)
                } else {
                    write!(f, "{}", bt)
                }
            }
        }
    }
}
