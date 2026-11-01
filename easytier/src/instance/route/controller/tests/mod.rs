//! Controller tests, split by platform implementation.

#[cfg(not(mobile))]
mod desktop;

#[cfg(mobile)]
mod mobile;
