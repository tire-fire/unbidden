//! Collectors, one module per group of mechanism classes.
//!
//! Grouping is by shared source material, not by kind: the cron collector
//! reads six spool layouts and emits two kinds, and splitting it would mean
//! parsing crontab syntax twice.

use crate::scan::Collector;

pub mod auth;
pub mod cron;
pub mod deep;
pub mod desktop;
pub mod initscripts;
pub mod kernel;
pub mod pkg;
pub mod shell;
pub mod systemd;

/// The command word of shell text, cut where the shell cuts it. A `;`, `|`,
/// `&`, `<`, `>` or parenthesis ends a word as surely as a space does, so
/// `/opt/a.sh; /tmp/x` runs /opt/a.sh and not a file named `a.sh;`, and the
/// rest of the line is left for enrichment to split into its own commands.
pub(crate) fn shell_word(word: &[u8]) -> &[u8] {
    let end = word.iter().position(|b| b";|&<>()".contains(b)).unwrap_or(word.len());
    &word[..end]
}

pub fn all() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(systemd::Systemd),
        Box::new(cron::Cron),
        Box::new(desktop::Desktop),
        Box::new(shell::Shell),
        Box::new(initscripts::InitScripts),
        Box::new(auth::Auth),
        Box::new(kernel::Kernel),
        Box::new(pkg::PkgHooks),
        Box::new(deep::GitConfig),
        Box::new(deep::Deep),
    ]
}
