/**
 * Initializes the logger
 * 
 * https://docs.rs/slog/latest/slog/
 *
 */
use std::sync::Mutex;

use crate::config::Settings;
use slog::{Drain, LevelFilter, Logger};
use slog_async::Async;
use slog_term::FullFormat;

/**
 * Initializes the logger.
 *
 * This function sets up the logger with the specified configuration settings.
 * It uses the `slog` crate for structured logging and configures the log level
 * based on the provided settings.
 *
 * @param cfg The configuration settings containing the log level.
 * @return A `Logger` instance configured with the specified log level.
 */
pub(crate) fn init_logger(cfg: &Settings) -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = FullFormat::new(decorator).build().fuse();
    let drain = Async::new(drain).build().fuse();

    let drain = LevelFilter::new(drain, cfg.log_level).fuse();
    Logger::root(Mutex::new(drain).fuse(), slog::o!())
}
