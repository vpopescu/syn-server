use serde::de::{self, Deserializer, Visitor};

use slog::Level;
use std::{env, fmt};

/**
 * Deserialize the log level from the configuration file.
 *
 * If the log level is not found in the configuration file, it will be inferred from the environment type.
 *
 */
pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
where
    D: Deserializer<'de>,
{
    match deserializer.deserialize_str(LogLevelVisitor) {
        Ok(level) => Ok(level),
        Err(_) => {
            let env = env::var("SYN_ENVIRONMENT").unwrap_or_else(|_| "production".into());
            match env.to_lowercase().as_str() {
                "development" => Ok(Level::Debug),
                "staging" => Ok(Level::Warning),
                "production" => Ok(Level::Warning),
                _ => Ok(Level::Warning),
            }
        }
    }
}

struct LogLevelVisitor;
/**
 * Deserialize the log level from a string.
 *
 */
impl<'de> Visitor<'de> for LogLevelVisitor {
    type Value = Level;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string representing a log level")
    }

    fn visit_str<E>(self, value: &str) -> Result<Level, E>
    where
        E: de::Error,
    {
        match value.to_lowercase().as_str() {
            "trace" => Ok(Level::Trace),
            "debug" => Ok(Level::Debug),
            "info" => Ok(Level::Info),
            "warn" => Ok(Level::Warning),
            "error" => Ok(Level::Error),
            "critical" => Ok(Level::Critical),
            _ => Err(de::Error::unknown_variant(
                value,
                &["trace", "debug", "info", "warn", "error", "critical"],
            )),
        }
    }
}
