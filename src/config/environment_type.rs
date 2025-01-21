/**
 * Define `EnvironmentType` enum and implements various traits for it.
 *
 * The `EnvironmentType` enum represents different types of environments:
 * - `development` (also aliased as 'dev')
 * - `staging` (also aliased as 'stg')
 * - `production` (also aliased as 'prod')
 */
use std::str::FromStr;

use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum EnvironmentType {
    development,
    staging,
    production,
}

impl std::str::FromStr for EnvironmentType {
    type Err = ();

    /**
     * Parse a string into an `EnvironmentType` enum.
     */
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" => Ok(EnvironmentType::development),
            "dev" => Ok(EnvironmentType::development),
            "staging" => Ok(EnvironmentType::staging),
            "stg" => Ok(EnvironmentType::staging),
            "production" => Ok(EnvironmentType::production),
            "prod" => Ok(EnvironmentType::production),
            _ => Ok(EnvironmentType::production),
        }
    }
}

impl EnvironmentType {
    /**
     * Convert an `EnvironmentType` enum into a string.
     */
    pub fn as_str(&self) -> &'static str {
        match self {
            EnvironmentType::development => "development",
            EnvironmentType::staging => "staging",
            EnvironmentType::production => "production",
        }
    }
}
impl<'de> Deserialize<'de> for EnvironmentType {
    /**
     * Deserialize a string into an `EnvironmentType` enum.
     */
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(EnvironmentType::from_str(&s).unwrap_or(EnvironmentType::production))
    }
}
