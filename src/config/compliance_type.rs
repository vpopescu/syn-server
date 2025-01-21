use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/**
 * Compliance type definition
 */

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) enum Compliance {
    /**
     * RFC 5389, but makes some allowances for older clients (for example, sending both XOR-MAPPED-ADDRESS and MAPPED-ADDRESS)
     * https://datatracker.ietf.org/doc/html/rfc5389
     */
    Relaxed,
    /**
     * Compatibile with RFC 5389, but may not work with some older clients
     * https://datatracker.ietf.org/doc/html/rfc5389
     */
    RFC5389,
    /**
     * Compatible with RFC 5780. This ,ay cause rfc5389 compatibile clients to stop working
     * https://datatracker.ietf.org/doc/html/rfc5780
     */
    RFC5780,
    /**
     * Compatible with RFC 8489. This may cause rfc5389 compatibile clients to stop working
     * https://datatracker.ietf.org/doc/html/rfc8489
     */
    RFC8489,
}

impl Default for Compliance {
    fn default() -> Self {
        Compliance::RFC5389
    }
}
impl Compliance {
    /**
     * Returns the string representation of the compliance level.
     *
     * @return A string slice representing the compliance level.
     */
    pub fn as_str(&self) -> &str {
        match *self {
            Compliance::Relaxed => "Relaxed",
            Compliance::RFC5389 => "RFC5389",
            Compliance::RFC5780 => "RFC5780",
            Compliance::RFC8489 => "RFC8489",
        }
    }
}

impl std::str::FromStr for Compliance {
    type Err = ();

    /**
     * Parse a string into an `EnvironmentType` enum.
     */
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "relaxed" => Ok(Compliance::Relaxed),
            "rfc5389" => Ok(Compliance::RFC5389),
            "rfc5780" => Ok(Compliance::RFC5780),
            "rfc8489" => Ok(Compliance::RFC8489),
            _ => Ok(Compliance::RFC5389),
        }
    }
}

/**
 * Deserialize the log level from the configuration file.
 *
 * If the log level is not found in the configuration file, it will be inferred from the environment type.
 *
 */
pub fn deserialize<'de, D>(deserializer: D) -> Result<Compliance, D::Error>
where
    D: Deserializer<'de>,
{
    match deserializer.deserialize_str(ComplianceVisitor) {
        Ok(c) => Ok(c),
        Err(_) => Ok(Compliance::RFC5389),
    }
}

struct ComplianceVisitor;
/**
 * Deserialize the log level from a string.
 *
 */
impl<'de> Visitor<'de> for ComplianceVisitor {
    type Value = Compliance;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string representing a log level")
    }

    fn visit_str<E>(self, value: &str) -> Result<Compliance, E>
    where
        E: de::Error,
    {
        match value.to_lowercase().as_str() {
            "relaxed" => Ok(Compliance::Relaxed),
            "rfc5389" => Ok(Compliance::RFC5389),
            "rfc5780" => Ok(Compliance::RFC5780),
            "rfc8489" => Ok(Compliance::RFC8489),
            _ => Ok(Compliance::RFC5389),
        }
    }
}
