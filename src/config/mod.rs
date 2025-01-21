use compliance_type::Compliance;
/**
 * Initialize server configuration, using hierarchical configuration
 * https://docs.rs/config/latest/config/
 *
 * 1. First syn.yaml is read
 * 2. Then syn.{environment}.yaml is read
 * 3. Then syn.local.yaml is read (this is normally used for dev and not checked in git)
 * 4. Finally, environment variables are read
 */
use config::{Config, ConfigError, Environment, File};
use environment_type::EnvironmentType;
use serde::Deserialize;
use std::env;
pub(crate) mod compliance_type;
mod environment_type;
mod loglevel_type;

/**
 * Represents the configuration settings for the SYN server.
 *
 * Fields:
 * - `environment`: The environment type (e.g., development, staging, or production).
 * - `tcp_bind_address`: The address and port to bind the TCP server (hostname:port format)
 * - `udp_bind_address`: The address to bind the UDP server (hostname:port format)
 * - `disable_tcp`: Flag to disable TCP server port.
 * - `disable_udp`: Flag to disable UDP server port.
 * - `software_name`: The name of the software, which will be added to 'software' field in STUN responses.
 * - `log_level`: The logging level. By default, logging is inferred from environment type if no other settings are found.
 * - `compliance`: The STUN protocol compliance level. By default, RFC5389 is used.
 */
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Settings {
    pub(crate) environment: EnvironmentType,
    pub(crate) tcp_bind_address: String,
    pub(crate) udp_bind_address: String,
    pub(crate) disable_tcp: bool,
    pub(crate) disable_udp: bool,
    pub(crate) software_name: String,
    #[serde(deserialize_with = "compliance_type::deserialize")]
    pub(crate) compliance: Compliance,
    #[serde(deserialize_with = "loglevel_type::deserialize")]
    pub(crate) log_level: slog::Level,
}

impl Settings {
    pub(crate) fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("SYN_ENVIRONMENT").unwrap_or_else(|_| "production".into());

        let s = Config::builder()
            // default config file
            .add_source(File::with_name("syn.yaml").required(false))
            // environment-based config file
            .add_source(File::with_name(&format!("syn.{run_mode}.yaml")).required(false))
            // local config file (don't check this into source control)
            .add_source(File::with_name("syn.local.yaml").required(false))
            .add_source(Environment::with_prefix("SYN"))
            .set_default("tcp_bind_address", "0.0.0.0:3478")?
            .set_default("udp_bind_address", "0.0.0.0:3478")?
            .set_default("compliance", Compliance::RFC5389.as_str())?
            .set_default(
                "log_level",
                if run_mode.to_lowercase() == "development" {
                    "debug"
                } else {
                    "warn"
                },
            )?
            .set_default("environment", EnvironmentType::production.as_str())?
            .set_default("disable_tcp", false)?
            .set_default("disable_udp", false)?
            .set_default("software_name", "SYN_SERVER/1")?
            .build()?;

        let mut settings: Settings = s.try_deserialize()?;
        settings.environment = EnvironmentType::from(settings.environment);
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    fn set_env_var(key: &str, value: &str) {
        env::set_var(key, value);
    }

    fn reset_env_var() {
        let v = env::vars().collect::<Vec<(String, String)>>();
        for (name, _) in v {
            if name.starts_with("SYN_") {
                env::remove_var(name);
            }
        }
    }

    #[test]
    #[serial]
    fn test_environment_variable_dev() {
        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "development");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(
            settings.environment.as_str(),
            EnvironmentType::development.as_str()
        );
        reset_env_var();
    }
    #[test]
    #[serial]
    fn test_environment_variable_prod() {
        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "production");

        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(
            settings.environment.as_str(),
            EnvironmentType::production.as_str()
        );
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_environment_variable_stg() {
        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "staging");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(
            settings.environment.as_str(),
            EnvironmentType::staging.as_str()
        );
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_environment_variable_garbage() {
        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "garbage");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(
            settings.environment.as_str(),
            EnvironmentType::production.as_str()
        );
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_environment_variable_none() {
        reset_env_var();
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(
            settings.environment.as_str(),
            EnvironmentType::production.as_str()
        );
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_disable_udp_variable_bool() {
        reset_env_var();
        set_env_var("SYN_DISABLE_UDP", "true");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.disable_udp, true);
        reset_env_var();
    }
    #[test]
    #[serial]
    fn test_disable_udp_variable_bool2() {
        reset_env_var();
        set_env_var("SYN_DISABLE_UDP", "false");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.disable_udp, false);
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_disable_udp_variable_num() {
        reset_env_var();
        set_env_var("SYN_DISABLE_UDP", "1");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.disable_udp, true);
        reset_env_var();
    }
    #[test]
    #[serial]
    fn test_disable_udp_variable_num2() {
        reset_env_var();
        set_env_var("SYN_DISABLE_UDP", "0");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.disable_udp, false);
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_tcp_bind_address_variable() {
        reset_env_var();
        set_env_var("SYN_TCP_BIND_ADDRESS", "127.0.0.1:1234");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.tcp_bind_address, "127.0.0.1:1234");
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_udp_bind_address_variable() {
        reset_env_var();
        set_env_var("SYN_UDP_BIND_ADDRESS", "127.0.0.1:5678");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.udp_bind_address, "127.0.0.1:5678");
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_log_level_none_none() {
        reset_env_var();
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Warning);
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_log_level_combinations() {
        reset_env_var();

        set_env_var("SYN_ENVIRONMENT", "production");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Warning);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "staging");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Warning);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "development");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Debug);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "production");
        set_env_var("SYN_LOG_LEVEL", "trace");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Trace);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "staging");
        set_env_var("SYN_LOG_LEVEL", "trace");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Trace);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "development");
        set_env_var("SYN_LOG_LEVEL", "trace");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Trace);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "development");
        set_env_var("SYN_LOG_LEVEL", "garbage");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Debug);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "production");
        set_env_var("SYN_LOG_LEVEL", "garbage");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Warning);

        reset_env_var();
        set_env_var("SYN_ENVIRONMENT", "staging");
        set_env_var("SYN_LOG_LEVEL", "garbage");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Warning);
    }

    #[test]
    #[serial]
    fn test_log_level_trace() {
        reset_env_var();
        set_env_var("SYN_LOG_LEVEL", "trace");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Trace);

        set_env_var("SYN_LOG_LEVEL", "Trace");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.log_level, slog::Level::Trace);

        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_compliance_rfc5389() {
        reset_env_var();
        set_env_var("SYN_COMPLIANCE", "RFC5389");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::RFC5389.as_str());

        set_env_var("SYN_COMPLIANCE", "rfc5389");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::RFC5389.as_str());
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_compliance_relaxed() {
        reset_env_var();
        set_env_var("SYN_COMPLIANCE", "RelaxeD");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::Relaxed.as_str());

        set_env_var("SYN_COMPLIANCE", "relaxed");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::Relaxed.as_str());

        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_compliance_rfc5780() {
        reset_env_var();
        set_env_var("SYN_COMPLIANCE", "RFC5780");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::RFC5780.as_str());

        set_env_var("SYN_COMPLIANCE", "rfc5780");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::RFC5780.as_str());

        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_compliance_rfc8489() {
        reset_env_var();
        set_env_var("SYN_COMPLIANCE", "RFC8489");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::RFC8489.as_str());

        set_env_var("SYN_COMPLIANCE", "rfc8489");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), Compliance::RFC8489.as_str());

        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_compliance_invalid() {
        reset_env_var();
        set_env_var("SYN_COMPLIANCE", "garbage");
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), "RFC5389"); // Default value
        reset_env_var();
    }

    #[test]
    #[serial]
    fn test_compliance_none() {
        reset_env_var();
        let settings = Settings::new().expect("Deserialization failed");
        assert_eq!(settings.compliance.as_str(), "RFC5389"); // Default value
        reset_env_var();
    }
}
