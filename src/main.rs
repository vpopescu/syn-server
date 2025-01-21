use auth::SimpleAuth;
use config::compliance_type::Compliance;
/**
 * This module defines the main entry point for the SYN server and the server implementation.
 */
use slog::{info, Logger};
use std::sync::Arc;
use stun::processor::{StaticConfig, StunMessageProcessor};

mod config;
mod logging;
mod net;
mod stun;
mod utils;
mod auth;

use std::sync::Mutex;
pub(crate) static SOFTWARE_NAME: Mutex<Option<String>> = Mutex::new(None);
pub(crate) static COMPLIANCE_LEVEL: Mutex<Option<Compliance>> = Mutex::new(None);

/**
 * Represents the context for the SYN server.
 *
 * Fields:
 * - `config`: The server configuration settings.
 * - `logger`: The server logger instance.
 */
#[derive(Debug)]
pub(crate) struct Context {
    pub(crate) config: config::Settings,
    pub(crate) logger: Logger,
}

pub struct SynServer {
    context: Arc<Context>,
}

impl SynServer {
    /**
     * Creates a new `SynServer` instance.
     *
     * This function initializes the server configuration and logger, and creates
     * a new `SynServer` instance with the initialized context.
     *
     * @return An `Arc` containing the new `SynServer` instance.
     */
    pub fn new() -> Arc<Self> {
        let cfg = config::Settings::new().expect("Failed to load configuration");

        let context = Context {
            config: cfg.clone(),
            logger: logging::init_logger(&cfg),
        };

        Arc::new(Self {
            context: Arc::new(context),
        })
    }

    /**
     * Run the SYN server.
     *
     * This function sets up the TCP and UDP listeners based on the configuration,
     * and starts the server to handle incoming connections. It blocks until
     * terminated or both threads exit
     *
     * @return A `Result` indicating success or failure.
     */
    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        let mut handles = vec![];

        info!(self.context.logger, "Starting STUN server");

        let settings = StaticConfig {
            software_name: SOFTWARE_NAME
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| self.context.config.software_name.clone()),
            compliance_level: COMPLIANCE_LEVEL
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(self.context.config.compliance.clone()),
        };

        let stun_processor = StunMessageProcessor::new(&self.context, &settings, Some(SimpleAuth::new()));
        let network_server = net::NetworkServer::new(&self.context, stun_processor);

        if !self.context.config.disable_tcp {
            let tcp_handle = network_server.setup_tcp_listener()?;
            handles.push(tcp_handle);
        }

        if !self.context.config.disable_udp {
            let udp_handle = network_server.setup_udp_listener()?;
            handles.push(udp_handle);
        }

        // Join handles
        for handle in handles {
            handle.await.unwrap();
        }
        Ok(())
    }
}

/**
 * The main entry point for the application, it creates
 * the server object and passes control to it.
 */
#[tokio::main]
async fn main() {
    let server = SynServer::new();
    _ = server.run().await;
}
