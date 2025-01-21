use crate::config::compliance_type::Compliance;
/**
 * A message processor for STUn messages
 *
 */
use crate::{utils, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::auth::{Auth, SimpleAuth};
use crate::stun::message_type::MSG_BINDING_REQUEST;
use crate::{stun::bindreq::StunBindingRequest, stun::bindresp::StunBindingResponse};
use async_trait::async_trait;
use hex;
use serde::Deserialize;
use slog::{debug, trace};

#[derive(Clone, Debug, Deserialize)]
pub struct StaticConfig {
    pub software_name: String,
    pub compliance_level: Compliance,
}

/**
 * This trait defines an asynchronous method for processing STUN messages and
 * generating responses.
 */
#[async_trait]
pub trait MessageProcessor {
    async fn process_message(
        &self,
        input: &[u8],
        client_addr: Option<SocketAddr>,
        output: &mut [u8],
        
    ) -> Result<usize, Box<dyn std::error::Error>>;
}

/**
 * Implement the `MessageProcessor` trait for handling STUN messages.
 */
#[derive(Clone)]
pub(crate) struct StunMessageProcessor <A: Auth + Send + Sync + 'static> {
    context: Arc<Context>,
    settings: StaticConfig,
    auth: Option<A>
}

impl<A: Auth + Send + Sync + 'static> StunMessageProcessor<A>  {
    /**
     * Creates a new `StunMessageProcessor` instance.
     *
     * @param context The server context containing configuration and logger.
     * @return A new `StunMessageProcessor` instance.
     */

    pub fn new(context: &Arc<Context>, static_settings: &StaticConfig, authenticator: Option<A>) -> Self {
        
        Self {
            context: Arc::clone(context),
            settings: static_settings.clone(),
            auth: authenticator
        }
    }

    /**
     * A shorthand function for creating StunBindingResponse objects specialized as errors
     *
     * @param request The STUN binding request.
     * @param response The STUN binding response.
     * @param output The buffer to write the response into.
     * @return A `Result` containing the number of bytes written to the output buffer, or an error.
     */
    fn prepare_error(
        &self,
        request: &StunBindingRequest,
        response: &StunBindingResponse,
        output: &mut [u8],
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let msg_size = response.serialize(output)?;
        // todo
        trace!(
            self.context.logger,
            "--<-- [{}] STUN BIND ERR: {:?}",
            hex::encode(&request.transaction_id),
            &response
        );
        return Ok(msg_size);
    }
}

#[async_trait]
impl<A: Auth + Send + Sync + 'static> MessageProcessor for StunMessageProcessor<A> {
    
    /**
     * Processes a STUN message and generates a response.
     *
     * @param input The input byte slice containing the STUN message.
     * @param client_addr The optional client address (present for UDP, may be None for TCP).
     * @param output The buffer to write the response into.
     * @return A `Result` containing the number of bytes written to the output buffer, or an error.
     */
    async fn process_message(
        &self,
        input: &[u8],
        client_addr: Option<SocketAddr>,
        output: &mut [u8]
    ) -> Result<usize, Box<dyn std::error::Error>> {
        use super::bindreq::StunBindingRequest;
        use super::bindresp::StunBindingResponse;

        let request = match StunBindingRequest::deserialize(&self.context, &self.settings, input) {
            Ok(msg) => msg,
            Err(e) => {
                let msg_size = e.serialize(output)?;

                trace!(
                    self.context.logger,
                    "--<-- [unknown] STUN BIND ERR: {:?}",
                    e
                );
                return Ok(msg_size);
            }
        };

        trace!(
            self.context.logger,
            "-->-- [{}]: {}",
            hex::encode(&request.transaction_id),
            utils::hex_encode_delimited(&input)
        );

        match request.validate(&self.context.logger, &input, input.len() as u16) {
            Some(e) => {
                let msg_size = self.prepare_error(&request, &e, output)?;
                return Ok(msg_size);
            }
            None => {}
        }

        match request.message_type {
            MSG_BINDING_REQUEST => {
                trace!(
                    self.context.logger,
                    "-->-- [{}] STUN BIND REQ: {:?}",
                    hex::encode(&request.transaction_id),
                    request
                );
                let mut response = StunBindingResponse::new(
                    &self.context,
                    request.transaction_id,
                    self.settings.clone(),
                );

                match response.update(client_addr, &response.transaction_id.clone()) {
                    Ok(_) => {}
                    Err(e) => {
                        let msg_size = self.prepare_error(&request, &e, output)?;
                        return Ok(msg_size);
                    }
                };
                response.message_length = calculate_response_size(&response);

                trace!(
                    self.context.logger,
                    "--<-- [{}] STUN BIND RESP: {:?}",
                    hex::encode(&request.transaction_id),
                    response
                );
                let msg_size = response.serialize(output)?;
                trace!(
                    self.context.logger,
                    "--<-- [{}]:  {}",
                    hex::encode(&response.transaction_id),
                    utils::hex_encode_delimited(&output[..msg_size])
                );
                return Ok(msg_size);
            }
            _ => {
                debug!(
                    self.context.logger,
                    "Unknown STUN message type: {}", request.message_type
                );
                return Ok(0);
            }
        }
    }
}

fn calculate_response_size(response: &StunBindingResponse) -> u16 {
    let mut size = size_of_val(&response.message_type)
        + size_of_val(&response.message_length)
        + size_of_val(&response.magic_cookie)
        + size_of_val(&response.transaction_id);

    if let Some(mapped_address) = &response.mapped_address {
        size += mapped_address.len();
    }
    if let Some(username) = &response.username {
        size += username.len();
    }
    if let Some(message_integrity) = &response.message_integrity {
        size += message_integrity.len();
    }
    if let Some(error_code) = &response.error_code {
        size += size_of_val(error_code);
    }
    if let Some(unknown_attributes) = &response.unknown_attributes {
        size += unknown_attributes.len() * size_of_val(&unknown_attributes[0]);
    }
    if let Some(realm) = &response.realm {
        size += realm.len();
    }
    if let Some(nonce) = &response.nonce {
        size += nonce.len();
    }
    if let Some(xor_mapped_address) = &response.xor_mapped_address {
        size += xor_mapped_address.len();
    }
    if let Some(software) = &response.software {
        size += software.len();
    }
    if let Some(alternate_server) = &response.alternate_server {
        size += alternate_server.len();
    }
    if let Some(fingerprint) = &response.fingerprint {
        size += size_of_val(fingerprint);
    }

    size as u16
}
