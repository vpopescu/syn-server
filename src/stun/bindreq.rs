/**
 * A STUN Binding Request message and associated helper functions
 * See RFC 5389 Section 6 for details
 * https://datatracker.ietf.org/doc/html/rfc5389#section-6
 *
 */
use std::{os::linux::raw, sync::Arc};

use crate::{
    stun::{
        bindresp::StunBindingResponse,
        error_code::{ERROR_CODE_BAD_REQUEST, ERROR_CODE_UNKNOWN_ATTRIBUTE},
        message_type::MSG_BINDING_REQUEST,
        HEADER_LENGTH, MAGIC_COOKIE,
    },
    Context,
};
use slog::{debug, Logger};

use super::processor::StaticConfig;

/**
 * A STUN Binding Request message
 * See RFC 5389 Section 6 for details
 * https://datatracker.ietf.org/doc/html/rfc5389#section-6
 */

#[derive(Debug)]
pub(crate) struct StunBindingRequest {
    pub message_type: u16, // Required: Message Type (e.g., 0x0001 for Binding Request)
    pub message_length: u16, // Required: Length of the message body
    pub magic_cookie: u32, // Required: Magic Cookie (0x2112A442)
    pub transaction_id: [u8; 12], // Required: Unique Transaction ID
    pub mapped_address: Option<[u8; 8]>, // Optional: Mapped Address attribute
    pub username: Option<String>, // Optional: Username attribute
    pub message_integrity: Option<[u8; 20]>, // Optional: Message Integrity attribute
    pub change_request: Option<[u8; 4]>, // Optional: Change Request attribute
    pub error_code: Option<(u16, String)>, // Optional: Error Code attribute
    pub unknown_attributes: Option<Vec<u16>>, // Optional: Unknown Attributes attribute
    pub realm: Option<String>, // Optional: Realm attribute
    pub nonce: Option<String>, // Optional: Nonce attribute
    pub xor_mapped_address: Option<[u8; 8]>, // Optional: XOR-Mapped Address attribute
    pub software: Option<String>, // Optional: Software attribute
    pub alternate_server: Option<[u8; 8]>, // Optional: Alternate Server attribute
    pub fingerprint: Option<u32>, // Optional: Fingerprint attribute

    //#[serde(skip_deserializing)]
    settings: StaticConfig,
    //#[serde(skip_deserializing)]
    context: Arc<Context>,
}

impl StunBindingRequest {
    /**
     * Create a new STUN Binding Request message
     *
     * @param transaction_id The unique transaction ID
     * @return A new STUN Binding Request message
     */
    #[allow(dead_code)]
    pub fn new(
        context: &Arc<Context>,
        transaction_id: [u8; 12],
        static_settings: &StaticConfig,
    ) -> Self {
        StunBindingRequest {
            message_type: MSG_BINDING_REQUEST, // Binding Request
            message_length: 0,                 // Initially set to 0, will be updated as needed
            magic_cookie: MAGIC_COOKIE,
            transaction_id,
            mapped_address: None,
            username: None,
            message_integrity: None,
            change_request: None,
            error_code: None,
            unknown_attributes: None,
            realm: None,
            nonce: None,
            xor_mapped_address: None,
            software: None,
            alternate_server: None,
            fingerprint: None,

            settings: static_settings.clone(),
            context: Arc::clone(context),
        }
    }

    /**
     * Validate the STUN Binding Request message
     * This function checks the magic cookie, message type, and message length
     * and returns an error response if any of these are invalid
     *
     * @param log The logger instance
     * @param raw_message_length The length of the raw message
     * @return An error response if the message is invalid, otherwise None
     *
     */
    pub fn validate(&self, log: &Logger, raw_message: &[u8], raw_message_length: u16) -> Option<StunBindingResponse> {
        // check that the magic cookie is correct
        if self.magic_cookie != MAGIC_COOKIE {
            debug!(
                log,
                "Received message with invalid magic cookie: 0x{:08X}, expected 0x{:08X}",
                self.magic_cookie,
                MAGIC_COOKIE
            );

            return Some(StunBindingResponse::new_error(
                &self.context,
                self.transaction_id,
                ERROR_CODE_BAD_REQUEST,
                "Invalid magic cookie".to_string(),
                self.settings.clone(),
            ));
        }

        // check that it's a binding request
        if self.message_type != MSG_BINDING_REQUEST {
            debug!(log, "Received unknown message type {}", self.message_type);
            return Some(StunBindingResponse::new_error(
                &self.context,
                self.transaction_id,
                ERROR_CODE_UNKNOWN_ATTRIBUTE,
                "Message type is unsupported".to_string(),
                self.settings.clone(),
            ));
        }

        // check the length
        if raw_message_length < 20 || (self.message_length + HEADER_LENGTH) != raw_message_length {
            debug!(
                log,
                "Received mismatched message length, header says {} but message is {}",
                self.message_length,
                raw_message_length - HEADER_LENGTH
            );
            return Some(StunBindingResponse::new_error(
                &self.context,
                self.transaction_id,
                ERROR_CODE_BAD_REQUEST,
                "Mismatched request length".to_string(),
                self.settings.clone(),
            ));
        }

        // if it has a signature, check it
        if let Some(fingerprint) = self.fingerprint {
            let calculated = crate::stun::util::calculate_local_fingerprint(&raw_message) ^ 0x5354554E;
            if calculated != fingerprint {
                debug!(log, "Received message with invalid fingerprint: 0x{:08X}, expected 0x{:08X}", self.fingerprint.unwrap(), calculated);
                return Some(StunBindingResponse::new_error(
                    &self.context,
                    self.transaction_id,
                    ERROR_CODE_BAD_REQUEST,
                    "Invalid fingerprint".to_string(),
                    self.settings.clone(),
                ));
            }

        }

        None
    }

    /**
     * Deserialize a STUN Binding Request message from a byte array
     *
     * @param bytes The byte array containing the message
     * @return A Result containing the deserialized STUN Binding Request message
     */
    pub fn deserialize(
        context: &Arc<Context>,
        settings: &StaticConfig,
        bytes: &[u8],
    ) -> Result<StunBindingRequest, StunBindingResponse> {
        if bytes.len() < 20 {
            return Err(StunBindingResponse::new_error(
                &context,
                [0; 12],
                ERROR_CODE_BAD_REQUEST,
                "Message is too short".to_string(),
                settings.clone(),
            ));
        }

        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let message_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let magic_cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&bytes[8..20]);

        // Parsing optional attributes
        let mut mapped_address = None;
        let mut username = None;
        let mut message_integrity = None;
        let mut change_request = None;
        let mut error_code = None;
        let mut unknown_attributes = None;
        let mut realm = None;
        let mut nonce = None;
        let mut xor_mapped_address = None;
        let mut software = None;
        let mut alternate_server = None;
        let mut fingerprint = None;

        let mut offset = 20;
        while offset < bytes.len() {
            if offset + 4 > bytes.len() {
                return Err(StunBindingResponse::new_error(
                    context,
                    [0; 12],
                    ERROR_CODE_BAD_REQUEST,
                    "Attribute header is too short".to_string(),
                    settings.clone(),
                ));
            }

            let attribute_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let attribute_length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            let attribute_value = &bytes[offset + 4..offset + 4 + attribute_length as usize];

            match attribute_type {
                0x0001 => {
                    // MAPPED-ADDRESS
                    if attribute_value.len() == 8 {
                        let mut address = [0u8; 8];
                        address.copy_from_slice(attribute_value);
                        mapped_address = Some(address);
                    }
                }
                0x0003 => {
                    // CHANGE-REQUEST
                    if attribute_value.len() == 4 {
                        let mut request = [0u8; 4];
                        request.copy_from_slice(attribute_value);
                        change_request = Some(request);
                    }
                }
                0x0006 => {
                    // USERNAME
                    username = Some(String::from_utf8_lossy(attribute_value).to_string());
                }
                0x0008 => {
                    // MESSAGE-INTEGRITY
                    if attribute_value.len() == 20 {
                        let mut integrity = [0u8; 20];
                        integrity.copy_from_slice(attribute_value);
                        message_integrity = Some(integrity);
                    }
                }
                0x0009 => {
                    // ERROR-CODE
                    if attribute_value.len() >= 4 {
                        let code = u16::from_be_bytes([attribute_value[2], attribute_value[3]]);
                        let reason = String::from_utf8_lossy(&attribute_value[4..]).to_string();
                        error_code = Some((code, reason));
                    }
                }
                0x000A => {
                    // UNKNOWN-ATTRIBUTES
                    let mut attrs = Vec::new();
                    for chunk in attribute_value.chunks(2) {
                        if chunk.len() == 2 {
                            attrs.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                        }
                    }
                    unknown_attributes = Some(attrs);
                }
                0x0014 => {
                    // REALM
                    realm = Some(String::from_utf8_lossy(attribute_value).to_string());
                }
                0x0015 => {
                    // NONCE
                    nonce = Some(String::from_utf8_lossy(attribute_value).to_string());
                }
                0x0020 => {
                    // XOR-MAPPED-ADDRESS
                    if attribute_value.len() == 8 {
                        let mut address = [0u8; 8];
                        address.copy_from_slice(attribute_value);
                        xor_mapped_address = Some(address);
                    }
                }
                0x8022 => {
                    // SOFTWARE
                    software = Some(String::from_utf8_lossy(attribute_value).to_string());
                }
                0x8023 => {
                    // ALTERNATE-SERVER
                    if attribute_value.len() == 8 {
                        let mut address = [0u8; 8];
                        address.copy_from_slice(attribute_value);
                        alternate_server = Some(address);
                    }
                }
                0x8028 => {
                    // FINGERPRINT
                    if attribute_value.len() == 4 {
                        fingerprint = Some(u32::from_be_bytes([attribute_value[0], attribute_value[1], attribute_value[2], attribute_value[3]]) );
                    }
                }
                _ => {} // Ignore unknown attributes
            }

            offset += 4 + attribute_length as usize;
        }

        Ok(StunBindingRequest {
            message_type,
            message_length,
            magic_cookie,
            transaction_id,
            mapped_address,
            username,
            message_integrity,
            change_request,
            error_code,
            unknown_attributes,
            realm,
            nonce,
            xor_mapped_address,
            software,
            alternate_server,
            fingerprint,
            settings: settings.clone(),
            context: context.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use serial_test::serial;
    use slog::o;

    use crate::config::compliance_type::Compliance;

    use super::*;

    fn setup_logger() -> Logger {
        let drain = slog::Discard;
        Logger::root(drain, o!())
    }

    fn setup_context() -> Arc<Context> {
        Arc::new(Context {
            config: crate::config::Settings::new().unwrap(),
            logger: setup_logger(),
        })
    }

    fn setup_static_config() -> StaticConfig {
        StaticConfig {
            software_name: "test".to_string(),
            compliance_level: Compliance::RFC5389,
        }
    }

    fn get_transaction_id() -> [u8; 12] {
        let mut rng = rand::thread_rng();
        let mut transaction_id = [0u8; 12];
        rng.fill(&mut transaction_id);
        transaction_id
    }

    #[test]
    #[serial]
    fn test_stun_binding_request_initialization() {
        let context = setup_context();
        let static_config = setup_static_config();

        let transaction_id = get_transaction_id();

        let request = StunBindingRequest::new(&context, transaction_id, &static_config);

        assert_eq!(request.message_type, MSG_BINDING_REQUEST);
        assert_eq!(request.message_length, 0);
        assert_eq!(request.magic_cookie, MAGIC_COOKIE);
        assert_eq!(request.transaction_id, transaction_id);
        assert!(request.mapped_address.is_none());
        assert!(request.username.is_none());
        assert!(request.message_integrity.is_none());
        assert!(request.change_request.is_none());
        assert!(request.error_code.is_none());
        assert!(request.unknown_attributes.is_none());
        assert!(request.realm.is_none());
        assert!(request.nonce.is_none());
        assert!(request.xor_mapped_address.is_none());
        assert!(request.software.is_none());
        assert!(request.alternate_server.is_none());
        assert!(request.fingerprint.is_none());
        assert_eq!(request.settings.software_name, static_config.software_name);
        assert_eq!(
            request.settings.compliance_level.as_str(),
            static_config.compliance_level.as_str()
        );
        assert_eq!(Arc::strong_count(&request.context), 2);
    }

    #[test]
    #[serial]
    fn test_stun_binding_request_fingerprint() {
        let context = setup_context();
        let static_config = setup_static_config();

        let transaction_id = get_transaction_id();

        let mut request = StunBindingRequest::new(&context, transaction_id, &static_config);

        // Simulate setting the fingerprint attribute
        let fingerprint_value = 0x12345678;
        request.fingerprint = Some(fingerprint_value);

        // Validate the fingerprint
        assert_eq!(request.fingerprint, Some(fingerprint_value));
    }

    #[test]
    #[serial]
    fn test_deserializer() {

        let byte_array: [u8; 44] = [
            0x00, 0x01, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42,
            0xe5, 0x48, 0x69, 0x4c, 0x28, 0x25, 0x5c, 0xe8,
            0x55, 0x22, 0x6b, 0x3e, 0x80, 0x22, 0x00, 0x0c,
            0x53, 0x74, 0x75, 0x6e, 0x43, 0x6c, 0x69, 0x65,
            0x6e, 0x74, 0x00, 0x00, 0x80, 0x28, 0x00, 0x04,
            0x6a, 0xab, 0xe7, 0x2d
        ];
        
        let packet = StunBindingRequest::deserialize(&setup_context(), &setup_static_config(), &byte_array).unwrap();

        assert_eq!(packet.message_type, 1);
        assert_eq!(packet.message_length, 0x0018 );
        assert_eq!(packet.magic_cookie, 0x2112a442);
        assert_eq!(packet.transaction_id, [0xe5, 0x48, 0x69, 0x4c, 0x28, 0x25, 0x5c, 0xe8, 0x55, 0x22, 0x6b, 0x3e]);
        assert_eq!(packet.software.unwrap(), "StunClient\0\0");
        assert_eq!(packet.fingerprint.unwrap(), 0x6aabe72d);


    }

    // todo: add test we don't  break when no fingerprint is present


}
