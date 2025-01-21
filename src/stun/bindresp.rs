/**
 * A STUN Binding Response message and associated helper functions
 * See RFC 5389 Section 7.3 for details
 * https://datatracker.ietf.org/doc/html/rfc5389#section-7.3
 *
 */
use serde::Serialize;
use std::{
    io::{Cursor, Write},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use crate::{
    config::compliance_type::Compliance,
    stun::{
        attribute_type::ATTR_FINGERPRINT,
        message_type::{MSG_BINDING_ERROR_RESPONSE, MSG_BINDING_RESPONSE},
        HEADER_LENGTH, MAGIC_COOKIE,
    },
    Context,
};

use super::{
    attribute_type::{
        ATTR_ERROR_CODE, ATTR_MAPPED_ADDRESS, ATTR_SOFTWARE, ATTR_XOR_MAPPED_ADDRESS,
    },
    defs::{SizedAddress, StunAttribute},
    processor::StaticConfig,
    util::calculate_local_fingerprint,
};

/**
 * definition of a stun binding response. For more information see RFC 5389
 * https://datatracker.ietf.org/doc/html/rfc5389#page-10
 */

#[derive(Serialize, Debug)]
pub struct StunBindingResponse {
    pub message_type: u16,
    pub message_length: u16,
    pub magic_cookie: u32,
    pub transaction_id: [u8; 12],
    pub mapped_address: Option<SizedAddress>,
    pub username: Option<String>,
    pub message_integrity: Option<[u8; 20]>,
    pub error_code: Option<(u16, String)>,
    pub unknown_attributes: Option<Vec<u16>>,
    pub realm: Option<String>,
    pub nonce: Option<String>,
    pub xor_mapped_address: Option<SizedAddress>,
    pub software: Option<String>,
    pub alternate_server: Option<[u8; 8]>,
    pub fingerprint: Option<u32>,

    #[serde(skip_serializing)]
    settings: StaticConfig,
    #[serde(skip_serializing)]
    context: Arc<Context>,
}

impl StunBindingResponse {
    /**
     * Create a new empty response
     *
     * @param tid The transaction ID, which must be the same as the incoming request
     */
    pub fn new(context: &Arc<Context>, tid: [u8; 12], static_settings: StaticConfig) -> Self {
        StunBindingResponse {
            message_type: MSG_BINDING_RESPONSE,
            message_length: 0,
            magic_cookie: MAGIC_COOKIE,
            transaction_id: tid,
            mapped_address: None,
            username: None,
            message_integrity: None,
            error_code: None,
            unknown_attributes: None,
            realm: None,
            nonce: None,
            xor_mapped_address: None,
            software: Some(static_settings.software_name.clone()),
            alternate_server: None,
            fingerprint: Some(0),
            //
            settings: static_settings.clone(),
            context: Arc::clone(context),
        }
    }

    /**
     * create a new error response
     *
     * @param tid The transaction ID, which must be the same as the incoming request
     * @param error_code The error code to return
     * @param error_reason The reason for the error (human readable)
     */
    pub fn new_error(
        context: &Arc<Context>,
        tid: [u8; 12],
        error_code: u16,
        error_reason: String,
        static_settings: StaticConfig,
    ) -> Self {
        StunBindingResponse {
            message_type: MSG_BINDING_ERROR_RESPONSE,
            message_length: 0,
            magic_cookie: MAGIC_COOKIE,
            transaction_id: tid,
            mapped_address: None,
            username: None,
            message_integrity: None,
            error_code: Some((error_code, error_reason)),
            unknown_attributes: None,
            realm: None,
            nonce: None,
            xor_mapped_address: None,
            software: Some(static_settings.software_name.clone()),
            alternate_server: None,
            fingerprint: Some(0),

            //
            settings: static_settings.clone(),
            context: Arc::clone(context),
        }
    }

    // write stun header (20 bytes)
    fn write_header(
        &self,
        cursor: &mut Cursor<&mut [u8]>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        cursor.write_all(&self.message_type.to_be_bytes())?;
        cursor.write_all(&self.message_length.to_be_bytes())?;
        cursor.write_all(&self.magic_cookie.to_be_bytes())?;
        cursor.write_all(&self.transaction_id)?;
        Ok(())
    }

    /**
     * Write an attribute to the buffer
     */
    fn write_attribute<T: StunAttribute>(
        attr_id: u16,
        cursor: &mut Cursor<&mut [u8]>,
        addr: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        cursor.write_all(&attr_id.to_be_bytes())?;
        cursor.write_all(&addr.attr_length().to_be_bytes())?;
        addr.write_to(cursor)?;
        Ok(())
    }

    /**
     * serialize the response into the provided buffer
     *
     * @param output The buffer to write the response into
     * @return The number of bytes written
     *  
     */
    pub fn serialize(&self, output: &mut [u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let mut cursor = Cursor::new(output);
        self.write_header(&mut cursor)?;

        let start_pos = cursor.position();

        // write attributes
        if let Some(ref addr) = self.xor_mapped_address {
            Self::write_attribute(ATTR_XOR_MAPPED_ADDRESS, &mut cursor, addr)?;
        }

        if let Some(ref addr) = self.mapped_address {
            Self::write_attribute(ATTR_MAPPED_ADDRESS, &mut cursor, addr)?;
        }

        if let Some(ref sw) = &self.software {
            let sw_attr = sw.as_bytes();
            cursor.write_all(&ATTR_SOFTWARE.to_be_bytes())?;

            let padding = (4 - (sw_attr.len() % 4)) % 4;

            cursor.write_all(&(sw_attr.len() as u16).to_be_bytes())?;

            cursor.write_all(sw_attr)?;
            cursor.write_all(&vec![0u8; padding])?;
        }

        if let Some((code, reason)) = &self.error_code {
            let reason_bytes = reason.as_bytes();
            let total_length = (reason_bytes.len() + 4) as u16; // 4 for class, reserved, and number

            cursor.write_all(&ATTR_ERROR_CODE.to_be_bytes())?;
            cursor.write_all(&total_length.to_be_bytes())?;

            cursor.write_all(&[0, (code / 100) as u8, (code % 100) as u8, 0])?;

            cursor.write_all(reason_bytes)?;

            // Padding calculation and addition
            let padding = (4 - (reason_bytes.len() % 4)) % 4;
            if padding > 0 {
                cursor.write_all(&[0u8; 4][..padding])?;
            }
        }

        // position is here plus additional 8 bytes for fingerprint
        let message_length = (cursor.position() - start_pos + 8 as u64) as u16;

        // Update message length
        cursor.set_position(2);
        cursor.write_all(&message_length.to_be_bytes())?;
        cursor.set_position(message_length as u64 + 20 - 8);

        // Calculate and write fingerprint
        let end_pos = message_length as usize + HEADER_LENGTH as usize;
        let underlying_buffer = cursor.get_ref();

        let crc32 = calculate_local_fingerprint(&underlying_buffer[..end_pos]);
        cursor.write_all(&ATTR_FINGERPRINT.to_be_bytes())?;
        cursor.write_all(&4u16.to_be_bytes())?;
        cursor.write_all(&crc32.to_be_bytes())?;

        Ok(message_length as usize + HEADER_LENGTH as usize)
    }

    /**
     * Update the response with fields that are calculated
     */
    pub fn update(
        &mut self,
        client_address: Option<SocketAddr>,
        transaction_id: &[u8; 12],
    ) -> Result<(), StunBindingResponse> {
        if self.message_type != MSG_BINDING_RESPONSE {
            return Ok(());
        }

        let addr = match client_address {
            Some(addr) => addr,
            None => {
                return Err(StunBindingResponse::new_error(
                    &self.context,
                    self.transaction_id,
                    500,
                    "Cannot determine IP".into(),
                    self.settings.clone(),
                ));
            }
        };

        match addr.ip() {
            IpAddr::V4(ipv4) => {
                let ip: [u8; 4] = ipv4.octets();
                self.xor_mapped_address = self.get_mapped_address_v4(ip, addr.port(), true)?;

                if self.settings.compliance_level == Compliance::Relaxed {
                    self.mapped_address = self.get_mapped_address_v4(ip, addr.port(), false)?;
                }
            }
            IpAddr::V6(ipv6) => {
                let ip: [u8; 16] = ipv6.octets();
                self.xor_mapped_address =
                    self.get_mapped_address_v6(ip, addr.port(), transaction_id, true)?;
                if self.settings.compliance_level == Compliance::Relaxed {
                    self.mapped_address =
                        self.get_mapped_address_v6(ip, addr.port(), &transaction_id, false)?;
                }
            }
        }

        Ok(())
    }

    /**
     * Set the v4 address (note that we use XOR_MAPPED_ADDRESS not MAPPED_ADDRESS)
     *
     * @param ip The IPv4 address, as bytes
     * @param port The port as u16
     */
    fn get_mapped_address_v4(
        &mut self,
        ip: [u8; 4],
        port: u16,
        use_xor: bool,
    ) -> Result<Option<SizedAddress>, StunBindingResponse> {
        let mut addr = [0u8; 8];
        let magic_bytes = MAGIC_COOKIE.to_be_bytes();

        // Set up family and port
        addr[1] = 0x01; // Family for IPv4
        let x_port = if use_xor {
            port ^ ((MAGIC_COOKIE >> 16) as u16)
        } else {
            port
        };

        addr[2] = (x_port >> 8) as u8; // High byte of the port
        addr[3] = x_port as u8; // Low byte of the port

        // XOR IP if required
        for i in 0..4 {
            addr[4 + i] = if use_xor {
                ip[i] ^ magic_bytes[i]
            } else {
                ip[i]
            };
        }

        Ok(Some(SizedAddress::Ipv4(addr)))
    }

    /**
     * Set the v6 address (note that we use XOR_MAPPED_ADDRESS not MAPPED_ADDRESS)
     *
     * @param ip The IPv6 address, as bytes
     * @param port The port as u16
     */
    fn get_mapped_address_v6(
        &mut self,
        ip: [u8; 16],
        port: u16,
        transaction_id: &[u8; 12],
        use_xor: bool,
    ) -> Result<Option<SizedAddress>, StunBindingResponse> {
        let mut addr = [0u8; 20];
        //let magic_bytes = MAGIC_COOKIE.to_be_bytes();

        // Set up family and port
        addr[1] = 0x02; // Family for IPv6
        let x_port = if use_xor {
            port ^ ((MAGIC_COOKIE >> 16) as u16)
        } else {
            port
        };

        addr[2] = (x_port >> 8) as u8; // High byte of the port
        addr[3] = x_port as u8; // Low byte of the port

        // XOR IP if required
        if use_xor {
            addr[4] = ip[0] ^ 0x21;
            addr[5] = ip[1] ^ 0x12;
            addr[6] = ip[2] ^ 0xA4;
            addr[7] = ip[3] ^ 0x42;

            for i in 0..12 {
                addr[8 + i] = ip[4 + i] ^ transaction_id[i];
            }
        } else {
            addr[4..20].copy_from_slice(&ip);
        }

        Ok(Some(SizedAddress::Ipv6(addr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::stun::processor::StaticConfig;
    use crate::Context;
    use std::sync::Arc;

    use serial_test::serial;
    use slog::{o, Logger};

    use crate::config::compliance_type::Compliance;

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
            software_name: "test1".to_string(),
            compliance_level: Compliance::RFC5389,
        }
    }

    #[test]
    #[serial]
    fn test_serialize_non_error() {
        let transaction_id = [
            0xcc, 0x96, 0x2d, 0x59, 0x2e, 0x49, 0x85, 0x1e, 0x5b, 0x4f, 0x2f, 0x20,
        ];
        let expected = [
            1, 1, 0, 20, 33, 18, 164, 66, 204, 150, 45, 89, 46, 73, 133, 30, 91, 79, 47, 32, 128,
            34, 0, 5, 116, 101, 115, 116, 49, 0, 0, 0, 128, 40, 0, 4, 115, 145, 44, 249,
        ];

        let packet =
            StunBindingResponse::new(&setup_context(), transaction_id, setup_static_config());

        let mut buffer = [0u8; 512];

        let bytes = packet.serialize(&mut buffer);

        assert!(bytes.is_ok());
        let len = bytes.unwrap();

        assert_eq!(len, 40);
        assert_eq!(expected, &buffer[..len]);
    }

    #[test]
    #[serial]
    fn test_serialize_error() {
        let transaction_id = [
            0xcc, 0x96, 0x2d, 0x59, 0x2e, 0x49, 0x85, 0x1e, 0x5b, 0x4f, 0x2f, 0x20,
        ];
        let expected = [
            1, 17, 0, 32, 33, 18, 164, 66, 204, 150, 45, 89, 46, 73, 133, 30, 91, 79, 47, 32, 128,
            34, 0, 5, 116, 101, 115, 116, 49, 0, 0, 0, 0, 9, 0, 8, 0, 0, 99, 0, 84, 69, 83, 84,
            128, 40, 0, 4, 27, 221, 194, 232,
        ];

        let packet = StunBindingResponse::new_error(
            &setup_context(),
            transaction_id,
            99,
            "TEST".to_string(),
            setup_static_config(),
        );

        let mut buffer = [0u8; 512];

        let bytes = packet.serialize(&mut buffer);

        assert!(&bytes.is_ok());

        let len = bytes.unwrap();
        assert_eq!(len, 52);
        assert_eq!(expected, &buffer[..len]);
        
    }

    #[test]
    #[serial]
    fn test_get_xor_mapped_address_v4() {
        let transaction_id = [
            0xcc, 0x96, 0x2d, 0x59, 0x2e, 0x49, 0x85, 0x1e, 0x5b, 0x4f, 0x2f, 0x20,
        ];
        let mut packet =
            StunBindingResponse::new(&setup_context(), transaction_id, setup_static_config());

        let ip_address = "128.15.30.255";
        let port: u16 = 31337;

        let ip_addr: std::net::Ipv4Addr = ip_address.parse().expect("Invalid IP address");
        let ip_bytes = ip_addr.octets();

        let mapped = packet.get_mapped_address_v4(ip_bytes, port, true).unwrap();
        assert!(&mapped.is_some());

        let binding = mapped.unwrap();
        let attr_value = binding.as_ref();
        assert_eq!(attr_value.len(), 8);

        let xor_ip = &attr_value[4..8];

        // get ip and port
        let decoded_port = u16::from_be_bytes([attr_value[2], attr_value[3]]) ^ 0x2112;
        let xor_ip = [
            xor_ip[0] ^ MAGIC_COOKIE.to_be_bytes()[0],
            xor_ip[1] ^ MAGIC_COOKIE.to_be_bytes()[1],
            xor_ip[2] ^ MAGIC_COOKIE.to_be_bytes()[2],
            xor_ip[3] ^ MAGIC_COOKIE.to_be_bytes()[3],
        ];

        // convert ip to string
        let decoded_addr =
            std::net::Ipv4Addr::new(xor_ip[0], xor_ip[1], xor_ip[2], xor_ip[3]).to_string();

        assert_eq!(decoded_port, port);
        assert_eq!(decoded_addr, ip_address);
    }

    #[test]
    #[serial]
    fn test_get_mapped_address_v4() {
        let transaction_id = [
            0xcc, 0x96, 0x2d, 0x59, 0x2e, 0x49, 0x85, 0x1e, 0x5b, 0x4f, 0x2f, 0x20,
        ];
        let mut packet =
            StunBindingResponse::new(&setup_context(), transaction_id, setup_static_config());

        let ip_address = "128.15.30.255";
        let port: u16 = 31337;

        let ip_addr: std::net::Ipv4Addr = ip_address.parse().expect("Invalid IP address");
        let ip_bytes = ip_addr.octets();

        let mapped = packet.get_mapped_address_v4(ip_bytes, port, false).unwrap();
        assert!(&mapped.is_some());

        let binding = mapped.unwrap();
        let attr_value = binding.as_ref();
        assert_eq!(attr_value.len(), 8);

        let xor_ip = &attr_value[4..8];

        // get ip and port
        let decoded_port = u16::from_be_bytes([attr_value[2], attr_value[3]]);
        let xor_ip = [xor_ip[0], xor_ip[1], xor_ip[2], xor_ip[3]];

        // convert ip to string
        let decoded_addr =
            std::net::Ipv4Addr::new(xor_ip[0], xor_ip[1], xor_ip[2], xor_ip[3]).to_string();

        assert_eq!(decoded_port, port);
        assert_eq!(decoded_addr, ip_address);
    }

    #[test]
    #[serial]
    fn test_get_xor_mapped_address_v6() {
        let transaction_id = [
            0xcc, 0x96, 0x2d, 0x59, 0x2e, 0x49, 0x85, 0x1e, 0x5b, 0x4f, 0x2f, 0x20,
        ];
        let mut packet =
            StunBindingResponse::new(&setup_context(), transaction_id, setup_static_config());

        let ip_address = "2001:db8::ff00:42:8329";
        let port: u16 = 31337;

        let ip_addr: std::net::Ipv6Addr = ip_address.parse().expect("Invalid IP address");
        let ip_bytes = ip_addr.octets();

        let mapped = packet
            .get_mapped_address_v6(ip_bytes, port, &transaction_id, true)
            .unwrap();
        assert!(&mapped.is_some());

        let binding = mapped.unwrap();
        let attr_value = binding.as_ref();
        assert_eq!(attr_value.len(), 20);

        let xor_ip = &attr_value[4..20];

        // get ip and port
        let decoded_port = u16::from_be_bytes([attr_value[2], attr_value[3]]) ^ 0x2112;
        let mut decoded_ip = [0u8; 16];
        decoded_ip[0] = xor_ip[0] ^ 0x21;
        decoded_ip[1] = xor_ip[1] ^ 0x12;
        decoded_ip[2] = xor_ip[2] ^ 0xA4;
        decoded_ip[3] = xor_ip[3] ^ 0x42;

        for i in 0..12 {
            decoded_ip[i + 4] = xor_ip[i + 4] ^ transaction_id[i];
        }

        // convert ip to string
        let decoded_addr = std::net::Ipv6Addr::from(decoded_ip).to_string();

        assert_eq!(decoded_port, port);
        assert_eq!(decoded_addr, ip_address);
    }

    #[test]
    #[serial]
    fn test_get_mapped_address_v6() {
        let transaction_id = [
            0xcc, 0x96, 0x2d, 0x59, 0x2e, 0x49, 0x85, 0x1e, 0x5b, 0x4f, 0x2f, 0x20,
        ];
        let mut packet =
            StunBindingResponse::new(&setup_context(), transaction_id, setup_static_config());

        let ip_address = "2001:db8::ff00:42:8329";
        let port: u16 = 31337;

        let ip_addr: std::net::Ipv6Addr = ip_address.parse().expect("Invalid IP address");
        let ip_bytes = ip_addr.octets();

        let mapped = packet
            .get_mapped_address_v6(ip_bytes, port, &transaction_id, false)
            .unwrap();
        assert!(&mapped.is_some());

        let binding = mapped.unwrap();
        let attr_value = binding.as_ref();
        assert_eq!(attr_value.len(), 20);

        let xor_ip = &attr_value[4..20];

        // get ip and port
        let decoded_port = u16::from_be_bytes([attr_value[2], attr_value[3]]);
        let mut decoded_ip = [0u8; 16];
        decoded_ip.copy_from_slice(xor_ip);

        // convert ip to string
        let decoded_addr = std::net::Ipv6Addr::from(decoded_ip).to_string();

        assert_eq!(decoded_port, port);
        assert_eq!(decoded_addr, ip_address);
    }
}
