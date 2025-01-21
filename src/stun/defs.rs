use std::io::{Cursor, Write};

use serde::Serialize;

use super::attribute_type::ATTR_XOR_MAPPED_ADDRESS;

/**
 * A trait for STUN attributes
 */
pub(crate) trait StunAttribute {
    fn write_to(&self, cursor: &mut Cursor<&mut [u8]>) -> Result<(), Box<dyn std::error::Error>>;
    fn attr_length(&self) -> u16;
}

/**
 * STUN addresses may be ipv4 or ipv6, and each has a different storage requirement
 */
#[derive(Serialize, Debug)]
pub enum SizedAddress {
    Ipv4([u8; 8]),
    Ipv6([u8; 20]),
}

impl SizedAddress {
    /**
     * Get the length of the address
     */
    pub fn len(&self) -> usize {
        match self {
            SizedAddress::Ipv4(_) => 8,
            SizedAddress::Ipv6(_) => 20,
        }
    }
}

impl AsRef<[u8]> for SizedAddress {
    /**
     * Get a reference to the address
     */
    fn as_ref(&self) -> &[u8] {
        match self {
            SizedAddress::Ipv4(addr) => addr,
            SizedAddress::Ipv6(addr) => addr,
        }
    }
}

impl StunAttribute for SizedAddress {
    /**
     * Write the address to a buffer
     */
    fn write_to(&self, cursor: &mut Cursor<&mut [u8]>) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            SizedAddress::Ipv4(addr) => cursor.write_all(addr)?,
            SizedAddress::Ipv6(addr) => cursor.write_all(addr)?,
        }
        Ok(())
    }


    /**
     * Get the attribute length
     */
    fn attr_length(&self) -> u16 {
        self.len() as u16
    }
}
