/**
 * The STUN-specific module, this file contains various constant definitions
 */

pub mod processor;
mod bindreq;
mod bindresp;
mod util;
mod defs;

/// length of a STUN header is 20 bytes
pub(crate) const HEADER_LENGTH: u16 = 20;

/// This value is included in STUN messages to help differentiate them from other types of network traffic and to
/// ensure that the messages are processed correctly by STUN servers and clients. The Magic Cookie value is 0x2112A442
pub(crate) const MAGIC_COOKIE: u32 = 0x2112A442;



// Message Types
#[allow(dead_code)]
pub(crate) mod message_type {
    /// A STUN client sends a Binding Request to a STUN server. The request typically contains attributes like
    /// USERNAME, NONCE, and MESSAGE-INTEGRITY for authentication and security purposes.
    pub const MSG_BINDING_REQUEST: u16 = 0x0001;

    /// This message to provide the client with its public IP address and port information, which is essential for
    /// establishing peer-to-peer connections across NATs and firewalls.
    pub const MSG_BINDING_RESPONSE: u16 = 0x0101;

    /// This message informs the client that the Binding Request could not be processed due to an error and to provide
    /// details about the nature of the error.
    pub const MSG_BINDING_ERROR_RESPONSE: u16 = 0x0111;

    /// In this message, the client sends a Shared Secret Request to the server, which responds with a
    /// Shared Secret Response containing the shared secret key.
    pub const MSG_SHARED_SECRET_REQUEST: u16 = 0x0002;

    /// This message is the response from the server to a SHARED_SECRET_REQUEST. The server responds with a response that
    /// contains a username, password, and possibly other attributes.
    pub const MSG_SHARED_SECRET_RESPONSE: u16 = 0x0102;

    /// This message notifies the client that the Shared Secret Request could not be processed due to an error, and
    /// provides information about the type of error that occurred.
    pub const MSG_SHARED_SECRET_ERROR_RESPONSE: u16 = 0x0112;
}


/*
   Comprehension-required range (0x0000-0x7FFF):
     0x0000: (Reserved)
     0x0001: MAPPED-ADDRESS
     0x0002: (Reserved; was RESPONSE-ADDRESS)
     0x0003: (Reserved; was CHANGE-ADDRESS)
     0x0004: (Reserved; was SOURCE-ADDRESS)
     0x0005: (Reserved; was CHANGED-ADDRESS)
     0x0006: USERNAME
     0x0007: (Reserved; was PASSWORD)
     0x0008: MESSAGE-INTEGRITY
     0x0009: ERROR-CODE
     0x000A: UNKNOWN-ATTRIBUTES
     0x000B: (Reserved; was REFLECTED-FROM)
     0x0014: REALM
     0x0015: NONCE
     0x0020: XOR-MAPPED-ADDRESS

   Comprehension-optional range (0x8000-0xFFFF)
     0x8022: SOFTWARE
     0x8023: ALTERNATE-SERVER
     0x8028: FINGERPRINT
*/


// Attribute Types
#[allow(dead_code)]
pub(crate) mod attribute_type {
    /// This attribute specifies an IP address and port, which are included in the Binding Response. It identifies the
    /// source IP address and port observed by the server in the Binding Request from the client, representing the
    /// public IP address and port of the STUN client, accessible from the internet.
    pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

    /// This optional attribute, usually found in the Binding Request from the STUN client to the STUN server, specifies
    /// the IP address and port where the Binding Response should be sent. If omitted, the Binding Response defaults to
    /// the source IP address and port of the Binding Request, corresponding to attribute 0x0001: MAPPED-ADDRESS.
    pub const ATTR_RESPONSE_ADDRESS: u16 = 0x0002;

    /// This optional attribute, exclusive to the Binding Request, contains two flags: "change IP" and "change Port." These
    /// flags control the IP address and port used for the response. They help determine if the client is behind a
    /// restricted cone NAT or a restricted port cone NAT by instructing the server to send the Binding Responses
    /// from a different source IP address and port.
    pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;

    /// This attribute is commonly found in Binding Responses and specifies the source IP address and port where the
    /// request originated. This corresponds to the IP address of the client's machine (typically an internal private
    /// IP address). It is particularly useful for the STUN server in detecting double NAT configurations.
    pub const ATTR_SOURCE_ADDRESS: u16 = 0x0004;

    /// This attribute is usually present in Binding Responses; it informs the client of the source IP address and port
    /// that would be used if the client requested the "change IP" and "change port" behaviour. 
    pub const ATTR_CHANGED_ADDRESS: u16 = 0x0005;

    /// The USERNAME attribute in a STUN (Session Traversal Utilities for NAT) packet is used to provide a credential
    /// that can be used to authenticate the client to the server. This attribute helps in validating that the request
    /// or response is from an authorized entity.
    pub const ATTR_USERNAME: u16 = 0x0006;

    // This optional attribute appears only in Shared Secret Responses, alongside the USERNAME attribute.
    /// The PASSWORD attribute's value is of variable length and serves as a shared secret between the STUN
    /// server and the STUN client.
    pub const ATTR_PASSWORD: u16 = 0x0007;

    /// This attribute must be the last attribute in a STUN message and can be present in both Binding Request and
    /// Binding Response. It contains HMAC-SHA1 of the STUN message.
    pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;

    /// This attribute is present in the Binding Error Response and Shared Secret Error Response only. It indicates that
    /// an error has occurred and indicates also the type of error which has occurred. It contains a
    /// numerical value in the range of 100 to 699; which is the error code and also a textual reason
    /// phrase encoded in UTF-8 describing the error code, which is meant for the client.
    pub const ATTR_ERROR_CODE: u16 = 0x0009;

    /// This attribute appears in Binding Error Responses or Shared Secret Error Responses when the error code is 420.
    /// It signifies that some attributes in the client's Request are unknown and not understood by the server.
    pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;

    /// This attribute is included exclusively in the Binding Response and serves to provide traceability, preventing the STUN server
    /// from being exploited in a denial of service attack. It contains the source IP address, indicating where the request
    /// originated from, specifically the IP address of the STUN client.
    pub const ATTR_REFLECTED_FROM: u16 = 0x000B;

    /// The REALM attribute provides a realm, or domain, within which the username and password are valid. It is used in conjunction
    /// with other attributes like USERNAME and MESSAGE-INTEGRITY to authenticate the client. This is useful when multiple domains
    /// are involved in authentication. REALM is used in conjuction with USERNAME.
    pub const ATTR_REALM: u16 = 0x0014;

    /// The NONCE attribute ensures that each STUN request is unique and prevents replay attacks by requiring the client to
    /// generate a new request for each interaction.
    /// When a client sends a STUN request, the server may respond with a challenge that includes a NONCE attribute. The client must
    /// then resend the request with the NONCE included, along with the appropriate authentication attributes (USERNAME and MESSAGE-INTEGRITY)
    pub const ATTR_NONCE: u16 = 0x0015;

    /// This attribute reveals the public IP address and port of the STUN client as observed by the STUN server, but does so in a manner that m
    /// akes it harder for intermediaries to tamper with or eavesdrop on the IP address and port information.
    /// When the server responds with the XOR_MAPPED_ADDRESS attribute, it typically does not include the MAPPED_ADDRESS attribute, but if both are
    /// included XOR_MAPPED_ADDRESS takes precedence.
    pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

    /// This attribute  provides a human-readable description of the software, including its name and version. This can be useful for
    /// debugging, diagnostics, or compatibility checks.
    pub const ATTR_SOFTWARE: u16 = 0x8022;

    /// This attribute redirects the client to a different STUN server for subsequent requests.
    pub const ATTR_ALTERNATE_SERVER: u16 = 0x8023;

    /// This attribute provides a CRC32 (Cyclic Redundancy Check) value of the STUN message, ensuring that the message has not been
    /// altered during transmission. The CRC32 is calculated on the entire STUN message, then the CRC32 value is XORed with the constant
    /// 0x5354554E (the ASCII representation of "STUN").
    pub const ATTR_FINGERPRINT: u16 = 0x8028;
}

// Error Codes
#[allow(dead_code)]
pub(crate) mod error_code {
    /// Bad Request (400)
    pub const ERROR_CODE_BAD_REQUEST: u16 = 400;

    /// Unauthorized (401)
    pub const ERROR_CODE_UNAUTHORIZED: u16 = 401;

    /// Unknown Attribute (402)
    pub const ERROR_CODE_UNKNOWN_ATTRIBUTE: u16 = 402;

    /// Allocation Mismatch (403)
    pub const ERROR_CODE_ALLOCATION_MISMATCH: u16 = 403;

    /// Unsupported Critical Attribute (404)
    pub const ERROR_CODE_UNSUPPORTED_CRITICAL_ATTRIBUTE: u16 = 404;

    /// Allocation Quota Exceeded (405)
    pub const ERROR_CODE_ALLOCATION_QUOTA_EXCEEDED: u16 = 405;

    /// Usage Quota Exceeded (406)
    pub const ERROR_CODE_USAGE_QUOTA_EXCEEDED: u16 = 406;

    /// Unsupported Realm (408)
    pub const ERROR_CODE_UNSUPPORTED_REALM: u16 = 408;

    /// Unsupported Transport Protocol (409)
    pub const ERROR_CODE_UNSUPPORTED_TRANSPORT_PROTOCOL: u16 = 409;

    /// Stale Nonce (420)
    pub const ERROR_CODE_STALE_NONCE: u16 = 420;

    /// Server Error (500)
    pub const ERROR_CODE_SERVER_ERROR: u16 = 500;

    /// Server Timeout (504)
    pub const ERROR_CODE_SERVER_TIMEOUT: u16 = 504;

    // Reserved for future use
    // pub const ERROR_CODE_RESERVED_407: u16 = 407;
    // pub const ERROR_CODE_RESERVED_410: u16 = 410;
    // pub const ERROR_CODE_RESERVED_430: u16 = 430;
    // pub const ERROR_CODE_RESERVED_431: u16 = 431;
    // pub const ERROR_CODE_RESERVED_432: u16 = 432;
    // pub const ERROR_CODE_RESERVED_433: u16 = 433;
    // pub const ERROR_CODE_RESERVED_501: u16 = 501;
    // pub const ERROR_CODE_RESERVED_502: u16 = 502;
    // pub const ERROR_CODE_RESERVED_503: u16 = 503;
    // pub const ERROR_CODE_RESERVED_505: u16 = 505;
    // pub const ERROR_CODE_RESERVED_506: u16 = 506;
    // pub const ERROR_CODE_RESERVED_507: u16 = 507;
    // pub const ERROR_CODE_RESERVED_508: u16 = 508;
    // pub const ERROR_CODE_RESERVED_509: u16 = 509;
    // pub const ERROR_CODE_RESERVED_510: u16 = 510;
    // pub const ERROR_CODE_RESERVED_511: u16 = 511;
    // pub const ERROR_CODE_RESERVED_520: u16 = 520;
    // pub const ERROR_CODE_RESERVED_521: u16 = 521;
    // pub const ERROR_CODE_RESERVED_530: u16 = 530;
    // pub const ERROR_CODE_RESERVED_540: u16 = 540;
}
