/**
 * Various misc. utility functions
 */

/**
 * Encodes a byte slice into a hexadecimal string with each byte separated by a comma.
 * Usually used in debug/trace logs.
 *
 * @param buffer The byte slice to encode.
 * @return A `String` containing the hexadecimal representation of the byte slice,
 *         with each byte separated by a comma.
 *
 */
pub(crate) fn hex_encode_delimited(buffer: &[u8]) -> String {
    buffer
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join(",")
}
