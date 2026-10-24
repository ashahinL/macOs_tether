//! RNDIS control and data messages. Every multi-byte field is little-endian.
//!
//! `InformationBufferOffset` and `DataOffset` count from the field's own base
//! in the Microsoft layout: the `RequestID` field for query and set, and the
//! `DataOffset` field for a data packet. Both of those fields sit at byte 8.

/// Receive size we advertise in `REMOTE_NDIS_INITIALIZE_MSG`.
pub const OUR_MAX_TRANSFER_SIZE: u32 = 32_768;

pub const MSG_PACKET: u32 = 0x0000_0001;
pub const MSG_INIT: u32 = 0x0000_0002;
pub const MSG_QUERY: u32 = 0x0000_0004;
pub const MSG_SET: u32 = 0x0000_0005;
pub const MSG_KEEPALIVE: u32 = 0x0000_0008;

/// Fixed header of `REMOTE_NDIS_PACKET_MSG`, before the Ethernet frame.
pub const DATA_HEADER_LEN: usize = 44;

/// `DataOffset` value that places the frame immediately after the header.
const DATA_OFFSET: u32 = 36;

/// Query and set information starts just after their 28-byte header.
/// 28 - 8 = 20 bytes from `RequestID`.
const OID_INFO_OFFSET: u32 = 20;

const OID_HEADER_LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RndisError {
    ShortBuffer,
    BadLength,
    BadDataOffset,
    BadType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Init {
        request_id: u32,
        major: u32,
        minor: u32,
        max_transfer_size: u32,
    },
    Query {
        request_id: u32,
        oid: u32,
        data: Vec<u8>,
    },
    Set {
        request_id: u32,
        oid: u32,
        data: Vec<u8>,
    },
    Keepalive {
        request_id: u32,
    },
    Data {
        frame: Vec<u8>,
    },
}

pub fn build_init(request_id: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, MSG_INIT);
    push_u32(&mut buf, 24);
    push_u32(&mut buf, request_id);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, OUR_MAX_TRANSFER_SIZE);
    buf
}

pub fn build_query(request_id: u32, oid: u32, data: &[u8]) -> Vec<u8> {
    build_oid(MSG_QUERY, request_id, oid, data)
}

pub fn build_set(request_id: u32, oid: u32, data: &[u8]) -> Vec<u8> {
    build_oid(MSG_SET, request_id, oid, data)
}

pub fn build_keepalive(request_id: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    push_u32(&mut buf, MSG_KEEPALIVE);
    push_u32(&mut buf, 12);
    push_u32(&mut buf, request_id);
    buf
}

pub fn build_data(frame: &[u8]) -> Vec<u8> {
    let msg_len = DATA_HEADER_LEN + frame.len();
    let mut buf = vec![0u8; msg_len];
    write_u32(&mut buf, 0, MSG_PACKET);
    write_u32(&mut buf, 4, msg_len as u32);
    write_u32(&mut buf, 8, DATA_OFFSET);
    write_u32(&mut buf, 12, frame.len() as u32);
    buf[DATA_HEADER_LEN..].copy_from_slice(frame);
    buf
}

/// Wrap `frame` as one OUT data packet no larger than `max_transfer_size`.
/// The RNDIS header counts toward that cap. A frame that does not fit is cut
/// so the packet length equals the cap.
pub fn cap_out_packet(frame: &[u8], max_transfer_size: u32) -> Result<Vec<u8>, RndisError> {
    let max = max_transfer_size as usize;
    if max < DATA_HEADER_LEN {
        return Err(RndisError::BadLength);
    }
    let room = max - DATA_HEADER_LEN;
    let take = frame.len().min(room);
    Ok(build_data(&frame[..take]))
}

/// Every complete message in `buf`. A short header, a length past the buffer,
/// or a payload offset outside its message is an error.
pub fn unwrap_messages(buf: &[u8]) -> Result<Vec<Message>, RndisError> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        if rest.len() < 8 {
            return Err(RndisError::ShortBuffer);
        }
        let msg_type = read_u32(rest, 0);
        let msg_len = read_u32(rest, 4) as usize;
        if msg_len < 8 || msg_len > rest.len() {
            return Err(RndisError::BadLength);
        }
        out.push(decode(&rest[..msg_len], msg_type)?);
        rest = &rest[msg_len..];
    }
    Ok(out)
}

fn build_oid(msg_type: u32, request_id: u32, oid: u32, data: &[u8]) -> Vec<u8> {
    let msg_len = OID_HEADER_LEN + data.len();
    let mut buf = Vec::with_capacity(msg_len);
    push_u32(&mut buf, msg_type);
    push_u32(&mut buf, msg_len as u32);
    push_u32(&mut buf, request_id);
    push_u32(&mut buf, oid);
    push_u32(&mut buf, data.len() as u32);
    push_u32(&mut buf, OID_INFO_OFFSET);
    push_u32(&mut buf, 0);
    buf.extend_from_slice(data);
    buf
}

fn decode(buf: &[u8], msg_type: u32) -> Result<Message, RndisError> {
    let msg_len = buf.len();
    match msg_type {
        MSG_INIT => {
            if msg_len < 24 {
                return Err(RndisError::BadLength);
            }
            Ok(Message::Init {
                request_id: read_u32(buf, 8),
                major: read_u32(buf, 12),
                minor: read_u32(buf, 16),
                max_transfer_size: read_u32(buf, 20),
            })
        }
        MSG_QUERY | MSG_SET => {
            if msg_len < OID_HEADER_LEN {
                return Err(RndisError::BadLength);
            }
            let data = ranged(
                buf,
                8,
                read_u32(buf, 20) as usize,
                read_u32(buf, 16) as usize,
            )?;
            let request_id = read_u32(buf, 8);
            let oid = read_u32(buf, 12);
            if msg_type == MSG_QUERY {
                Ok(Message::Query {
                    request_id,
                    oid,
                    data,
                })
            } else {
                Ok(Message::Set {
                    request_id,
                    oid,
                    data,
                })
            }
        }
        MSG_KEEPALIVE => {
            if msg_len < 12 {
                return Err(RndisError::BadLength);
            }
            Ok(Message::Keepalive {
                request_id: read_u32(buf, 8),
            })
        }
        MSG_PACKET => {
            if msg_len < DATA_HEADER_LEN {
                return Err(RndisError::BadLength);
            }
            let frame = ranged(
                buf,
                8,
                read_u32(buf, 8) as usize,
                read_u32(buf, 12) as usize,
            )?;
            Ok(Message::Data { frame })
        }
        _ => Err(RndisError::BadType),
    }
}

/// `rel` is an offset from `base`. The bytes must lie inside this message.
fn ranged(buf: &[u8], base: usize, rel: usize, len: usize) -> Result<Vec<u8>, RndisError> {
    let start = base.checked_add(rel).ok_or(RndisError::BadDataOffset)?;
    if start > buf.len() {
        return Err(RndisError::BadDataOffset);
    }
    let end = start.checked_add(len).ok_or(RndisError::BadDataOffset)?;
    if end > buf.len() {
        return Err(RndisError::BadDataOffset);
    }
    Ok(buf[start..end].to_vec())
}

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(buf: &[u8], at: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[at..at + 4]);
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_query_set_keepalive_and_data_round_trip() {
        let init = build_init(7);
        assert_eq!(&init[0..4], &MSG_INIT.to_le_bytes());
        assert_eq!(&init[4..8], &24u32.to_le_bytes());
        assert_eq!(&init[8..12], &7u32.to_le_bytes());
        assert_eq!(&init[20..24], &OUR_MAX_TRANSFER_SIZE.to_le_bytes());
        assert_eq!(
            unwrap_messages(&init).unwrap(),
            vec![Message::Init {
                request_id: 7,
                major: 1,
                minor: 0,
                max_transfer_size: 32_768,
            }]
        );

        let oid = 0x0101_0102;
        let mac = [2u8, 0, 0, 0, 0, 1];
        let query = build_query(3, oid, &mac);
        assert_eq!(
            unwrap_messages(&query).unwrap(),
            vec![Message::Query {
                request_id: 3,
                oid,
                data: mac.to_vec(),
            }]
        );

        let filter = 0x0000_000f_u32.to_le_bytes();
        let set = build_set(4, 0x0001_010e, &filter);
        assert_eq!(
            unwrap_messages(&set).unwrap(),
            vec![Message::Set {
                request_id: 4,
                oid: 0x0001_010e,
                data: filter.to_vec(),
            }]
        );

        let keepalive = build_keepalive(9);
        assert_eq!(&keepalive[0..4], &MSG_KEEPALIVE.to_le_bytes());
        assert_eq!(
            unwrap_messages(&keepalive).unwrap(),
            vec![Message::Keepalive { request_id: 9 }]
        );

        let frame = vec![0xff, 0xee, 0x45, 0x00, 0x00, 0x1c];
        let data = build_data(&frame);
        assert_eq!(&data[0..4], &MSG_PACKET.to_le_bytes());
        assert_eq!(&data[8..12], &36u32.to_le_bytes());
        assert_eq!(
            unwrap_messages(&data).unwrap(),
            vec![Message::Data { frame }]
        );
    }

    #[test]
    fn short_buffer_bad_length_and_bad_data_offset_are_errors() {
        assert_eq!(
            unwrap_messages(&[0x02, 0x00, 0x00]),
            Err(RndisError::ShortBuffer)
        );

        let mut overlong = build_keepalive(1);
        overlong[4..8].copy_from_slice(&1000u32.to_le_bytes());
        assert_eq!(unwrap_messages(&overlong), Err(RndisError::BadLength));

        let mut shifted = build_data(&[1, 2, 3, 4]);
        let past = (shifted.len() as u32) + 8;
        shifted[8..12].copy_from_slice(&past.to_le_bytes());
        assert_eq!(unwrap_messages(&shifted), Err(RndisError::BadDataOffset));
    }

    #[test]
    fn two_messages_in_one_buffer_both_parse() {
        let mut buf = build_keepalive(1);
        let frame = vec![0xab, 0xcd];
        buf.extend_from_slice(&build_data(&frame));

        assert_eq!(
            unwrap_messages(&buf).unwrap(),
            vec![
                Message::Keepalive { request_id: 1 },
                Message::Data { frame },
            ]
        );
    }

    #[test]
    fn out_length_is_capped_by_phone_max_transfer_size() {
        let phone_max = 80u32;
        let frame = vec![0x11u8; 100];
        let capped = cap_out_packet(&frame, phone_max).unwrap();

        assert_eq!(capped.len(), phone_max as usize);
        let msg_len = u32::from_le_bytes(capped[4..8].try_into().unwrap());
        let data_len = u32::from_le_bytes(capped[12..16].try_into().unwrap());
        assert_eq!(msg_len as usize, capped.len());
        assert_eq!(DATA_HEADER_LEN + data_len as usize, capped.len());
        assert_eq!(
            unwrap_messages(&capped).unwrap(),
            vec![Message::Data {
                frame: frame[..data_len as usize].to_vec(),
            }]
        );

        let small = vec![1u8, 2, 3, 4];
        let intact = cap_out_packet(&small, phone_max).unwrap();
        assert_eq!(intact.len(), DATA_HEADER_LEN + small.len());
        assert!(intact.len() < phone_max as usize);
        assert_eq!(
            unwrap_messages(&intact).unwrap(),
            vec![Message::Data { frame: small }]
        );
    }
}
