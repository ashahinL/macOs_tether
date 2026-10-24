//! BOOTP/DHCP messages. The magic cookie is `0x63825363` in network order.

use std::net::Ipv4Addr;

pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

const HEADER_LEN: usize = 240;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_END: u8 = 255;
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    Offer(Lease),
    Ack(Lease),
    Nak,
}

impl ServerMessage {
    pub fn lease(&self) -> Option<&Lease> {
        match self {
            ServerMessage::Offer(lease) | ServerMessage::Ack(lease) => Some(lease),
            ServerMessage::Nak => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpError {
    Short,
    BadCookie,
    Truncated,
    NotServer,
}

pub fn build_discover(mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut packet = header(mac, xid);
    packet.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, DISCOVER]);
    packet.extend_from_slice(&[55, 3, 1, 3, 6]);
    packet.push(OPT_END);
    packet
}

pub fn build_request(mac: [u8; 6], xid: u32, requested: Ipv4Addr, server: Ipv4Addr) -> Vec<u8> {
    let mut packet = header(mac, xid);
    packet.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, REQUEST]);
    packet.extend_from_slice(&[50, 4]);
    packet.extend_from_slice(&requested.octets());
    packet.extend_from_slice(&[54, 4]);
    packet.extend_from_slice(&server.octets());
    packet.extend_from_slice(&[55, 3, 1, 3, 6]);
    packet.push(OPT_END);
    packet
}

pub fn parse_server_message(packet: &[u8]) -> Result<ServerMessage, DhcpError> {
    if packet.len() < HEADER_LEN {
        return Err(DhcpError::Short);
    }
    if packet[236..240] != MAGIC_COOKIE {
        return Err(DhcpError::BadCookie);
    }

    let address = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let mut kind = None;
    let mut router = None;
    let mut dns = Vec::new();
    let mut index = HEADER_LEN;
    while index < packet.len() {
        let code = packet[index];
        if code == OPT_END {
            break;
        }
        if code == 0 {
            index += 1;
            continue;
        }
        if index + 1 >= packet.len() {
            return Err(DhcpError::Truncated);
        }
        let len = packet[index + 1] as usize;
        let start = index + 2;
        let end = start.checked_add(len).ok_or(DhcpError::Truncated)?;
        if end > packet.len() {
            return Err(DhcpError::Truncated);
        }
        let value = &packet[start..end];
        match code {
            OPT_ROUTER if value.len() >= 4 => {
                router = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            OPT_DNS => {
                for chunk in value.chunks_exact(4) {
                    dns.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
            }
            OPT_MESSAGE_TYPE if !value.is_empty() => kind = Some(value[0]),
            _ => {}
        }
        index = end;
    }

    let lease = Lease {
        address,
        router,
        dns,
    };
    match kind {
        Some(OFFER) => Ok(ServerMessage::Offer(lease)),
        Some(ACK) => Ok(ServerMessage::Ack(lease)),
        Some(NAK) => Ok(ServerMessage::Nak),
        _ => Err(DhcpError::NotServer),
    }
}

fn header(mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut packet = vec![0u8; HEADER_LEN];
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    packet[4..8].copy_from_slice(&xid.to_be_bytes());
    packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    packet[28..34].copy_from_slice(&mac);
    packet[236..240].copy_from_slice(&MAGIC_COOKIE);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_packet(
        kind: u8,
        yiaddr: [u8; 4],
        router: Option<[u8; 4]>,
        dns: &[[u8; 4]],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; HEADER_LEN];
        packet[0] = 2;
        packet[16..20].copy_from_slice(&yiaddr);
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);
        packet.push(0);
        packet.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, kind]);
        if let Some(router) = router {
            packet.extend_from_slice(&[OPT_ROUTER, 4]);
            packet.extend_from_slice(&router);
        }
        if !dns.is_empty() {
            packet.push(OPT_DNS);
            packet.push((dns.len() * 4) as u8);
            for address in dns {
                packet.extend_from_slice(address);
            }
        }
        packet.push(OPT_END);
        packet
    }

    #[test]
    fn discover_and_request_contain_magic_cookie() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x10];
        let discover = build_discover(mac, 0x1234_5678);
        let request = build_request(
            mac,
            0x1234_5678,
            Ipv4Addr::new(192, 168, 42, 100),
            Ipv4Addr::new(192, 168, 42, 129),
        );

        assert_eq!(&discover[236..240], &MAGIC_COOKIE);
        assert_eq!(&request[236..240], &MAGIC_COOKIE);
        assert_eq!(&discover[240..243], &[OPT_MESSAGE_TYPE, 1, DISCOVER]);
        assert_eq!(&request[240..243], &[OPT_MESSAGE_TYPE, 1, REQUEST]);
        assert_eq!(u32::from_be_bytes(MAGIC_COOKIE), 0x6382_5363);
    }

    #[test]
    fn offer_yields_address_router_and_dns() {
        let packet = server_packet(
            OFFER,
            [192, 168, 42, 100],
            Some([192, 168, 42, 129]),
            &[[8, 8, 8, 8], [8, 8, 4, 4]],
        );
        let message = parse_server_message(&packet).unwrap();
        assert_eq!(
            message.lease(),
            Some(&Lease {
                address: Ipv4Addr::new(192, 168, 42, 100),
                router: Some(Ipv4Addr::new(192, 168, 42, 129)),
                dns: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            })
        );
        assert!(matches!(message, ServerMessage::Offer(_)));
    }

    #[test]
    fn ack_yields_present_options_and_nak_is_not_a_lease() {
        let ack = server_packet(
            ACK,
            [192, 168, 42, 100],
            Some([192, 168, 42, 129]),
            &[[8, 8, 8, 8]],
        );
        let message = parse_server_message(&ack).unwrap();
        assert_eq!(
            message,
            ServerMessage::Ack(Lease {
                address: Ipv4Addr::new(192, 168, 42, 100),
                router: Some(Ipv4Addr::new(192, 168, 42, 129)),
                dns: vec![Ipv4Addr::new(8, 8, 8, 8)],
            })
        );

        let bare = server_packet(ACK, [10, 0, 0, 5], None, &[]);
        let bare_ack = parse_server_message(&bare).unwrap();
        assert_eq!(
            bare_ack.lease(),
            Some(&Lease {
                address: Ipv4Addr::new(10, 0, 0, 5),
                router: None,
                dns: vec![],
            })
        );

        let nak = server_packet(
            NAK,
            [192, 168, 42, 100],
            Some([192, 168, 42, 129]),
            &[[8, 8, 8, 8]],
        );
        let message = parse_server_message(&nak).unwrap();
        assert_eq!(message, ServerMessage::Nak);
        assert!(message.lease().is_none());
    }
}
