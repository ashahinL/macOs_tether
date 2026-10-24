//! Ethernet ARP for IPv4. A request for our address becomes a reply.
//! A gateway reply counts only when its sender protocol address is that gateway.

use std::net::Ipv4Addr;

const FRAME_LEN: usize = 42;
const ARP_ETHERTYPE: u16 = 0x0806;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

pub fn build_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> [u8; 42] {
    write_frame(
        [0xff; 6], sender_mac, OP_REQUEST, sender_mac, sender_ip, [0; 6], target_ip,
    )
}

/// Reply when `frame` is an ARP request for `our_ip`. Any other target is ignored.
pub fn reply_if_ours(frame: &[u8], our_mac: [u8; 6], our_ip: Ipv4Addr) -> Option<[u8; 42]> {
    let fields = parse(frame)?;
    if fields.opcode != OP_REQUEST || fields.target_ip != our_ip {
        return None;
    }
    Some(write_frame(
        fields.sender_mac,
        our_mac,
        OP_REPLY,
        our_mac,
        our_ip,
        fields.sender_mac,
        fields.sender_ip,
    ))
}

/// Sender hardware address when this is an ARP reply from `gateway_ip`.
pub fn accept_gateway_reply(frame: &[u8], gateway_ip: Ipv4Addr) -> Option<[u8; 6]> {
    let fields = parse(frame)?;
    if fields.opcode != OP_REPLY || fields.sender_ip != gateway_ip {
        return None;
    }
    Some(fields.sender_mac)
}

struct Fields {
    opcode: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
}

fn parse(frame: &[u8]) -> Option<Fields> {
    if frame.len() < FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ARP_ETHERTYPE {
        return None;
    }
    if u16::from_be_bytes([frame[14], frame[15]]) != 1 {
        return None;
    }
    if u16::from_be_bytes([frame[16], frame[17]]) != 0x0800 || frame[18] != 6 || frame[19] != 4 {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[22..28]);
    Some(Fields {
        opcode: u16::from_be_bytes([frame[20], frame[21]]),
        sender_mac,
        sender_ip: ipv4_at(frame, 28),
        target_ip: ipv4_at(frame, 38),
    })
}

fn write_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    opcode: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    let mut frame = [0u8; FRAME_LEN];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&opcode.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender_ip.octets());
    frame[32..38].copy_from_slice(&target_mac);
    frame[38..42].copy_from_slice(&target_ip.octets());
    frame
}

fn ipv4_at(frame: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(frame[at], frame[at + 1], frame[at + 2], frame[at + 3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crafted_reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> [u8; 42] {
        let mut frame = [0u8; 42];
        frame[0..6].copy_from_slice(&target_mac);
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        frame[14..16].copy_from_slice(&[0x00, 0x01]);
        frame[16..18].copy_from_slice(&[0x08, 0x00]);
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&[0x00, 0x02]);
        frame[22..28].copy_from_slice(&sender_mac);
        frame[28..32].copy_from_slice(&sender_ip);
        frame[32..38].copy_from_slice(&target_mac);
        frame[38..42].copy_from_slice(&target_ip);
        frame
    }

    #[test]
    fn request_for_our_ip_becomes_a_reply() {
        let their_mac = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let their_ip = Ipv4Addr::new(10, 0, 0, 1);
        let our_mac = [0x02, 0x10, 0x20, 0x30, 0x40, 0x50];
        let our_ip = Ipv4Addr::new(10, 0, 0, 2);

        let request = build_request(their_mac, their_ip, our_ip);
        assert_eq!(&request[0..6], &[0xff; 6]);
        assert_eq!(&request[20..22], &[0x00, 0x01]);
        assert_eq!(&request[38..42], &our_ip.octets());

        let reply = reply_if_ours(&request, our_mac, our_ip).unwrap();
        assert_eq!(&reply[0..6], &their_mac);
        assert_eq!(&reply[6..12], &our_mac);
        assert_eq!(&reply[12..14], &[0x08, 0x06]);
        assert_eq!(&reply[20..22], &[0x00, 0x02]);
        assert_eq!(&reply[22..28], &our_mac);
        assert_eq!(&reply[28..32], &our_ip.octets());
        assert_eq!(&reply[32..38], &their_mac);
        assert_eq!(&reply[38..42], &their_ip.octets());
    }

    #[test]
    fn request_for_another_ip_is_ignored() {
        let our_mac = [0x02, 0x10, 0x20, 0x30, 0x40, 0x50];
        let our_ip = Ipv4Addr::new(10, 0, 0, 2);
        let other = Ipv4Addr::new(10, 0, 0, 9);
        let request = build_request(our_mac, our_ip, other);
        assert_eq!(&request[38..42], &other.octets());
        assert!(reply_if_ours(&request, our_mac, our_ip).is_none());
    }

    #[test]
    fn gateway_reply_accepted_only_when_sender_is_gateway() {
        let gateway = Ipv4Addr::new(192, 168, 42, 129);
        let gateway_mac = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let our_ip = [192, 168, 42, 100];

        let good = crafted_reply(gateway_mac, gateway.octets(), our_mac, our_ip);
        assert_eq!(accept_gateway_reply(&good, gateway), Some(gateway_mac));

        let wrong_sender = crafted_reply(gateway_mac, [8, 8, 8, 8], our_mac, gateway.octets());
        assert_eq!(accept_gateway_reply(&wrong_sender, gateway), None);

        let mut request = good;
        request[20..22].copy_from_slice(&[0x00, 0x01]);
        assert_eq!(accept_gateway_reply(&request, gateway), None);
    }
}
