//! macOS utun packets are a 4-byte address family in network order, then the IP packet.

/// macOS `AF_INET`.
pub const AF_INET: u32 = 2;

/// macOS `AF_INET6`. Darwin uses 30. Linux uses 10.
pub const AF_INET6: u32 = 30;

const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Short,
    Unsupported,
}

pub fn utun_to_eth(utun: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> Result<Vec<u8>, FrameError> {
    if utun.len() < 4 {
        return Err(FrameError::Short);
    }
    let family = read_u32_be(utun);
    let ethertype = match family {
        AF_INET => ETHERTYPE_IPV4,
        AF_INET6 => ETHERTYPE_IPV6,
        _ => return Err(FrameError::Unsupported),
    };
    let ip = &utun[4..];
    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + ip.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(ip);
    Ok(frame)
}

pub fn eth_to_utun(frame: &[u8]) -> Result<Vec<u8>, FrameError> {
    if frame.len() < ETH_HEADER_LEN {
        return Err(FrameError::Short);
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let family = match ethertype {
        ETHERTYPE_IPV4 => AF_INET,
        ETHERTYPE_IPV6 => AF_INET6,
        _ => return Err(FrameError::Unsupported),
    };
    let mut utun = Vec::with_capacity(4 + frame.len() - ETH_HEADER_LEN);
    utun.extend_from_slice(&family.to_be_bytes());
    utun.extend_from_slice(&frame[ETH_HEADER_LEN..]);
    Ok(utun)
}

fn read_u32_be(buf: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[..4]);
    u32::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(family: u32, ethertype: [u8; 2], ip: &[u8]) {
        let src = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut utun = family.to_be_bytes().to_vec();
        utun.extend_from_slice(ip);

        let frame = utun_to_eth(&utun, src, dst).unwrap();
        assert_eq!(&frame[0..6], &dst);
        assert_eq!(&frame[6..12], &src);
        assert_eq!(&frame[12..14], &ethertype);
        assert_eq!(&frame[14..], ip);

        let back = eth_to_utun(&frame).unwrap();
        assert_eq!(&back[..4], &family.to_be_bytes());
        assert_eq!(&back[4..], ip);
    }

    #[test]
    fn ipv4_utun_round_trip_keeps_ip_bytes() {
        round_trip(AF_INET, [0x08, 0x00], &[0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_utun_round_trip_keeps_ip_bytes() {
        round_trip(
            AF_INET6,
            [0x86, 0xdd],
            &[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40],
        );
    }
}
