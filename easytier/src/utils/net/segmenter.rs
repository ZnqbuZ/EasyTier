use crate::utils::buf::{BufMargins, BufPool};
use derive_more::TryFrom;
use etherparse::{
    Ipv4Slice, Ipv6ExtensionSlice, Ipv6Slice, NetSlice, SlicedPacket, TcpSlice, TransportSlice,
    UdpSlice,
};
use std::collections::VecDeque;
use thiserror::Error;

use easytier_core::packet::{ZCPacket, ZCPacketType};

use super::virtio::*;

#[allow(dead_code)]
mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const CWR: u8 = 0x80;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SegmentError {
    #[error("packet is not a GSO packet")]
    NotGso,

    #[error("GSO packet has gso_size == 0")]
    InvalidGsoSize,

    #[error("unsupported virtio GSO type {0:#04x}")]
    UnsupportedGsoType(u8),

    #[error("virtio GSO type does not match the IP/transport packet")]
    ProtocolMismatch,

    #[error("failed to parse GSO IP packet")]
    InvalidPacket,

    #[error("unsupported network or transport protocol for GSO segmentation")]
    InvalidProtocol,

    #[error("GSO packet has no transport payload")]
    EmptyPayload,

    #[error("cannot software-segment a packet containing IPsec AH")]
    AuthenticationHeader,

    #[error("unsupported active IPv6 routing header type {0}")]
    UnsupportedRoutingHeader(u8),

    #[error("cannot software-segment an IPv4 packet containing source routing options")]
    SourceRouting,

    #[error("unsupported TCP flags in GSO packet: {0:#04x}")]
    UnsupportedTcpFlags(u8),

    #[error("software GSO segment exceeds protocol length limits")]
    SegmentTooLarge,
}

#[repr(u8)]
#[derive(TryFrom)]
#[try_from(repr)]
enum GsoType {
    TcpV4 = VNET_HDR_GSO_TCPV4,
    TcpV6 = VNET_HDR_GSO_TCPV6,
    UdpL4 = VNET_HDR_GSO_UDP_L4,
}

struct GsoMeta {
    ty: GsoType,
    size: usize,
}

impl TryFrom<&[u8]> for GsoMeta {
    type Error = SegmentError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < VNET_HDR_LEN {
            return Err(SegmentError::InvalidPacket);
        }

        let gso_type = value[1];
        if gso_type == VNET_HDR_GSO_NONE {
            return Err(SegmentError::NotGso);
        }

        let ty = GsoType::try_from(gso_type & !VNET_HDR_GSO_ECN)
            .map_err(|_| SegmentError::UnsupportedGsoType(gso_type))?;

        // GSO_ECN is a TCP modifier, not a standalone GSO type.
        if gso_type & VNET_HDR_GSO_ECN != 0 && matches!(ty, GsoType::UdpL4) {
            return Err(SegmentError::UnsupportedGsoType(gso_type));
        }

        let size = u16::from_ne_bytes([value[4], value[5]]) as usize;
        if size == 0 {
            return Err(SegmentError::InvalidGsoSize);
        }

        Ok(Self { ty, size })
    }
}

#[repr(u8)]
enum IpProto {
    Tcp = 6,
    Udp = 17,
}

pub struct Segmenter {
    margins: BufMargins,
    queue: VecDeque<ZCPacket>,
}

impl Segmenter {
    pub fn new(margins: BufMargins) -> Self {
        Self {
            margins,
            queue: VecDeque::new(),
        }
    }

    pub fn pop(&mut self) -> Option<ZCPacket> {
        self.queue.pop_front()
    }

    /// Software-segment one GSO IP packet read from a TUN device.
    ///
    /// `buf` is the buffer pool used to allocate memory for segmented packets.
    /// `packet` is the raw packet buffer containing the virtio-net header at
    /// `vnet_hdr_off` and the IPv4/IPv6 packet at `self.margins.header`.
    /// `vnet_hdr_off` is the byte offset of the virtio-net header within `packet`.
    ///
    /// Generated `ZCPacket`s are populated directly into `self.queue` with
    /// `self.margins` allocated from `buf`.
    pub fn segment(
        &mut self,
        buf: &mut BufPool,
        packet: &[u8],
        vnet_hdr_off: usize,
    ) -> Result<usize, SegmentError> {
        let gso = GsoMeta::try_from(
            packet
                .get(vnet_hdr_off..vnet_hdr_off + VNET_HDR_LEN)
                .unwrap_or_default(),
        )?;
        let packet = packet
            .get(self.margins.header..)
            .and_then(|packet| SlicedPacket::from_ip(packet).ok())
            .ok_or(SegmentError::InvalidPacket)?;

        // Fragmented IP packets (IPv4 fragments with more_fragments / fragment_offset != 0,
        // and IPv6 packets with a Fragment header) are not parsed further by etherparse
        // (packet.transport is None), and are thus naturally rejected here as InvalidPacket.
        let transport = packet.transport.ok_or(SegmentError::InvalidPacket)?;

        let proto = match transport {
            TransportSlice::Tcp(_) => IpProto::Tcp,
            TransportSlice::Udp(_) => IpProto::Udp,
            _ => return Err(SegmentError::InvalidProtocol),
        };

        let net = packet.net.ok_or(SegmentError::InvalidPacket)?;

        let (ip_hdr, pseudo_hdr) = match &net {
            NetSlice::Ipv4(ip) => {
                if ip.extensions().auth.is_some() {
                    return Err(SegmentError::AuthenticationHeader);
                }

                const IPOPT_EOL: u8 = 0x00;
                const IPOPT_NOP: u8 = 0x01;
                const IPOPT_LSRR: u8 = 0x83;
                const IPOPT_SSRR: u8 = 0x89;

                let mut opts = ip.header().options();
                while let Some((&kind, rest)) = opts.split_first() {
                    match kind {
                        IPOPT_EOL => break,
                        IPOPT_NOP => {
                            opts = rest;
                        }
                        IPOPT_LSRR | IPOPT_SSRR => return Err(SegmentError::SourceRouting),
                        _ => {
                            if let Some((&len, _)) = rest.split_first() {
                                let len = len as usize;
                                if len < 2 || len > opts.len() {
                                    break;
                                }
                                opts = &opts[len..];
                            } else {
                                break;
                            }
                        }
                    }
                }

                (
                    IpHeader::from_v4(ip),
                    PseudoHeader::new_v4(ip.header().source(), ip.header().destination(), proto),
                )
            }
            NetSlice::Ipv6(ip) => {
                let mut dst = ip.header().destination();

                for ext in ip.extensions().clone() {
                    match ext {
                        Ipv6ExtensionSlice::Authentication(_) => {
                            return Err(SegmentError::AuthenticationHeader);
                        }
                        Ipv6ExtensionSlice::Routing(routing) => {
                            let routing = routing.slice();
                            if routing.len() < 4 {
                                return Err(SegmentError::InvalidPacket);
                            }

                            if routing[3] > 0 {
                                let len = routing.len();
                                match routing[2] {
                                    0 | 2 => {
                                        if len < 24 {
                                            return Err(SegmentError::InvalidPacket);
                                        }
                                        dst.copy_from_slice(&routing[len - 16..]);
                                    }
                                    4 => {
                                        if len < 24 {
                                            return Err(SegmentError::InvalidPacket);
                                        }
                                        dst.copy_from_slice(&routing[8..24]);
                                    }
                                    ty => return Err(SegmentError::UnsupportedRoutingHeader(ty)),
                                }
                            }
                        }
                        _ => {}
                    }
                }

                (
                    IpHeader::from_v6(ip),
                    PseudoHeader::new_v6(ip.header().source(), dst, proto),
                )
            }
            _ => return Err(SegmentError::InvalidProtocol),
        };

        match (gso.ty, &net, &transport) {
            (GsoType::TcpV4, NetSlice::Ipv4(_), TransportSlice::Tcp(tcp))
            | (GsoType::TcpV6, NetSlice::Ipv6(_), TransportSlice::Tcp(tcp)) => {
                self.segment_tcp(buf, &ip_hdr, pseudo_hdr, tcp, gso.size)
            }
            (GsoType::UdpL4, _, TransportSlice::Udp(udp)) => {
                self.segment_udp(buf, &ip_hdr, pseudo_hdr, udp, gso.size)
            }
            _ => Err(SegmentError::ProtocolMismatch),
        }
    }
}

enum PseudoHeader {
    V4([u8; 12]),
    V6([u8; 40]),
}

impl PseudoHeader {
    fn new_v4(src: [u8; 4], dst: [u8; 4], proto: IpProto) -> Self {
        let mut hdr = [0u8; 12];
        hdr[0..4].copy_from_slice(&src);
        hdr[4..8].copy_from_slice(&dst);
        hdr[8] = 0;
        hdr[9] = proto as _;
        Self::V4(hdr)
    }

    fn new_v6(src: [u8; 16], dst: [u8; 16], proto: IpProto) -> Self {
        let mut hdr = [0u8; 40];
        hdr[0..16].copy_from_slice(&src);
        hdr[16..32].copy_from_slice(&dst);
        hdr[39] = proto as _;
        Self::V6(hdr)
    }

    fn set_len(&mut self, len: u16) {
        match self {
            Self::V4(hdr) => hdr[10..12].copy_from_slice(&len.to_be_bytes()),
            Self::V6(hdr) => hdr[32..36].copy_from_slice(&(len as u32).to_be_bytes()),
        }
    }
}

impl AsRef<[u8]> for PseudoHeader {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::V4(hdr) => hdr,
            Self::V6(hdr) => hdr,
        }
    }
}

enum IpHeader<'s> {
    V4 { hdr: &'s [u8], df: bool, ident: u16 },
    V6 { hdr: &'s [u8], ext: &'s [u8] },
}

impl<'s> IpHeader<'s> {
    fn from_v4(ip: &'s Ipv4Slice<'s>) -> Self {
        let hdr = ip.header().slice();
        let df = (hdr[6] & 0x40) != 0;
        let ident = u16::from_be_bytes([hdr[4], hdr[5]]);
        Self::V4 { hdr, df, ident }
    }

    fn from_v6(ip: &'s Ipv6Slice<'s>) -> Self {
        Self::V6 {
            hdr: ip.header().slice(),
            ext: ip.extensions().slice(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::V4 { hdr, .. } => hdr.len(),
            Self::V6 { hdr, ext } => hdr.len() + ext.len(),
        }
    }

    fn write_header(&self, buf: &mut [u8], idx: usize, pkt_len: u16) {
        match self {
            Self::V4 { hdr, df, ident } => {
                let hdr_len = hdr.len();
                buf[..hdr_len].copy_from_slice(hdr);
                buf[2..4].copy_from_slice(&pkt_len.to_be_bytes());
                if !df {
                    buf[4..6].copy_from_slice(&ident.wrapping_add(idx as u16).to_be_bytes());
                }
                buf[10..12].copy_from_slice(&[0, 0]);
                let csum = internet_checksum::checksum(&buf[..hdr_len]);
                buf[10..12].copy_from_slice(&csum);
            }
            Self::V6 { hdr, ext } => {
                let hdr_len = hdr.len();
                buf[..hdr_len].copy_from_slice(hdr);
                buf[hdr_len..hdr_len + ext.len()].copy_from_slice(ext);
                buf[4..6].copy_from_slice(&(pkt_len - 40).to_be_bytes());
            }
        }
    }
}

impl Segmenter {
    fn write_checksum(pseudo_hdr: &PseudoHeader, buf: &mut [u8], proto: IpProto) {
        let csum_off = match proto {
            IpProto::Tcp => 16,
            IpProto::Udp => 6,
        };
        buf[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
        let mut csum = internet_checksum::Checksum::new();
        csum.add_bytes(pseudo_hdr.as_ref());
        csum.add_bytes(buf);
        let csum = match (csum.checksum(), proto) {
            ([0, 0], IpProto::Udp) => [0xff, 0xff],
            (csum, _) => csum,
        };
        buf[csum_off..csum_off + 2].copy_from_slice(&csum);
    }

    fn segment_tcp(
        &mut self,
        buf: &mut BufPool,
        ip_hdr: &IpHeader,
        mut pseudo_hdr: PseudoHeader,
        tcp: &TcpSlice,
        seg_len: usize,
    ) -> Result<usize, SegmentError> {
        let payload = tcp.payload();
        let len = payload.len();
        if len == 0 {
            return Err(SegmentError::EmptyPayload);
        }

        let flags = tcp.slice()[13];
        if flags & (tcp_flags::SYN | tcp_flags::RST | tcp_flags::URG) != 0 {
            return Err(SegmentError::UnsupportedTcpFlags(flags));
        }

        let cwr = flags & tcp_flags::CWR;
        let psh = flags & tcp_flags::PSH;
        let fin = flags & tcp_flags::FIN;
        let flags = flags & !(tcp_flags::CWR | tcp_flags::PSH | tcp_flags::FIN);

        let seq = tcp.sequence_number();

        let ip_hdr_len = ip_hdr.len();
        let tcp_data_off = tcp.header_slice().len();
        let hdr_len = ip_hdr_len + tcp_data_off;

        let n = len.div_ceil(seg_len);
        for (idx, payload) in payload.chunks(seg_len).enumerate() {
            let last = idx == n - 1;
            let len = payload.len();
            let pkt_len =
                u16::try_from(hdr_len + len).map_err(|_| SegmentError::SegmentTooLarge)?;

            let mut writer = buf.writer(pkt_len as usize + self.margins.size(), self.margins);
            let slice = writer.as_slice();
            let buf = unsafe {
                std::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, slice.len())
            };

            ip_hdr.write_header(buf, idx, pkt_len);
            buf[ip_hdr_len..hdr_len].copy_from_slice(tcp.header_slice());
            buf[hdr_len..hdr_len + len].copy_from_slice(payload);

            pseudo_hdr.set_len(
                u16::try_from(tcp_data_off + len).map_err(|_| SegmentError::SegmentTooLarge)?,
            );

            {
                let buf = &mut buf[ip_hdr_len..];

                buf[4..8].copy_from_slice(&seq.wrapping_add((idx * seg_len) as u32).to_be_bytes());

                let mut flags = flags;
                if idx == 0 {
                    flags |= cwr;
                }
                if last {
                    flags |= psh | fin;
                }
                buf[13] = flags;
                buf[18..20].copy_from_slice(&[0, 0]);

                Self::write_checksum(&pseudo_hdr, buf, IpProto::Tcp);
            }

            writer.commit(pkt_len as usize);
            let mut packet = writer.split();
            packet.truncate(packet.len() - self.margins.trailer);
            self.queue
                .push_back(ZCPacket::new_from_buf(packet, ZCPacketType::NIC));
        }

        Ok(n)
    }

    fn segment_udp(
        &mut self,
        buf: &mut BufPool,
        ip_hdr: &IpHeader,
        mut pseudo_hdr: PseudoHeader,
        udp: &UdpSlice,
        seg_len: usize,
    ) -> Result<usize, SegmentError> {
        let payload = udp.payload();
        let len = payload.len();
        if len == 0 {
            return Err(SegmentError::EmptyPayload);
        }

        let ip_hdr_len = ip_hdr.len();
        let hdr_len = ip_hdr_len + 8;

        let n = len.div_ceil(seg_len);
        for (idx, payload) in payload.chunks(seg_len).enumerate() {
            let len = payload.len();
            let pkt_len =
                u16::try_from(hdr_len + len).map_err(|_| SegmentError::SegmentTooLarge)?;

            let mut writer = buf.writer(pkt_len as usize + self.margins.size(), self.margins);
            let slice = writer.as_slice();
            let buf = unsafe {
                std::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, slice.len())
            };

            ip_hdr.write_header(buf, idx, pkt_len);
            buf[ip_hdr_len..ip_hdr_len + 4].copy_from_slice(&udp.slice()[..4]);
            buf[hdr_len..hdr_len + len].copy_from_slice(payload);

            let udp_len = u16::try_from(8 + len).map_err(|_| SegmentError::SegmentTooLarge)?;
            pseudo_hdr.set_len(udp_len);

            {
                let buf = &mut buf[ip_hdr_len..];
                buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
                Self::write_checksum(&pseudo_hdr, buf, IpProto::Udp);
            }

            writer.commit(pkt_len as usize);
            let mut packet = writer.split();
            packet.truncate(packet.len() - self.margins.trailer);
            self.queue
                .push_back(ZCPacket::new_from_buf(packet, ZCPacketType::NIC));
        }

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::packet::TAIL_RESERVED_SIZE;

    fn test_margins() -> BufMargins {
        BufMargins {
            header: ZCPacketType::NIC.get_packet_offsets().payload_offset,
            trailer: TAIL_RESERVED_SIZE,
        }
    }

    fn make_packet(vnet_hdr: &[u8], ip_packet: &[u8]) -> (Vec<u8>, usize) {
        let vnet_hdr_off = test_margins().header - VNET_HDR_LEN;
        let mut buf = vec![0u8; test_margins().header + ip_packet.len()];
        buf[vnet_hdr_off..vnet_hdr_off + vnet_hdr.len()].copy_from_slice(vnet_hdr);
        buf[test_margins().header..].copy_from_slice(ip_packet);
        (buf, vnet_hdr_off)
    }

    fn build_tcp4_packet(payload_len: usize) -> Vec<u8> {
        let payload = vec![0xAB; payload_len];
        let ip_hdr_len = 20;
        let tcp_hdr_len = 20;
        let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

        let mut ip_packet = vec![0u8; total_len];
        ip_packet[0] = 0x45;
        ip_packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip_packet[4..6].copy_from_slice(&1234u16.to_be_bytes());
        ip_packet[6] = 0x40;
        ip_packet[8] = 64;
        ip_packet[9] = 6;
        ip_packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
        ip_packet[16..20].copy_from_slice(&[192, 168, 1, 2]);

        let ip_csum = internet_checksum::checksum(&ip_packet[..20]);
        ip_packet[10..12].copy_from_slice(&ip_csum);

        let tcp = &mut ip_packet[20..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].copy_from_slice(&payload);

        ip_packet
    }

    fn build_tcp4_packet_with_options(opts: &[u8; 4]) -> Vec<u8> {
        let payload = vec![0xAB; 3000];
        let ip_hdr_len = 24;
        let tcp_hdr_len = 20;
        let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

        let mut ip_packet = vec![0u8; total_len];
        ip_packet[0] = 0x46;
        ip_packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip_packet[4..6].copy_from_slice(&1234u16.to_be_bytes());
        ip_packet[6] = 0x40;
        ip_packet[8] = 64;
        ip_packet[9] = 6;
        ip_packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
        ip_packet[16..20].copy_from_slice(&[192, 168, 1, 2]);
        ip_packet[20..24].copy_from_slice(opts);

        let ip_csum = internet_checksum::checksum(&ip_packet[..24]);
        ip_packet[10..12].copy_from_slice(&ip_csum);

        let tcp = &mut ip_packet[24..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].copy_from_slice(&payload);

        ip_packet
    }

    fn build_tcp6_routing_packet(routing_type: u8, segments_left: u8) -> Vec<u8> {
        let payload = vec![0xCD; 3000];
        let routing_len = 24;
        let tcp_hdr_len = 20;
        let payload_len = routing_len + tcp_hdr_len + payload.len();
        let total_len = 40 + payload_len;

        let mut ip_packet = vec![0u8; total_len];
        ip_packet[0] = 0x60;
        ip_packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        ip_packet[6] = 43; // Routing header
        ip_packet[7] = 64;
        ip_packet[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip_packet[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        ip_packet[40] = 6; // next header TCP
        ip_packet[41] = 2; // (24 - 8) / 8 = 2
        ip_packet[42] = routing_type;
        ip_packet[43] = segments_left;
        ip_packet[44..48].copy_from_slice(&[0, 0, 0, 0]);
        ip_packet[48..64].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

        let tcp = &mut ip_packet[64..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&2000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].copy_from_slice(&payload);

        ip_packet
    }

    fn vnet_hdr(
        gso_type: u8,
        hdr_len: u16,
        gso_size: u16,
        csum_start: u16,
        csum_offset: u16,
    ) -> [u8; VNET_HDR_LEN] {
        let mut hdr = [0u8; VNET_HDR_LEN];
        hdr[1] = gso_type;
        hdr[2..4].copy_from_slice(&hdr_len.to_ne_bytes());
        hdr[4..6].copy_from_slice(&gso_size.to_ne_bytes());
        hdr[6..8].copy_from_slice(&csum_start.to_ne_bytes());
        hdr[8..10].copy_from_slice(&csum_offset.to_ne_bytes());
        hdr
    }

    #[test]
    fn test_segmenter_rejects_unsupported() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        // Non-GSO packet
        let (packet, vnet_hdr_off) = make_packet(&[0u8; VNET_HDR_LEN], &[0u8; 2000]);
        assert_eq!(
            segmenter.segment(&mut pool, &packet, vnet_hdr_off),
            Err(SegmentError::NotGso)
        );

        // TCP SYN, RST, URG flags
        let hdr = vnet_hdr(VNET_HDR_GSO_TCPV4, 40, 1460, 20, 16);
        for bad_flag in [tcp_flags::SYN, tcp_flags::RST, tcp_flags::URG] {
            let mut ip_packet = build_tcp4_packet(3000);
            ip_packet[33] |= bad_flag;
            let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
            assert!(matches!(
                segmenter.segment(&mut pool, &packet, vnet_hdr_off),
                Err(SegmentError::UnsupportedTcpFlags(flags)) if flags & bad_flag != 0
            ));
        }

        // IPv4 source routing options (LSRR: 0x83, SSRR: 0x89)
        for opt_kind in [0x83, 0x89] {
            let ip_packet = build_tcp4_packet_with_options(&[opt_kind, 3, 4, 0x00]);
            let hdr = vnet_hdr(VNET_HDR_GSO_TCPV4, 44, 1460, 24, 16);
            let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
            assert_eq!(
                segmenter.segment(&mut pool, &packet, vnet_hdr_off),
                Err(SegmentError::SourceRouting)
            );
        }

        // IPv6 active unknown routing header (type 99, segments_left = 1)
        let ip_packet = build_tcp6_routing_packet(99, 1);
        let hdr = vnet_hdr(VNET_HDR_GSO_TCPV6, 84, 1000, 64, 16);
        let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
        assert_eq!(
            segmenter.segment(&mut pool, &packet, vnet_hdr_off),
            Err(SegmentError::UnsupportedRoutingHeader(99))
        );
    }

    #[test]
    fn test_segmenter_tcp4() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let ip_packet = build_tcp4_packet(3000);
        let hdr = vnet_hdr(VNET_HDR_GSO_TCPV4, 40, 1460, 20, 16);
        let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
        let count = segmenter.segment(&mut pool, &packet, vnet_hdr_off).unwrap();

        assert_eq!(count, 3);
        assert_eq!(segmenter.queue.len(), 3);

        let seg0 = segmenter.pop().unwrap();
        assert_eq!(seg0.payload().len(), 1500);
        let parsed = SlicedPacket::from_ip(seg0.payload()).unwrap();
        let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp.sequence_number(), 1000);
        assert_eq!(tcp.payload().len(), 1460);
        assert_eq!(tcp.slice()[13] & tcp_flags::PSH, 0);

        let seg1 = segmenter.pop().unwrap();
        assert_eq!(seg1.payload().len(), 1500);
        let parsed = SlicedPacket::from_ip(seg1.payload()).unwrap();
        let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp.sequence_number(), 1000 + 1460);
        assert_eq!(tcp.payload().len(), 1460);

        let seg2 = segmenter.pop().unwrap();
        assert_eq!(seg2.payload().len(), 40 + 80);
        let parsed = SlicedPacket::from_ip(seg2.payload()).unwrap();
        let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp.sequence_number(), 1000 + 2920);
        assert_eq!(tcp.payload().len(), 80);
        assert_ne!(tcp.slice()[13] & tcp_flags::PSH, 0);

        assert!(segmenter.pop().is_none());
    }

    #[test]
    fn test_segmenter_tcp6() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let payload = vec![0xCD; 3000];
        let ip_hdr_len = 40;
        let tcp_hdr_len = 20;
        let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

        let mut ip_packet = vec![0u8; total_len];
        ip_packet[0] = 0x60;
        ip_packet[4..6].copy_from_slice(&((tcp_hdr_len + payload.len()) as u16).to_be_bytes());
        ip_packet[6] = 6;
        ip_packet[7] = 64;
        ip_packet[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip_packet[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let tcp = &mut ip_packet[40..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&2000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].copy_from_slice(&payload);

        let hdr = vnet_hdr(VNET_HDR_GSO_TCPV6, 60, 1440, 40, 16);
        let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
        let count = segmenter.segment(&mut pool, &packet, vnet_hdr_off).unwrap();

        assert_eq!(count, 3);
        assert_eq!(segmenter.queue.len(), 3);

        let seg0 = segmenter.pop().unwrap();
        assert_eq!(seg0.payload().len(), 1500);
        let parsed = SlicedPacket::from_ip(seg0.payload()).unwrap();
        let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp.sequence_number(), 2000);
        assert_eq!(tcp.payload().len(), 1440);

        let _seg1 = segmenter.pop().unwrap();

        let seg2 = segmenter.pop().unwrap();
        assert_eq!(seg2.payload().len(), 60 + 120);
        let parsed = SlicedPacket::from_ip(seg2.payload()).unwrap();
        let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp.sequence_number(), 2000 + 2880);
        assert_eq!(tcp.payload().len(), 120);
        assert_ne!(tcp.slice()[13] & tcp_flags::PSH, 0);

        assert!(segmenter.pop().is_none());
    }

    #[test]
    fn test_segmenter_udp4() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let payload = vec![0xAB; 3000];
        let ip_hdr_len = 20;
        let udp_hdr_len = 8;
        let total_len = ip_hdr_len + udp_hdr_len + payload.len();

        let mut ip_packet = vec![0u8; total_len];
        ip_packet[0] = 0x45;
        ip_packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip_packet[4..6].copy_from_slice(&1234u16.to_be_bytes());
        ip_packet[6] = 0x40;
        ip_packet[8] = 64;
        ip_packet[9] = 17;
        ip_packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
        ip_packet[16..20].copy_from_slice(&[192, 168, 1, 2]);

        let ip_csum = internet_checksum::checksum(&ip_packet[..20]);
        ip_packet[10..12].copy_from_slice(&ip_csum);

        let udp = &mut ip_packet[20..];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&80u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((udp_hdr_len + payload.len()) as u16).to_be_bytes());
        udp[8..].copy_from_slice(&payload);

        // Deliberately not MTU-derived: this verifies that UDP datagram
        // boundaries come from the sender's GSO metadata.
        let hdr = vnet_hdr(VNET_HDR_GSO_UDP_L4, 28, 1200, 20, 6);
        let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
        let count = segmenter.segment(&mut pool, &packet, vnet_hdr_off).unwrap();

        assert_eq!(count, 3);
        assert_eq!(segmenter.queue.len(), 3);

        let seg0 = segmenter.pop().unwrap();
        assert_eq!(seg0.payload().len(), 20 + 8 + 1200);
        let parsed = SlicedPacket::from_ip(seg0.payload()).unwrap();
        let TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(udp.payload().len(), 1200);

        let seg1 = segmenter.pop().unwrap();
        assert_eq!(seg1.payload().len(), 20 + 8 + 1200);
        let parsed = SlicedPacket::from_ip(seg1.payload()).unwrap();
        let TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(udp.payload().len(), 1200);

        let seg2 = segmenter.pop().unwrap();
        assert_eq!(seg2.payload().len(), 20 + 8 + 600);
        let parsed = SlicedPacket::from_ip(seg2.payload()).unwrap();
        let TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(udp.payload().len(), 600);

        assert!(segmenter.pop().is_none());
    }

    #[test]
    fn test_segmenter_udp6() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let payload = vec![0xEF; 2000];
        let ext_len = 8;
        let udp_hdr_len = 8;
        let total_len = 40 + ext_len + udp_hdr_len + payload.len();

        let mut ip_packet = vec![0u8; total_len];
        ip_packet[0] = 0x60;
        ip_packet[4..6]
            .copy_from_slice(&((ext_len + udp_hdr_len + payload.len()) as u16).to_be_bytes());
        ip_packet[6] = 60; // Destination Options
        ip_packet[7] = 64;
        ip_packet[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip_packet[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        // One 8-byte Destination Options header, followed by UDP.
        ip_packet[40] = 17;
        ip_packet[41] = 0;

        let udp = &mut ip_packet[48..];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&80u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((udp_hdr_len + payload.len()) as u16).to_be_bytes());
        udp[8..].copy_from_slice(&payload);

        let hdr = vnet_hdr(VNET_HDR_GSO_UDP_L4, 56, 1000, 48, 6);
        let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
        let count = segmenter.segment(&mut pool, &packet, vnet_hdr_off).unwrap();

        assert_eq!(count, 2);
        assert_eq!(segmenter.queue.len(), 2);

        while let Some(segment) = segmenter.pop() {
            let parsed = SlicedPacket::from_ip(segment.payload()).unwrap();
            let NetSlice::Ipv6(ip) = parsed.net.unwrap() else {
                panic!()
            };
            assert_eq!(ip.extensions().slice(), &ip_packet[40..48]);

            let TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
                panic!()
            };
            assert_eq!(udp.payload().len(), 1000);
        }
    }
}
