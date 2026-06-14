use bytes::{Bytes, BytesMut};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{MutablePacket, Packet, ipv4};

pub fn ipv6_skip_exthdr(packet: &[u8]) -> Option<(usize, IpNextHeaderProtocol)> {
    if packet.len() < 40 {
        return None;
    }

    let mut next_hdr = IpNextHeaderProtocol(packet[6]);
    let mut offset = 40;

    loop {
        let ext_len = match next_hdr {
            IpNextHeaderProtocols::Hopopt
            | IpNextHeaderProtocols::Ipv6Opts
            | IpNextHeaderProtocols::Ipv6Route => (*packet.get(offset + 1)? as usize + 1) * 8,
            IpNextHeaderProtocols::Ah => (*packet.get(offset + 1)? as usize + 2) * 4,
            IpNextHeaderProtocols::Ipv6Frag => {
                if packet.len() < offset + 8 {
                    return None;
                }
                if u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) & 0xFFF8 != 0 {
                    return Some((offset, next_hdr));
                }
                8
            }
            IpNextHeaderProtocol(59) => return None,
            _ => return Some((offset, next_hdr)),
        };

        if packet.len() < offset + ext_len {
            return None;
        }

        next_hdr = IpNextHeaderProtocol(packet[offset]);
        offset += ext_len;
    }
}

pub struct Segmenter {
    buf: BytesMut,
}

impl Default for Segmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Segmenter {
    pub fn new() -> Segmenter {
        Segmenter {
            buf: BytesMut::with_capacity(1 << 20),
        }
    }
}

impl Segmenter {
    pub fn tcp_segment_ipv4(
        &mut self,
        header: &[u8],
        ip: &Ipv4Packet,
        tcp: &TcpPacket,
        mtu: usize,
    ) -> Option<Vec<Bytes>> {
        let len = tcp.payload().len();
        if len == 0 {
            return None;
        }

        let ip_hdr_len = (ip.get_header_length() as usize) * 4;
        let tcp_data_off = (tcp.get_data_offset() as usize) * 4;
        let hdr_len = ip_hdr_len + tcp_data_off;

        let seg_len = mtu.saturating_sub(hdr_len);
        if seg_len == 0 {
            return None;
        }

        let n = len.div_ceil(seg_len);

        let mut pseudo_hdr = [0u8; 12];
        pseudo_hdr[0..4].copy_from_slice(&ip.get_source().octets());
        pseudo_hdr[4..8].copy_from_slice(&ip.get_destination().octets());
        pseudo_hdr[8] = 0;
        pseudo_hdr[9] = 6;

        let seq = tcp.get_sequence();

        let flags = tcp.get_flags();
        let psh = flags & TcpFlags::PSH;
        let fin = flags & TcpFlags::FIN;
        let flags = flags & !(TcpFlags::PSH | TcpFlags::FIN);

        let buf = &mut self.buf;
        if buf.capacity() < n * (header.len() + hdr_len) + len {
            buf.reserve(1 << 20);
        }
        let mut offset = 0;
        let mut frames = Vec::with_capacity(n);

        for idx in 0..n as u16 {
            let last = idx as usize == n - 1;
            let seg_len = if last { len - offset } else { seg_len };

            buf.extend_from_slice(header);
            buf.extend_from_slice(&ip.packet()[..ip_hdr_len]);
            buf.extend_from_slice(&tcp.packet()[..tcp_data_off]);
            buf.extend_from_slice(&tcp.payload()[offset..offset + seg_len]);

            let mut buf = buf.split();

            {
                let buf = &mut buf[header.len()..];
                buf[2..4].copy_from_slice(&((hdr_len + seg_len) as u16).to_be_bytes());

                let mut ip = MutableIpv4Packet::new(buf).unwrap();
                ip.set_flags(Ipv4Flags::DontFragment);
                ip.set_fragment_offset(0);
                ip.set_identification(ip.get_identification().wrapping_add(idx));
                ip.set_checksum(0);
                ip.set_checksum(ipv4::checksum(&ip.to_immutable()));

                let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
                tcp.set_sequence(seq.wrapping_add(offset as u32));
                let mut flags = flags;
                if last {
                    flags |= psh | fin;
                }
                tcp.set_flags(flags);
                tcp.set_checksum(0);

                pseudo_hdr[10..12]
                    .copy_from_slice(&((tcp_data_off + seg_len) as u16).to_be_bytes());

                let mut csum = internet_checksum::Checksum::new();
                csum.add_bytes(&pseudo_hdr);
                csum.add_bytes(ip.payload());
                buf[ip_hdr_len + 16..ip_hdr_len + 18].copy_from_slice(&csum.checksum());
            }

            frames.push(buf.freeze());

            offset += seg_len;
        }

        Some(frames)
    }

    pub fn tcp_segment_ipv6(
        &mut self,
        header: &[u8],
        ip: &Ipv6Packet,
        ip_hdr_len: usize,
        tcp: &TcpPacket,
        mtu: usize,
    ) -> Option<Vec<Bytes>> {
        let len = tcp.payload().len();
        if len == 0 {
            return None;
        }

        let tcp_data_off = (tcp.get_data_offset() as usize) * 4;
        let hdr_len = ip_hdr_len + tcp_data_off;

        let seg_len = mtu.saturating_sub(hdr_len);
        if seg_len == 0 {
            return None;
        }

        let n = len.div_ceil(seg_len);

        let mut pseudo_hdr = [0u8; 40];
        pseudo_hdr[0..16].copy_from_slice(&ip.get_source().octets());
        pseudo_hdr[16..32].copy_from_slice(&ip.get_destination().octets());
        pseudo_hdr[39] = 6;

        let seq = tcp.get_sequence();

        let flags = tcp.get_flags();
        let psh = flags & TcpFlags::PSH;
        let fin = flags & TcpFlags::FIN;
        let flags = flags & !(TcpFlags::PSH | TcpFlags::FIN);

        let buf = &mut self.buf;
        if buf.capacity() < n * (header.len() + hdr_len) + len {
            buf.reserve(1 << 20);
        }
        let mut offset = 0;
        let mut frames = Vec::with_capacity(n);

        for idx in 0..n as u16 {
            let last = idx as usize == n - 1;
            let seg_len = if last { len - offset } else { seg_len };

            buf.extend_from_slice(header);
            buf.extend_from_slice(&ip.packet()[..ip_hdr_len]);
            buf.extend_from_slice(&tcp.packet()[..tcp_data_off]);
            buf.extend_from_slice(&tcp.payload()[offset..offset + seg_len]);

            let mut buf = buf.split();

            {
                let buf = &mut buf[header.len()..];
                buf[4..6].copy_from_slice(&((hdr_len - 40 + seg_len) as u16).to_be_bytes());

                let mut tcp = MutableTcpPacket::new(&mut buf[ip_hdr_len..]).unwrap();
                tcp.set_sequence(seq.wrapping_add(offset as u32));
                let mut seg_flags = flags;
                if last {
                    seg_flags |= psh | fin;
                }
                tcp.set_flags(seg_flags);
                tcp.set_checksum(0);

                pseudo_hdr[32..36]
                    .copy_from_slice(&((tcp_data_off + seg_len) as u32).to_be_bytes());

                let mut csum = internet_checksum::Checksum::new();
                csum.add_bytes(&pseudo_hdr);
                csum.add_bytes(&buf[ip_hdr_len..]);
                buf[ip_hdr_len + 16..ip_hdr_len + 18].copy_from_slice(&csum.checksum());
            }

            frames.push(buf.freeze());

            offset += seg_len;
        }

        Some(frames)
    }
}
