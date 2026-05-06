use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

use ipnet::Ipv4Net;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const MAX_DATAGRAM_SIZE: usize = 1350;
const MIN_INITIAL_SIZE: usize = 1200;
const PACKET_NUMBER_LEN: usize = 1;
const UNSUPPORTED_VERSION: u32 = 0x1a2a3a4a;

// 固定探测端口
const PORTS: &[u16] = &[443];

// 防止误操作/文件过大导致跑飞（可按你的实验环境调小/调大）
const MAX_HOSTS_PER_NET: u32 = 100_000_000;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args();
    let cmd = args.next().unwrap_or_else(|| "quic-vn-probe".to_string());

    let cidr_file = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("Usage: {cmd} CIDR_FILE");
            eprintln!("Example CIDR_FILE lines:");
            eprintln!("  10.0.0.0/24");
            eprintln!("  127.0.0.0/8");
            return Ok(());
        }
    };

    let nets = read_cidr_file(&cidr_file)?;
    if nets.is_empty() {
        eprintln!("no valid CIDR found in {cidr_file}");
        return Ok(());
    }

    for net in nets {
        // 合规防护：跳过公网网段
        // if !is_allowed_net(&net) {
        //     println!("{net}  (cidr): <skipped: non-private / non-test network>");
        //     continue;
        // }

        // 粗略限制规模，避免误把 /8 /0 等扫穿实验环境
        let host_count = {
            // 通过前缀长度计算地址数量：2^(32 - prefix_len)，去掉 network/broadcast
            let prefix = net.prefix_len();
            if prefix >= 32 {
                0u64
            } else {
                (1u64 << (32 - prefix as u32)).saturating_sub(2)
            }
        }; // hosts() 会去掉 network/broadcast
        if host_count > MAX_HOSTS_PER_NET as u64 {
            println!("{net}  (cidr): <skipped: too many hosts ({host_count})>");
            continue;
        }

        for ip in net.hosts() {
            for &port in PORTS {
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                match probe_versions(addr) {
                    Ok(versions) => {
                        if versions.is_empty() {
                            println!("{ip}:{port}  (cidr {net}): <no versions in VN packet>");
                        } else {
                            let vers = versions
                                .iter()
                                .map(|v| format!("0x{v:08x}"))
                                .collect::<Vec<_>>()
                                .join(" ");
                            println!("{ip}:{port}  (cidr {net}): {vers}");
                        }
                    }
                    Err(e) => {
                        println!("{ip}:{port}  (cidr {net}): <error: {e}>");
                    }
                }
            }
        }
    }

    Ok(())
}

fn read_cidr_file(path: &str) -> Result<Vec<Ipv4Net>, Box<dyn Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);

    let mut out = Vec::new();

    for (lineno, line) in r.lines().enumerate() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match line.parse::<Ipv4Net>() {
            Ok(net) => out.push(net),
            Err(_) => {
                eprintln!("skip line {} (bad CIDR): {}", lineno + 1, line);
                continue;
            }
        }
    }

    Ok(out)
}

// 允许：RFC1918 私网、回环、链路本地、CGNAT、文档测试网段（便于实验）
// 你也可以根据实验需要扩展 allowlist（但不要用于未授权公网扫描）。
fn is_allowed_net(net: &Ipv4Net) -> bool {
    let first = net.network();
    let last = net.broadcast();
    is_allowed_ip(first) && is_allowed_ip(last)
}

fn is_allowed_ip(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || is_cgnat(ip)
        || is_doc_net(ip)
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    // 100.64.0.0/10
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000
}

fn is_doc_net(ip: Ipv4Addr) -> bool {
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    let o = ip.octets();
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn probe_versions(peer_addr: SocketAddr) -> Result<Vec<u32>, Box<dyn Error>> {
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;

    // connect() 后 recv() 只收来自该 peer 的包，避免串包
    socket.connect(peer_addr)?;

    let mut scid = [0u8; 8];
    let mut dcid = [0u8; 8];
    SystemRandom::new().fill(&mut scid).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::Other, "ring::rand::SystemRandom::fill failed")
    })?;
    SystemRandom::new().fill(&mut dcid).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::Other, "ring::rand::SystemRandom::fill failed")
    })?;

    let packet = build_initial_packet(&scid, &dcid)?;
    socket.send(&packet)?;

    let mut buf = [0u8; 65535];
    let len = socket.recv(&mut buf)?;

    let mut pkt = buf[..len].to_vec();
    let header = quiche::Header::from_slice(&mut pkt, quiche::MAX_CONN_ID_LEN)?;

    if header.ty != quiche::packet::Type::VersionNegotiation {
        return Err(format!("unexpected packet type: {:?}", header.ty).into());
    }

    Ok(header.versions.unwrap_or_default())
}

fn build_initial_packet(scid: &[u8], dcid: &[u8]) -> Result<Vec<u8>, quiche::Error> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut b = octets::OctetsMut::with_slice(&mut out);

    let hdr = quiche::Header {
        ty: quiche::packet::Type::Initial,
        version: UNSUPPORTED_VERSION,
        dcid: quiche::ConnectionId::from_ref(dcid),
        scid: quiche::ConnectionId::from_ref(scid),
        pkt_num: 0,
        pkt_num_len: PACKET_NUMBER_LEN,
        token: None,
        versions: None,
        key_phase: false,
    };

    hdr.to_bytes(&mut b)?;

    let header_len = b.off();

    // total = header_len + varint_len(length) + length >= MIN_INITIAL_SIZE
    let mut length = PACKET_NUMBER_LEN;

    for _ in 0..4 {
        let length_len = octets::varint_len(length as u64);
        let desired_length = MIN_INITIAL_SIZE
            .saturating_sub(header_len + length_len)
            .max(PACKET_NUMBER_LEN);

        if desired_length == length {
            break;
        }
        length = desired_length;
    }

    let padding_len = length.saturating_sub(PACKET_NUMBER_LEN);

    b.put_varint(length as u64)?;
    b.put_u8(0)?; // packet number

    if padding_len > 0 {
        let zeros = vec![0u8; padding_len];
        b.put_bytes(&zeros)?;
    }

    let total_len = b.off();
    out.truncate(total_len);
    Ok(out)
}
