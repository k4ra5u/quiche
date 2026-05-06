use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const MAX_DATAGRAM_SIZE: usize = 1350;
const MIN_INITIAL_SIZE: usize = 1200;
const PACKET_NUMBER_LEN: usize = 1;
const UNSUPPORTED_VERSION: u32 = 0x1a2a3a4a;

#[derive(Debug, Clone)]
struct Target {
    name: String,
    addr: SocketAddr,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args();
    let cmd = args.next().unwrap_or_else(|| "quic-vn-probe".to_string());

    let port_file = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("Usage: {cmd} PORT_FILE");
            eprintln!("Example PORT_FILE line: aioquic: 58443 72,73");
            return Ok(());
        }
    };

    let targets = read_port_file(&port_file)?;
    if targets.is_empty() {
        eprintln!("no valid targets found in {port_file}");
        return Ok(());
    }

    for t in targets {
        match probe_versions(t.addr) {
            Ok(versions) => {
                if versions.is_empty() {
                    println!("{}:{}  ({}): <no versions in VN packet>", t.addr.ip(), t.addr.port(), t.name);
                } else {
                    // 你也可以把输出改成多行；这里默认一行更便于汇总/grep
                    let vers = versions
                        .iter()
                        .map(|v| format!("0x{v:08x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    println!("{}:{}  ({}): {}", t.addr.ip(), t.addr.port(), t.name, vers);
                }
            }
            Err(e) => {
                println!(
                    "{}:{}  ({}): <error: {}>",
                    t.addr.ip(),
                    t.addr.port(),
                    t.name,
                    e
                );
            }
        }
    }

    Ok(())
}

/// 读取形如：
/// aioquic:        58443 72,73
/// cf-quiche:      26443 64,65
/// 的文件，只取“冒号前的名字”和“冒号后第一个整数端口”
fn read_port_file(path: &str) -> Result<Vec<Target>, Box<dyn Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);

    let mut out = Vec::new();

    for (lineno, line) in r.lines().enumerate() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (name_part, rest) = match line.split_once(':') {
            Some(v) => v,
            None => {
                eprintln!("skip line {} (no ':'): {}", lineno + 1, line);
                continue;
            }
        };

        let name = name_part.trim();
        if name.is_empty() {
            eprintln!("skip line {} (empty name): {}", lineno + 1, line);
            continue;
        }

        let mut it = rest.split_whitespace();
        let port_str = match it.next() {
            Some(v) => v,
            None => {
                eprintln!("skip line {} (no port): {}", lineno + 1, line);
                continue;
            }
        };

        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("skip line {} (bad port '{}'): {}", lineno + 1, port_str, line);
                continue;
            }
        };

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        out.push(Target {
            name: name.to_string(),
            addr,
        });
    }

    Ok(out)
}

fn probe_versions(peer_addr: SocketAddr) -> Result<Vec<u32>, Box<dyn Error>> {
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;

    // connect() 之后 recv() 只会接收来自该 peer 的数据，避免多目标探测时串包
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

    // 让 total_size = header_len + varint_len(length) + length == MIN_INITIAL_SIZE
    // length 表示 “length 字段之后的字节数”，这里我们只写 pkt_num(1B) + padding
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

    // payload = pkt_num + padding
    let padding_len = length.saturating_sub(PACKET_NUMBER_LEN);

    b.put_varint(length as u64)?;
    b.put_u8(0)?; // packet number = 0

    if padding_len > 0 {
        // 这里用栈上大块零缓冲分段写也可以；当前写法足够直观
        let zeros = vec![0u8; padding_len];
        b.put_bytes(&zeros)?;
    }

    let total_len = b.off();
    out.truncate(total_len);
    Ok(out)
}
