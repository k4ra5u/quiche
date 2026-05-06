// Copyright (C) 2024, Cloudflare, Inc.
// All rights reserved.
//
// This file is a merged version of two similar QUIC probing clients.
// - Streaming JSONL input/output (crash-friendly)
// - Hard connect timeout (default 10s)
// - Better version selection
// - More complete quiche config and more reasonable poll timeout usage
// - Clear SNI semantics: attempted vs succeeded

use quiche_apps::args::CommonArgs;
use quiche_apps::common::generate_cid_and_reset_token;

use mio::net::UdpSocket;
use ring::rand::{SecureRandom, SystemRandom};

use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_PORT: u16 = 443;
const MAX_CONNECT_TIME: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
struct InputRecord {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: Option<String>,
    versions: Option<String>,
    pdns: Option<PdnsRecord>,
}

#[derive(Debug, Deserialize)]
struct PdnsRecord {
    current_domains: Vec<String>,
    historical_domains: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OutputRecord {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: u16,

    /// The domain that succeeded (if any).
    selected_domain: Option<String>,

    /// Whether we attempted SNI/domain binding at all.
    sni_attempted: bool,

    /// Whether a SNI attempt actually succeeded (selected_domain is Some).
    sni_succeeded: bool,

    /// "connected" or "failed"
    status: String,

    /// Optional machine-friendly note / error string.
    note: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder().format_timestamp_nanos().init();

    let mut args = std::env::args().skip(1);
    let input_path = args
        .next()
        .ok_or("usage: test-client <input.jsonl> <output.jsonl>")?;
    let output_path = args
        .next()
        .ok_or("usage: test-client <input.jsonl> <output.jsonl>")?;

    let input = File::open(input_path)?;
    let mut output = File::create(output_path)?;

    let reader = BufReader::new(input);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let record: InputRecord = serde_json::from_str(&line)?;

        let port = record
            .port
            .as_deref()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);

        let version = choose_version(record.versions.as_deref());
        let domains = collect_domains(record.pdns.as_ref());

        // Build attempt list:
        // - If no domains: try once with None (no SNI)
        // - If domains exist: try each domain as SNI in order
        let mut attempts: Vec<Option<String>> = Vec::new();
        if domains.is_empty() {
            attempts.push(None);
        } else {
            attempts.extend(domains.into_iter().map(Some));
        }

        let sni_attempted = attempts.iter().any(|a| a.is_some());

        let mut selected_domain: Option<String> = None;
        let mut status = "failed".to_string();
        let mut note: Option<String> = None;

        for attempt in attempts {
            let sni = attempt.as_deref();

            match connect_and_test(&record.ip, port, sni, version, MAX_CONNECT_TIME) {
                Ok(true) => {
                    selected_domain = attempt;
                    status = "connected".to_string();
                    note = None;
                    break;
                },
                Ok(false) => {
                    // handshake/connect not established within timeout or closed early
                    // keep trying next domain if any
                    note = Some("handshake_failed".to_string());
                    continue;
                },
                Err(err) => {
                    // Local errors (bind/poll/send/recv/resolve) likely affect all attempts.
                    note = Some(format!("connection_error: {err}"));
                    break;
                },
            }
        }

        if status != "connected" {
            // Make note more explicit depending on whether we had domains.
            if !sni_attempted {
                note.get_or_insert_with(|| "no_domains_connection_failed".to_string());
            } else {
                note.get_or_insert_with(|| "all_domains_failed".to_string());
            }
        }

        let result = OutputRecord {
            row: record.row,
            ip: record.ip,
            port,
            selected_domain: selected_domain.clone(),
            sni_attempted,
            sni_succeeded: selected_domain.is_some(),
            status,
            note,
        };

        writeln!(output, "{}", serde_json::to_string(&result)?)?;
    }

    Ok(())
}

fn collect_domains(pdns: Option<&PdnsRecord>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    if let Some(p) = pdns {
        for d in p.current_domains.iter().chain(p.historical_domains.iter()) {
            let dd = d.trim();
            if dd.is_empty() {
                continue;
            }
            if seen.insert(dd.to_string()) {
                out.push(dd.to_string());
            }
        }
    }

    out
}

/// Version selection rules (merged & slightly hardened):
/// 1) If versions contains 0x00000001 => pick it.
/// 2) Else: parse all versions, pick the first quiche::Config::new(v) that works.
/// 3) Else: fallback to quiche::PROTOCOL_VERSION.
fn choose_version(versions: Option<&str>) -> u32 {
    let parsed = parse_versions(versions);

    if parsed.iter().any(|v| *v == 0x0000_0001) {
        return 0x0000_0001;
    }

    for v in parsed {
        if quiche::Config::new(v).is_ok() {
            return v;
        }
    }

    quiche::PROTOCOL_VERSION
}

fn parse_versions(versions: Option<&str>) -> Vec<u32> {
    let mut parsed = Vec::new();

    let Some(s) = versions else {
        return parsed;
    };

    for token in s.split_whitespace() {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }

        let raw = t.strip_prefix("0x").unwrap_or(t);
        if let Ok(v) = u32::from_str_radix(raw, 16) {
            parsed.push(v);
        }
    }

    parsed
}

fn format_peer_addr(ip: &str, port: u16) -> String {
    // Robust formatting for IPv6 literals without brackets.
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn connect_and_test(
    ip: &str,
    port: u16,
    sni: Option<&str>,
    version: u32,
    max_time: Duration,
) -> Result<bool, String> {
    let peer_str = format_peer_addr(ip, port);

    let peer_addr = peer_str
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "no peer address".to_string())?;

    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let mut socket = UdpSocket::bind(
        bind_addr
            .parse()
            .map_err(|e| format!("bind parse failed: {e}"))?,
    )
    .map_err(|e| format!("bind failed: {e}"))?;

    let mut poll = mio::Poll::new().map_err(|e| format!("poll: {e}"))?;
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .map_err(|e| format!("poll register: {e}"))?;

    // Config: try requested version first, fallback to default protocol version.
    let mut config = quiche::Config::new(version)
        .or_else(|_| quiche::Config::new(quiche::PROTOCOL_VERSION))
        .map_err(|e| format!("config: {e}"))?;

    configure(&mut config)?;

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))?;

    let rng = SystemRandom::new();
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid_bytes)
        .map_err(|e| format!("rand scid: {e:?}"))?;
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn =
        quiche::connect(sni, &scid, local_addr, peer_addr, &mut config)
            .map_err(|e| format!("connect: {e}"))?;

    let mut buf = [0u8; 65535];
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    let start = Instant::now();
    let deadline = start + max_time;

    let mut events = mio::Events::with_capacity(128);

    let mut established = false;
    let mut sent_tests = false;

    // Send initial packets.
    send_pending(&mut conn, &mut socket, &mut out)?;

    loop {
        // Hard timeout.
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }

        // Poll timeout = min(quiche_timeout, remaining_time).
        let remaining = deadline.saturating_duration_since(now);
        let quiche_to = conn.timeout().unwrap_or(Duration::from_millis(50));
        let poll_timeout = std::cmp::min(quiche_to, remaining);

        poll.poll(&mut events, Some(poll_timeout))
            .map_err(|e| format!("poll: {e}"))?;

        if events.is_empty() {
            conn.on_timeout();
        }

        for event in events.iter() {
            if event.token() != mio::Token(0) {
                continue;
            }

            loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(format!("recv failed: {e}")),
                };

                let recv_info = quiche::RecvInfo { from, to: local_addr };

                match conn.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(format!("conn recv: {e}")),
                }
            }
        }

        if conn.is_established() && !sent_tests {
            established = true;
            send_test_frames(&mut conn, &rng, local_addr, peer_addr)?;
            let _ = conn.close(true, 0x00, b"done");
            sent_tests = true;
        }

        send_pending(&mut conn, &mut socket, &mut out)?;

        if conn.is_closed() {
            break;
        }
    }

    Ok(established)
}

fn configure(config: &mut quiche::Config) -> Result<(), String> {
    let common = CommonArgs::default();

    config.verify_peer(false);

    // Use the quiche-apps CommonArgs ALPN list (more general than only HTTP/3).
    config
        .set_application_protos(&common.alpns)
        .map_err(|e| format!("alpn: {e}"))?;

    config.set_max_idle_timeout(common.idle_timeout);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);

    config.set_initial_max_data(common.max_data);
    config.set_initial_max_stream_data_bidi_local(common.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(common.max_stream_data);
    config.set_initial_max_stream_data_uni(common.max_stream_data);
    config.set_initial_max_streams_bidi(common.max_streams_bidi);
    config.set_initial_max_streams_uni(common.max_streams_uni);

    // Extra config from code-2:
    config.set_disable_active_migration(!common.enable_active_migration);
    config.set_active_connection_id_limit(common.max_active_cids);
    config.set_max_connection_window(common.max_window);
    config.set_max_stream_window(common.max_stream_window);
    config
        .set_cc_algorithm_name(&common.cc_algorithm)
        .map_err(|e| format!("cc: {e}"))?;
    config.enable_hystart(!common.disable_hystart);

    Ok(())
}

fn send_test_frames(
    conn: &mut quiche::Connection,
    rng: &SystemRandom,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), String> {
    let _ = conn.stream_send(0, b"Hello", true);
    let _ = conn.probe_path(local_addr, peer_addr);

    // Safer: check if we can issue a new SCID.
    if conn.scids_left() > 0 {
        let (new_scid, reset_token) = generate_cid_and_reset_token(rng);
        let _ = conn.new_scid(&new_scid, reset_token, false);
    }

    Ok(())
}

fn send_pending(
    conn: &mut quiche::Connection,
    socket: &mut UdpSocket,
    out: &mut [u8; MAX_DATAGRAM_SIZE],
) -> Result<(), String> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => {
                match socket.send_to(&out[..write], send_info.to) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(format!("send_to failed: {e}")),
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(format!("send failed: {e}")),
        }
    }

    Ok(())
}
