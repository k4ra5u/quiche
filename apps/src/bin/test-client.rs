// Copyright (C) 2024, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use quiche_apps::args::CommonArgs;
use quiche_apps::common::generate_cid_and_reset_token;

use mio::net::UdpSocket;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug, Deserialize)]
struct InputRow {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: Option<String>,
    versions: Option<String>,
    pdns: Option<Pdns>,
}

#[derive(Debug, Deserialize)]
struct Pdns {
    current_domains: Vec<String>,
    historical_domains: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OutputRow {
    #[serde(rename = "_row")]
    row: Option<u64>,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: u16,
    selected_domain: Option<String>,
    sni_used: bool,
    status: String,
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

        let row: InputRow = serde_json::from_str(&line)?;
        let port = row
            .port
            .as_deref()
            .unwrap_or("443")
            .parse::<u16>()
            .unwrap_or(443);
        let version = select_version(&row.versions);

        let mut domains = Vec::new();
        if let Some(pdns) = &row.pdns {
            domains.extend(pdns.current_domains.iter().cloned());
            domains.extend(pdns.historical_domains.iter().cloned());
        }

        let result = if domains.is_empty() {
            match run_test(&row.ip, port, None, version) {
                Ok(true) => OutputRow {
                    row: row.row,
                    ip: row.ip,
                    port,
                    selected_domain: None,
                    sni_used: false,
                    status: "connected".to_string(),
                    note: Some("no domains provided".to_string()),
                },
                Ok(false) => OutputRow {
                    row: row.row,
                    ip: row.ip,
                    port,
                    selected_domain: None,
                    sni_used: false,
                    status: "failed".to_string(),
                    note: Some("no domains provided".to_string()),
                },
                Err(err) => OutputRow {
                    row: row.row,
                    ip: row.ip,
                    port,
                    selected_domain: None,
                    sni_used: false,
                    status: "failed".to_string(),
                    note: Some(err),
                },
            }
        } else {
            let mut bound_domain = None;
            let mut status = "failed".to_string();
            let mut note = None;

            for domain in domains {
                match run_test(&row.ip, port, Some(&domain), version) {
                    Ok(true) => {
                        bound_domain = Some(domain);
                        status = "connected".to_string();
                        break;
                    },
                    Ok(false) => {
                        note = Some("handshake failed".to_string());
                    },
                    Err(err) => {
                        note = Some(err);
                    },
                }
            }

            if bound_domain.is_none() && note.is_none() {
                note = Some("no domains succeeded".to_string());
            }

            OutputRow {
                row: row.row,
                ip: row.ip,
                port,
                selected_domain: bound_domain,
                sni_used: true,
                status,
                note,
            }
        };

        let line = serde_json::to_string(&result)?;
        writeln!(output, "{}", line)?;
    }

    Ok(())
}

fn select_version(versions: &Option<String>) -> u32 {
    let Some(versions) = versions else {
        return quiche::PROTOCOL_VERSION;
    };

    for entry in versions.split_whitespace() {
        let trimmed = entry.trim();
        let value = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if let Ok(parsed) = u32::from_str_radix(value, 16) {
            if parsed == 0x0000_0001 {
                return parsed;
            }
        }
    }

    quiche::PROTOCOL_VERSION
}

fn run_test(
    ip: &str, port: u16, sni: Option<&str>, version: u32,
) -> Result<bool, String> {
    let peer_addr = format!("{}:{}", ip, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "no peer address".to_string())?;

    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let mut socket = UdpSocket::bind(
        bind_addr.parse().map_err(|e| format!("bind failed: {e}"))?,
    )
    .map_err(|e| format!("bind failed: {e}"))?;

    let mut poll = mio::Poll::new().map_err(|e| format!("poll: {e}"))?;
    let mut events = mio::Events::with_capacity(16);
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .map_err(|e| format!("poll register: {e}"))?;

    let mut config =
        quiche::Config::new(version).map_err(|e| format!("config: {e}"))?;
    let conn_args = CommonArgs::default();
    config.verify_peer(false);
    config
        .set_application_protos(&conn_args.alpns)
        .map_err(|e| format!("alpn: {e}"))?;
    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_active_connection_id_limit(conn_args.max_active_cids);

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))?;
    let rng = SystemRandom::new();
    let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut conn_id).map_err(|e| format!("rand: {e:?}"))?;
    let scid = quiche::ConnectionId::from_ref(&conn_id);

    let mut conn =
        quiche::connect(sni, &scid, local_addr, peer_addr, &mut config)
            .map_err(|e| format!("connect: {e}"))?;

    let mut buf = [0u8; 65535];
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut test_sent = false;
    let mut close_sent = false;

    send_pending(&mut conn, &mut socket, &mut out, local_addr, peer_addr)?;

    loop {
        let timeout = conn.timeout().map(|t| Duration::from_millis(100));
        poll.poll(&mut events, timeout).map_err(|e| e.to_string())?;

        if events.is_empty() {
            conn.on_timeout();
        }

        for event in &events {
            if event.token() != mio::Token(0) {
                continue;
            }

            loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    },
                    Err(e) => return Err(format!("recv failed: {e}")),
                };

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    if e == quiche::Error::Done {
                        break;
                    }
                }
            }
        }

        if conn.is_established() && !test_sent {
            let _ = conn.stream_send(0, b"Hello", true);
            let _ = conn.probe_path(local_addr, peer_addr);
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);
            let _ = conn.new_scid(&scid, reset_token, false);
            test_sent = true;
        }

        if test_sent && !close_sent {
            conn.close(true, 0x00, b"done").ok();
            close_sent = true;
        }

        send_pending(&mut conn, &mut socket, &mut out, local_addr, peer_addr)?;

        if conn.is_closed() {
            return Ok(conn.is_established() && test_sent);
        }
    }
}

fn send_pending(
    conn: &mut quiche::Connection, socket: &mut UdpSocket,
    out: &mut [u8; MAX_DATAGRAM_SIZE], local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), String> {
    loop {
        let (write, send_info) =
            match conn.send_on_path(out, Some(local_addr), Some(peer_addr)) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(format!("send failed: {e}")),
            };

        if let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }
            return Err(format!("send_to failed: {e}"));
        }
    }

    Ok(())
}
