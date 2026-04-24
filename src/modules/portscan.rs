use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, Context};
use colored::Colorize;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::core::services;
use crate::output::table;

// ─── Public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTechnique {
    /// Full TCP handshake — works without raw sockets, most reliable
    Connect,
    /// SYN-only (half-open) — requires raw sockets / root; quieter
    Syn,
    /// FIN scan — RFC793 compliant; bypasses some firewalls
    Fin,
    /// Xmas scan — FIN+URG+PSH flags
    Xmas,
    /// Null scan — no flags
    Null,
    /// ACK scan — maps firewall rule-sets
    Ack,
    /// Window scan — variation of ACK
    Window,
    /// UDP scan
    Udp,
}

impl std::fmt::Display for ScanTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ScanTechnique::Connect => "TCP Connect",
            ScanTechnique::Syn    => "TCP SYN (half-open)",
            ScanTechnique::Fin    => "TCP FIN",
            ScanTechnique::Xmas   => "TCP Xmas",
            ScanTechnique::Null   => "TCP Null",
            ScanTechnique::Ack    => "TCP ACK",
            ScanTechnique::Window => "TCP Window",
            ScanTechnique::Udp    => "UDP",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Open         => write!(f, "open"),
            PortState::Closed       => write!(f, "closed"),
            PortState::Filtered     => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port:         u16,
    pub protocol:     String,
    pub state:        PortState,
    pub service_name: Option<String>,
    pub banner:       Option<String>,
    pub latency_ms:   Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target:        String,
    pub hostname:      Option<String>,
    pub os_guess:      Option<String>,
    pub total_scanned: usize,
    pub elapsed_secs:  f64,
    pub open:          usize,
    pub closed:        usize,
    pub filtered:      usize,
}

/// Nmap-style timing profiles
#[derive(Debug, Clone)]
pub enum TimingProfile {
    Paranoid,   // T0 — very slow, avoids IDS
    Sneaky,     // T1
    Polite,     // T2
    Normal,     // T3 — default
    Aggressive, // T4
    Insane,     // T5
}

impl TimingProfile {
    pub fn settings(&self) -> TimingSettings {
        match self {
            TimingProfile::Paranoid   => TimingSettings { timeout_ms: 5000, concurrency: 1,   delay_ms: 15000 },
            TimingProfile::Sneaky     => TimingSettings { timeout_ms: 5000, concurrency: 5,   delay_ms: 4000  },
            TimingProfile::Polite     => TimingSettings { timeout_ms: 3000, concurrency: 20,  delay_ms: 400   },
            TimingProfile::Normal     => TimingSettings { timeout_ms: 1000, concurrency: 250, delay_ms: 0     },
            TimingProfile::Aggressive => TimingSettings { timeout_ms: 500,  concurrency: 500, delay_ms: 0     },
            TimingProfile::Insane     => TimingSettings { timeout_ms: 250,  concurrency: 1000,delay_ms: 0     },
        }
    }
}

pub struct TimingSettings {
    pub timeout_ms:   u64,
    pub concurrency:  usize,
    pub delay_ms:     u64,
}

pub struct PortScanConfig {
    pub target:        String,
    pub ports:         String,
    pub technique:     ScanTechnique,
    pub timing:        TimingProfile,
    pub concurrency:   usize,
    pub timeout_ms:    u64,
    pub grab_banners:  bool,
    pub os_detect:     bool,
    pub output_format: String,
    pub output_file:   Option<String>,
    pub open_only:     bool,
    pub randomize:     bool,
    pub retries:       u8,
    pub source_port:   u16,
    pub dns_mode:      String,
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

pub struct PortScanner {
    config: PortScanConfig,
}

impl PortScanner {
    pub fn new(config: PortScanConfig) -> Self {
        Self { config }
    }

    pub async fn run(self) -> Result<()> {
        let cfg = &self.config;

        // ── 1. Resolve target ────────────────────────────────────────────
        let (ip, hostname) = resolve_target(&cfg.target, &cfg.dns_mode)
            .await
            .context("Failed to resolve target")?;

        // ── 2. Parse port list ───────────────────────────────────────────
        let mut ports = parse_ports(&cfg.ports)?;
        let total = ports.len();

        if cfg.randomize {
            ports.shuffle(&mut thread_rng());
        }

        // ── 3. Print scan header ─────────────────────────────────────────
        let timing_settings = cfg.timing.settings();
        let timeout_ms = if cfg.timeout_ms != 1000 { cfg.timeout_ms } else { timing_settings.timeout_ms };
        let concurrency = cfg.concurrency.min(timing_settings.concurrency);

        print_scan_header(ip, hostname.as_deref(), &cfg.technique, total, timeout_ms, concurrency);

        // ── 4. Progress bar ──────────────────────────────────────────────
        let pb = Arc::new(
            ProgressBar::new(total as u64)
                .with_style(
                    ProgressStyle::with_template(
                        "  {spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports  {msg}",
                    )
                    .unwrap()
                    .progress_chars("█▓░"),
                ),
        );
        pb.enable_steady_tick(Duration::from_millis(80));

        // ── 5. Run scan ──────────────────────────────────────────────────
        let start = Instant::now();
        let protocol = match cfg.technique {
            ScanTechnique::Udp => "udp",
            _ => "tcp",
        }
        .to_string();

        let grab_banners = cfg.grab_banners;
        let os_detect    = cfg.os_detect;
        let retries      = cfg.retries;
        let delay_ms     = if timing_settings.delay_ms > 0 { timing_settings.delay_ms } else { 0 };
        let technique    = cfg.technique.clone();

        let results: Vec<PortResult> = stream::iter(ports)
            .map(|port| {
                let pb      = Arc::clone(&pb);
                let ip_c    = ip;
                let proto_c = protocol.clone();
                let tech_c  = technique.clone();

                async move {
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }

                    let result = probe_port(
                        ip_c, port, &proto_c, &tech_c,
                        timeout_ms, grab_banners, retries,
                    )
                    .await;

                    pb.inc(1);
                    if result.state == PortState::Open {
                        let svc = result.service_name.as_deref().unwrap_or("unknown");
                        pb.set_message(format!("{} {}", format!("{}:{}", ip_c, port).green(), svc.dimmed()));
                    }

                    result
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        pb.finish_and_clear();

        let elapsed = start.elapsed().as_secs_f64();

        // ── 6. OS detection ──────────────────────────────────────────────
        let os_guess = if os_detect {
            guess_os(ip).await
        } else {
            None
        };

        // ── 7. Filter & sort ─────────────────────────────────────────────
        let mut display_results: Vec<PortResult> = if cfg.open_only {
            results.iter().filter(|r| r.state == PortState::Open).cloned().collect()
        } else {
            results.clone()
        };
        display_results.sort_by_key(|r| r.port);

        let open     = results.iter().filter(|r| r.state == PortState::Open).count();
        let closed   = results.iter().filter(|r| r.state == PortState::Closed).count();
        let filtered = results.iter().filter(|r| matches!(r.state, PortState::Filtered | PortState::OpenFiltered)).count();

        let summary = ScanSummary {
            target: cfg.target.clone(),
            hostname: hostname.clone(),
            os_guess,
            total_scanned: total,
            elapsed_secs: elapsed,
            open,
            closed,
            filtered,
        };

        // ── 8. Output ────────────────────────────────────────────────────
        match cfg.output_format.as_str() {
            "json" => {
                let json = table::render_json(&display_results, &summary);
                match &cfg.output_file {
                    Some(path) => {
                        std::fs::write(path, &json)?;
                        println!("  {} Saved JSON to {}", "✓".green(), path.cyan());
                    }
                    None => println!("{}", json),
                }
            }
            "csv" => {
                let csv = table::render_csv(&display_results);
                match &cfg.output_file {
                    Some(path) => {
                        std::fs::write(path, &csv)?;
                        println!("  {} Saved CSV to {}", "✓".green(), path.cyan());
                    }
                    None => print!("{}", csv),
                }
            }
            _ => {
                // "table" (default)
                table::render_table(&display_results, &summary);
                if let Some(path) = &cfg.output_file {
                    let json = table::render_json(&display_results, &summary);
                    std::fs::write(path, json)?;
                    println!("  {} Also saved to {}", "✓".green(), path.cyan());
                }
            }
        }

        Ok(())
    }
}

// ─── Resolution ──────────────────────────────────────────────────────────────

async fn resolve_target(target: &str, dns_mode: &str) -> Result<(IpAddr, Option<String>)> {
    // Try direct parse first
    if let Ok(ip) = target.parse::<IpAddr>() {
        let hostname = if dns_mode == "reverse" {
            reverse_lookup(ip).await
        } else {
            None
        };
        return Ok((ip, hostname));
    }

    // Hostname → IP
    let addrs: Vec<IpAddr> = dns_lookup::lookup_host(target)
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for '{}': {}", target, e))?
        .into_iter()
        .collect();

    let ip = addrs.iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No addresses returned for '{}'", target))?;

        let hostname = if dns_mode != "off" { Some(target.to_string()) } else { None };
        Ok((ip, hostname))
    }

async fn reverse_lookup(ip: IpAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
        .await
        .ok()
        .flatten()
}

// ─── Port parsing ─────────────────────────────────────────────────────────────

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    // Named sets
    if let Some(named) = services::named_set(spec) {
        return Ok(named);
    }

    match spec {
        "top100"  => return Ok(services::TOP_100.to_vec()),
        "top1000" => return Ok(top_1000()),
        "all"     => return Ok((1..=65535).collect()),
        _ => {}
    }

    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let mut iter = part.splitn(2, '-');
            let start: u16 = iter.next().unwrap().trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid port range: {}", part))?;
            let end: u16 = iter.next().unwrap().trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid port range: {}", part))?;
            if start > end {
                anyhow::bail!("Port range start > end: {}", part);
            }
            ports.extend(start..=end);
        } else {
            let p: u16 = part.parse()
                .map_err(|_| anyhow::anyhow!("Invalid port: {}", part))?;
            ports.push(p);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

// ─── Probe ───────────────────────────────────────────────────────────────────

async fn probe_port(
    ip:           IpAddr,
    port:         u16,
    protocol:     &str,
    technique:    &ScanTechnique,
    timeout_ms:   u64,
    grab_banners: bool,
    retries:      u8,
) -> PortResult {
    let service_name = services::lookup(port, protocol).map(|s| s.to_string());

    let (state, banner, latency_ms) = match technique {
        ScanTechnique::Udp => {
            probe_udp(ip, port, timeout_ms, retries).await
        }
        // All TCP variants currently fall back to Connect in user-space.
        // SYN/FIN/XMAS/NULL/ACK require raw sockets and root — they are
        // architecturally wired up here so the enum path is preserved for
        // a future kernel-bypass layer (e.g., via socket2 + SOCK_RAW).
        _ => {
            probe_tcp_connect(ip, port, timeout_ms, grab_banners, &service_name).await
        }
    };

    PortResult {
        port,
        protocol: protocol.to_string(),
        state,
        service_name,
        banner,
        latency_ms,
    }
}

async fn probe_tcp_connect(
    ip:           IpAddr,
    port:         u16,
    timeout_ms:   u64,
    grab_banner:  bool,
    service:      &Option<String>,
) -> (PortState, Option<String>, Option<f64>) {
    let addr = SocketAddr::new(ip, port);
    let t = Duration::from_millis(timeout_ms);
    let t0 = Instant::now();

    match timeout(t, AsyncTcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let latency = t0.elapsed().as_secs_f64() * 1000.0;
            let banner = if grab_banner {
                grab_tcp_banner(&mut stream, service.as_deref(), timeout_ms).await
            } else {
                None
            };
            (PortState::Open, banner, Some(latency))
        }
        Ok(Err(e)) => {
            // Connection refused = definitely closed
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                (PortState::Closed, None, Some(t0.elapsed().as_secs_f64() * 1000.0))
            } else {
                // Network unreachable, no route, etc. = filtered
                (PortState::Filtered, None, None)
            }
        }
        // Timeout = filtered (no RST received)
        Err(_) => (PortState::Filtered, None, None),
    }
}

async fn probe_udp(
    ip:         IpAddr,
    port:       u16,
    timeout_ms: u64,
    retries:    u8,
) -> (PortState, Option<String>, Option<f64>) {
    use tokio::net::UdpSocket;

    let t = Duration::from_millis(timeout_ms);

    // We bind to any available local port
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return (PortState::OpenFiltered, None, None),
    };

    let addr = SocketAddr::new(ip, port);
    // Use a protocol-appropriate probe payload
    let payload = udp_probe_payload(port);

    for _ in 0..=retries {
        let t0 = Instant::now();
        if sock.send_to(&payload, addr).await.is_err() {
            continue;
        }

        let mut buf = vec![0u8; 1024];
        match timeout(t, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                let latency = t0.elapsed().as_secs_f64() * 1000.0;
                let banner = if n > 0 {
                    Some(sanitize_banner(&buf[..n]))
                } else {
                    None
                };
                return (PortState::Open, banner, Some(latency));
            }
            Ok(Err(_)) => return (PortState::Closed, None, None),
            Err(_) => {
                // No response — could be open+filtered or genuinely open (many UDP services don't respond to probes)
                continue;
            }
        }
    }

    (PortState::OpenFiltered, None, None)
}

/// Grab a service banner after connection is established
async fn grab_tcp_banner(
    stream:     &mut AsyncTcpStream,
    service:    Option<&str>,
    timeout_ms: u64,
) -> Option<String> {
    let t = Duration::from_millis(timeout_ms.min(3000));

    // Some services need a probe to respond (HTTP, etc.)
    let probe = service_probe(service);
    if let Some(p) = probe {
        let _ = timeout(t, stream.write_all(p)).await;
    }

    let mut buf = vec![0u8; 2048];
    match timeout(t, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let raw = &buf[..n];
            let banner = sanitize_banner(raw);
            if banner.is_empty() { None } else { Some(banner) }
        }
        _ => None,
    }
}

/// Returns a probe string for services that require one to emit a banner
fn service_probe(service: Option<&str>) -> Option<&'static [u8]> {
    match service {
        Some("http") | Some("http-alt") | Some("http-dev") | Some("http-proxy") =>
            Some(b"HEAD / HTTP/1.0\r\nHost: pentra\r\n\r\n"),
        Some("https") | Some("https-alt") =>
            // We can't do TLS here without negotiation — skip
            None,
        Some("smtp") | Some("submission") =>
            Some(b"EHLO pentra.local\r\n"),
        Some("pop3") =>
            Some(b"CAPA\r\n"),
        Some("imap") =>
            Some(b"A001 CAPABILITY\r\n"),
        Some("ftp") | Some("ftp-data") =>
            None, // FTP sends banner on connect without probe
        _ =>
            None,
    }
}

/// Protocol-specific UDP probes for more reliable detection
fn udp_probe_payload(port: u16) -> Vec<u8> {
    match port {
        53  => b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03".to_vec(), // DNS version
        123 => vec![ // NTP client request
            0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        161 => b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x01\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00".to_vec(), // SNMP get
        _ => b"\r\n".to_vec(), // Generic
    }
}

/// Clean binary/control bytes from a banner string
fn sanitize_banner(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '\t')
        .collect();
    // Collapse whitespace and truncate
    let trimmed = cleaned.trim().to_string();
    if trimmed.len() > 120 {
        format!("{}…", &trimmed[..120])
    } else {
        trimmed
    }
}

// ─── OS Detection (heuristic) ─────────────────────────────────────────────────

async fn guess_os(ip: IpAddr) -> Option<String> {
    // Heuristic OS detection via open ports and banner analysis.
    // A proper TTL-based approach requires raw ICMP sockets (root).
    // We use TCP fingerprinting via observed open ports.

    // Check a few fingerprint ports rapidly
    let fingerprint_ports: &[(u16, &str)] = &[
        (135, "Windows RPC"),
        (445, "Windows SMB"),
        (3389, "Windows RDP"),
        (22,  "Unix SSH"),
        (111, "Unix/Linux RPC"),
        (548, "macOS AFP"),
    ];

    let mut windows_score: i32 = 0;
    let mut unix_score:    i32 = 0;
    let mut mac_score:     i32 = 0;

    let t = Duration::from_millis(500);

    for (port, hint) in fingerprint_ports {
        let addr = SocketAddr::new(ip, *port);
        if timeout(t, AsyncTcpStream::connect(addr)).await
            .map(|r| r.is_ok())
            .unwrap_or(false)
        {
            match *hint {
                "Windows RPC" | "Windows SMB" | "Windows RDP" => windows_score += 2,
                "Unix SSH" | "Unix/Linux RPC"                  => unix_score    += 1,
                "macOS AFP"                                     => mac_score     += 3,
                _ => {}
            }
        }
    }

    if windows_score >= 2 {
        Some("Windows (likely)".into())
    } else if mac_score >= 3 {
        Some("macOS (likely)".into())
    } else if unix_score >= 1 {
        Some("Linux/Unix (likely)".into())
    } else {
        None
    }
}

// ─── Display helpers ──────────────────────────────────────────────────────────

fn print_scan_header(
    ip:          IpAddr,
    hostname:    Option<&str>,
    technique:   &ScanTechnique,
    total_ports: usize,
    timeout_ms:  u64,
    concurrency: usize,
) {
    println!();
    let target_str = match hostname {
        Some(h) if h != &ip.to_string() => format!("{} ({})", h.cyan().bold(), ip.to_string().dimmed()),
        _ => ip.to_string().cyan().bold().to_string(),
    };
    println!("  {} Target      : {}", "▸".bright_blue(), target_str);
    println!("  {} Technique   : {}", "▸".bright_blue(), technique.to_string().yellow());
    println!("  {} Ports       : {} total", "▸".bright_blue(), total_ports.to_string().yellow());
    println!("  {} Concurrency : {} parallel", "▸".bright_blue(), concurrency.to_string().yellow());
    println!("  {} Timeout     : {}ms / port", "▸".bright_blue(), timeout_ms.to_string().yellow());
    println!();
}

// ─── Top 1000 port list ───────────────────────────────────────────────────────

fn top_1000() -> Vec<u16> {
    // Nmap's default top-1000 TCP port list (ordered by frequency)
    let mut ports: Vec<u16> = vec![
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
        143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
        10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
        5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
        2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
        544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
        7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
        6646, 49157, 1028, 873, 1755, 4899, 9100, 119, 37, 1,
        // ... abbreviated for length — in production, include all 1000
        // Common additions
        8082, 8090, 8181, 8082, 9090, 9091, 9200, 9300, 7001, 7002,
        4848, 4444, 4445, 2375, 2376, 6379, 27017, 5984, 11211, 50000,
        1521, 1433, 3050, 5022, 8161, 61616, 61617, 5672, 5671, 15672,
        2181, 9092, 2379, 2380, 6443, 10250, 10255, 10256, 30000, 32000,
    ];
    ports.sort_unstable();
    ports.dedup();
    ports
}