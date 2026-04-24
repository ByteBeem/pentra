use clap::{Parser, Subcommand};
use anyhow::Result;

use crate::modules::portscan::{PortScanConfig, PortScanner, ScanTechnique, TimingProfile};
use crate::output::banner;

#[derive(Parser)]
#[command(
    name = "pentra",
    about = "A lightweight, modular penetration testing platform",
    long_about = None,
    version,
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Suppress banner
    #[arg(global = true, long, short = 'q')]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Advanced port scanner with OS fingerprinting, service detection, and banner grabbing
    Scan {
        /// Target IP, hostname, or CIDR range (e.g. 192.168.1.1, host.com, 10.0.0.0/24)
        #[arg(short, long)]
        target: String,

        /// Port specification: single (80), range (1-1024), list (22,80,443), or named sets
        /// Named sets: top100, top1000, all, web, db, mail, smb, voip
        #[arg(short, long, default_value = "top1000")]
        ports: String,

        /// Scan technique: syn, connect, fin, xmas, null, ack, udp, window
        #[arg(long, default_value = "connect", value_parser = parse_technique)]
        technique: ScanTechnique,

        /// Timing profile: paranoid, sneaky, polite, normal, aggressive, insane
        #[arg(long, short = 'T', default_value = "normal", value_parser = parse_timing)]
        timing: TimingProfile,

        /// Max concurrent connections
        #[arg(long, default_value = "250")]
        concurrency: usize,

        /// Per-port timeout in milliseconds
        #[arg(long, default_value = "1000")]
        timeout: u64,

        /// Grab service banners (slower but more info)
        #[arg(long, short = 'b')]
        banners: bool,

        /// Attempt OS fingerprinting via TTL and TCP window analysis
        #[arg(long)]
        os_detect: bool,

        /// Output format: table, json, csv
        #[arg(long, short = 'o', default_value = "table")]
        output: String,

        /// Save results to file
        #[arg(long, short = 'f')]
        file: Option<String>,

        /// Only show open ports (suppress closed/filtered)
        #[arg(long)]
        open_only: bool,

        /// Randomize port scan order (evasion)
        #[arg(long, short = 'r')]
        randomize: bool,

        /// Max retries per port for UDP or unreliable connections
        #[arg(long, default_value = "1")]
        retries: u8,

        /// Source port to use (0 = random)
        #[arg(long, default_value = "0")]
        source_port: u16,

        /// DNS resolution: on, off, reverse
        #[arg(long, default_value = "on")]
        dns: String,
    },
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        if !self.quiet {
            banner::print_banner();
        }

        match self.command {
            Commands::Scan {
                target,
                ports,
                technique,
                timing,
                concurrency,
                timeout,
                banners,
                os_detect,
                output,
                file,
                open_only,
                randomize,
                retries,
                source_port,
                dns,
            } => {
                let config = PortScanConfig {
                    target,
                    ports,
                    technique,
                    timing,
                    concurrency,
                    timeout_ms: timeout,
                    grab_banners: banners,
                    os_detect,
                    output_format: output,
                    output_file: file,
                    open_only,
                    randomize,
                    retries,
                    source_port,
                    dns_mode: dns,
                };

                let scanner = PortScanner::new(config);
                scanner.run().await?;
            }
        }

        Ok(())
    }
}

fn parse_technique(s: &str) -> Result<ScanTechnique, String> {
    match s.to_lowercase().as_str() {
        "syn" => Ok(ScanTechnique::Syn),
        "connect" => Ok(ScanTechnique::Connect),
        "fin" => Ok(ScanTechnique::Fin),
        "xmas" => Ok(ScanTechnique::Xmas),
        "null" => Ok(ScanTechnique::Null),
        "ack" => Ok(ScanTechnique::Ack),
        "udp" => Ok(ScanTechnique::Udp),
        "window" => Ok(ScanTechnique::Window),
        other => Err(format!("Unknown technique: '{}'. Use: syn, connect, fin, xmas, null, ack, udp, window", other)),
    }
}

fn parse_timing(s: &str) -> Result<TimingProfile, String> {
    match s.to_lowercase().as_str() {
        "paranoid" | "t0" | "0" => Ok(TimingProfile::Paranoid),
        "sneaky"   | "t1" | "1" => Ok(TimingProfile::Sneaky),
        "polite"   | "t2" | "2" => Ok(TimingProfile::Polite),
        "normal"   | "t3" | "3" => Ok(TimingProfile::Normal),
        "aggressive"| "t4"| "4" => Ok(TimingProfile::Aggressive),
        "insane"   | "t5" | "5" => Ok(TimingProfile::Insane),
        other => Err(format!("Unknown timing: '{}'. Use: paranoid, sneaky, polite, normal, aggressive, insane (or T0-T5)", other)),
    }
}
