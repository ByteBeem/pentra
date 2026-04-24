use colored::Colorize;
use comfy_table::{Table, Cell, Color, Attribute, ContentArrangement};
use crate::modules::portscan::{PortResult, PortState, ScanSummary};

pub fn render_table(results: &[PortResult], summary: &ScanSummary) {
    if results.is_empty() {
        println!("{}", "  No open ports found.".yellow());
        return;
    }

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("PORT").add_attribute(Attribute::Bold).fg(Color::Cyan),
            Cell::new("STATE").add_attribute(Attribute::Bold).fg(Color::Cyan),
            Cell::new("SERVICE").add_attribute(Attribute::Bold).fg(Color::Cyan),
            Cell::new("VERSION / BANNER").add_attribute(Attribute::Bold).fg(Color::Cyan),
            Cell::new("LATENCY").add_attribute(Attribute::Bold).fg(Color::Cyan),
        ]);

    for r in results {
        let port_str = format!("{}/{}", r.port, r.protocol);
        let (state_cell, state_color) = match r.state {
            PortState::Open     => (Cell::new("open").fg(Color::Green), Color::Green),
            PortState::Closed   => (Cell::new("closed").fg(Color::Red), Color::Red),
            PortState::Filtered => (Cell::new("filtered").fg(Color::Yellow), Color::Yellow),
            PortState::OpenFiltered => (Cell::new("open|filtered").fg(Color::Yellow), Color::Yellow),
        };

        let service = r.service_name.as_deref().unwrap_or("unknown");
        let banner = r.banner.as_deref().unwrap_or("-");
        let latency = r.latency_ms
            .map(|l| format!("{:.1}ms", l))
            .unwrap_or_else(|| "-".into());

        table.add_row(vec![
            Cell::new(&port_str).fg(state_color),
            state_cell,
            Cell::new(service),
            Cell::new(banner),
            Cell::new(&latency),
        ]);
    }

    println!("{table}");
    render_summary(summary);
}

pub fn render_summary(s: &ScanSummary) {
    println!();
    println!(
        "  {} Target: {}{}",
        "►".cyan(),
        s.target.bold(),
        if let Some(ref h) = s.hostname { format!(" ({})", h.dimmed()) } else { "".into() }
    );
    if let Some(ref os) = s.os_guess {
        println!("  {} OS Guess: {}", "►".cyan(), os.yellow());
    }
    println!(
        "  {} Scanned {} ports in {:.2}s — {} open, {} closed, {} filtered",
        "►".cyan(),
        s.total_scanned,
        s.elapsed_secs,
        s.open.to_string().green().bold(),
        s.closed.to_string().red(),
        s.filtered.to_string().yellow(),
    );
    println!();
}

pub fn render_json(results: &[PortResult], summary: &ScanSummary) -> String {
    use serde_json::json;
    let val = json!({
        "summary": {
            "target": summary.target,
            "hostname": summary.hostname,
            "os_guess": summary.os_guess,
            "total_scanned": summary.total_scanned,
            "elapsed_secs": summary.elapsed_secs,
            "open": summary.open,
            "closed": summary.closed,
            "filtered": summary.filtered,
        },
        "ports": results.iter().map(|r| json!({
            "port": r.port,
            "protocol": r.protocol,
            "state": format!("{:?}", r.state).to_lowercase(),
            "service": r.service_name,
            "banner": r.banner,
            "latency_ms": r.latency_ms,
        })).collect::<Vec<_>>()
    });
    serde_json::to_string_pretty(&val).unwrap()
}

pub fn render_csv(results: &[PortResult]) -> String {
    let mut out = String::from("port,protocol,state,service,banner,latency_ms\n");
    for r in results {
        out.push_str(&format!(
            "{},{},{:?},{},{},{}\n",
            r.port,
            r.protocol,
            r.state,
            r.service_name.as_deref().unwrap_or(""),
            r.banner.as_deref().unwrap_or("").replace(',', ";"),
            r.latency_ms.map(|l| l.to_string()).unwrap_or_default(),
        ));
    }
    out
}