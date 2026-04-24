use colored::Colorize;

pub fn print_banner() {
    println!(
        "{}",
        r#"
  ██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗
  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗
  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║
  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║
  ██║     ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"#
            .bright_red()
    );
    println!(
        "  {}  {}\n",
        "v0.1.0".dimmed(),
        "modular penetration testing platform".dimmed()
    );
    println!(
        "  {}  Use only on systems you own or have explicit permission to test.\n",
        "[ ! ]".yellow().bold()
    );
}