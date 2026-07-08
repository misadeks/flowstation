//! Standalone `pd-gateway` binary.
//!
//! On Linux this opens a TUN interface, spawns the gateway task, and waits for
//! SIGINT (Ctrl-C).  On other platforms it prints a friendly message and exits.

// ── Non-Linux early-exit ──────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("pd-gateway requires Linux — TUN/TAP is a Linux-only feature.");
    // Exit 0 (not an error) so CI on non-Linux can still build + run the binary.
}

// ── Linux main ────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
use clap::Parser;

#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[command(
    name = "pd-gateway",
    about = "FlowStation packet-data TUN gateway (PD-6)",
    long_about = "Opens a Linux TUN interface and bridges IPv4 packets between \
                  the OS network stack and the TETRA SNDCP entity."
)]
struct Args {
    /// TUN interface name (created if absent; requires CAP_NET_ADMIN).
    #[arg(long, default_value = "flowstation-pd0")]
    tun_name: String,

    /// Gateway IPv4 address assigned to the TUN interface.
    #[arg(long, default_value = "192.168.100.1")]
    tun_addr: std::net::Ipv4Addr,

    /// Subnet prefix length for the TUN interface.
    #[arg(long, default_value_t = 24)]
    tun_prefix_len: u8,

    /// Interface MTU in bytes.
    #[arg(long, default_value_t = 1500)]
    mtu: u16,
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use pd_gateway::{GatewayConfig, spawn_gateway_task};
    use tokio::signal;

    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let config = GatewayConfig {
        tun_name: args.tun_name,
        tun_addr: args.tun_addr,
        tun_prefix_len: args.tun_prefix_len,
        mtu: args.mtu,
    };

    tracing::info!(
        tun_name = %config.tun_name,
        tun_addr = %config.tun_addr,
        prefix_len = config.tun_prefix_len,
        mtu = config.mtu,
        "starting pd-gateway"
    );

    let _handle = spawn_gateway_task(config).await?;

    tracing::info!("pd-gateway running — press Ctrl-C to stop");

    signal::ctrl_c().await?;

    tracing::info!("received SIGINT, shutting down pd-gateway");

    Ok(())
}
