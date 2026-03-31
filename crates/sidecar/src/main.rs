//! Gateway sidecar binary.
//!
//! Minimal entry point that runs the gateway proxy as a transparent forward
//! proxy. Designed for container deployment alongside an agent sandbox — set
//! `HTTPS_PROXY=http://localhost:19090` on the agent process and all traffic
//! flows through the sidecar.
//!
//! Configuration:
//!   GATEWAY_CONFIG       — path to gateway YAML config (optional — defaults are fine)
//!   GATEWAY_PORT         — listen port (default: 19090)
//!   GATEWAY_AGENT_TYPE   — agent type label (default: auto-detect)
//!   GATEWAY_ENVIRONMENT  — environment label (default: "ci" if CI=true, else "local")
//!   GATEWAY_CONTROL_PLANE_URL — control plane URL for event shipping (optional)
//!
//! Or pass as args:
//!   gateway-sidecar [config_path] [port]

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let config_path: Option<String> = if args.len() > 1 {
        Some(args[1].clone())
    } else {
        std::env::var("GATEWAY_CONFIG").ok()
    };

    let port: u16 = if args.len() > 2 {
        match args[2].parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fatal: invalid port '{}': {}", args[2], e);
                std::process::exit(1);
            }
        }
    } else {
        match std::env::var("GATEWAY_PORT") {
            Ok(p) => match p.parse() {
                Ok(port) => port,
                Err(e) => {
                    eprintln!("fatal: invalid GATEWAY_PORT '{}': {}", p, e);
                    std::process::exit(1);
                }
            },
            Err(_) => 19090,
        }
    };

    let agent_type = std::env::var("GATEWAY_AGENT_TYPE").ok();
    let environment = std::env::var("GATEWAY_ENVIRONMENT").ok();

    eprintln!("gateway-sidecar starting");
    eprintln!(
        "  config: {}",
        config_path.as_deref().unwrap_or("(defaults)")
    );
    eprintln!("  port:   {}", port);

    if let Err(e) =
        getdiff_gateway::proxy::run_gateway(config_path.as_deref(), port, agent_type, environment)
            .await
    {
        eprintln!("fatal: {:#}", e);
        std::process::exit(1);
    }
}
