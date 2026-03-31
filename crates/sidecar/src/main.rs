//! Gateway sidecar binary.
//!
//! Minimal entry point that runs the gateway proxy. Designed for container
//! deployment alongside an agent sandbox. No CLI framework, no interactive
//! features — just the proxy.
//!
//! Configuration:
//!   GATEWAY_CONFIG       — path to gateway YAML config (default: /etc/gateway/gateway.yaml)
//!   GATEWAY_PORT         — listen port (default: 8080)
//!   GATEWAY_CONTROL_PLANE_URL — control plane URL for event shipping (optional)
//!
//! Or pass as args:
//!   gateway-sidecar [config_path] [port]

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let config_path = if args.len() > 1 {
        args[1].clone()
    } else {
        std::env::var("GATEWAY_CONFIG").unwrap_or_else(|_| "/etc/gateway/gateway.yaml".to_string())
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
            Err(_) => 8080,
        }
    };

    eprintln!("gateway-sidecar starting");
    eprintln!("  config: {}", config_path);
    eprintln!("  port:   {}", port);

    if let Err(e) = getdiff_gateway::proxy::run_proxy_from_file(&config_path, port).await {
        eprintln!("fatal: {:#}", e);
        std::process::exit(1);
    }
}
