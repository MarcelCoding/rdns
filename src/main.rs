use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::{TcpListener, UdpSocket};
use tokio::select;
use tokio::signal::ctrl_c;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use trust_dns_server::authority::{Authority, Catalog, ZoneType};
use trust_dns_server::proto::rr::LowerName;
use trust_dns_server::resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol};
use trust_dns_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use trust_dns_server::ServerFuture;

use crate::args::{Args, UpstreamDns};
use crate::authority::netbox::{NetboxClient, NetboxIpv4Authority};
use crate::blacklist::Blacklist;
use crate::stats::Stats;

mod args;
mod authority;
mod blacklist;
mod stats;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let args = Args::parse();

  let subscriber = FmtSubscriber::builder()
    .with_max_level(Level::DEBUG)
    .compact()
    .finish();

  tracing::subscriber::set_global_default(subscriber)?;

  info!(concat!(
    "Booting ",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "..."
  ));

  let mut catalog = Catalog::new();

  for forwarding in args.forwarding {
    let upstreams = forwarding
      .upstreams
      .iter()
      .map(|upstream| match upstream {
        UpstreamDns::Tcp(addr) => NameServerConfig {
          socket_addr: *addr,
          protocol: Protocol::Tcp,
          tls_dns_name: None,
          trust_negative_responses: true,
          tls_config: None,
          bind_addr: None,
        },
        UpstreamDns::Udp(addr) => NameServerConfig {
          socket_addr: *addr,
          protocol: Protocol::Udp,
          tls_dns_name: None,
          trust_negative_responses: true,
          tls_config: None,
          bind_addr: None,
        },
        UpstreamDns::Tls(addr, domain) => NameServerConfig {
          socket_addr: *addr,
          protocol: Protocol::Tls,
          tls_dns_name: Some(domain.to_string()),
          trust_negative_responses: true,
          tls_config: None,
          bind_addr: None,
        },
        UpstreamDns::Https(addr, domain) => NameServerConfig {
          socket_addr: *addr,
          protocol: Protocol::Https,
          tls_dns_name: Some(domain.to_string()),
          trust_negative_responses: true,
          tls_config: None,
          bind_addr: None,
        },
      })
      .collect::<Vec<_>>();

    let authority = ForwardAuthority::try_from_config(
      forwarding.name,
      ZoneType::Forward,
      &ForwardConfig {
        name_servers: NameServerConfigGroup::from(upstreams),
        options: None,
      },
    )
    .unwrap();

    catalog.upsert(authority.origin().clone(), Box::new(Arc::new(authority)))
  }

  if let Some(url) = args.reverse_dns_netbox_url {
    info!("Configuring netbox");
    let netbox_client = Arc::new(NetboxClient::new(
      url,
      args.reverse_dns_netbox_token.unwrap(),
    ));

    catalog.upsert(
      LowerName::from_str("in-addr.arpa.")?,
      Box::new(NetboxIpv4Authority::new(netbox_client)),
    );
  }

  let mut blacklist = Blacklist::new();
  blacklist.update().await?;

  let stats = Stats::new(
    args.stats_url.as_ref().unwrap(),
    args.stats_bucket.unwrap(),
    args.stats_org.unwrap(),
    args.stats_token.as_ref().unwrap(),
    catalog,
    blacklist,
  );

  let mut server = ServerFuture::new(stats.clone());

  for addr in args.udp_listen_addr {
    let udp = UdpSocket::bind(addr).await?;
    server.register_socket(udp);
    info!("Listening on {}/udp...", addr);
  }

  for addr in args.tcp_listen_addr {
    let tcp = TcpListener::bind(addr).await?;
    server.register_listener(tcp, Duration::from_secs(10));
    info!("Listening on {}/tcp...", addr);
  }

  tokio::spawn(async move {
    loop {
      if let Err(err) = stats.flush().await {
        error!("Error: {}", err);
      }
      tokio::time::sleep(Duration::from_secs(10)).await;
    }
  });

  select! {
    result = server.block_until_done() => {
      result?;
      info!("Server closed, quitting...");
    },
    _ = shutdown_signal() => {
      info!("Termination signal received, quitting...");
    }
  }

  Ok(())
}

async fn shutdown_signal() {
  let ctrl_c = async { ctrl_c().await.expect("failed to install Ctrl+C handler") };

  #[cfg(unix)]
  {
    let terminate = async {
      tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install signal handler")
        .recv()
        .await;
    };

    select! {
      _ = ctrl_c => {},
      _ = terminate => {},
    }
  }

  #[cfg(not(unix))]
  ctrl_c.await;
}
