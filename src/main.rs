use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;
use trust_dns_server::authority::{Authority, Catalog, ZoneType};
use trust_dns_server::client::rr::LowerName;
use trust_dns_server::resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol};
use trust_dns_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use trust_dns_server::ServerFuture;

use crate::args::{Args, UpstreamDns};
use crate::authority::netbox::{NetboxClient, NetboxIpv4Authority};
use crate::blacklist::Blacklist;

mod args;
mod authority;
mod blacklist;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::fmt::init();

  let args = Args::parse();

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
          trust_nx_responses: true,
          tls_config: None,
          bind_addr: None,
        },
        UpstreamDns::Udp(addr) => NameServerConfig {
          socket_addr: *addr,
          protocol: Protocol::Udp,
          tls_dns_name: None,
          trust_nx_responses: true,
          tls_config: None,
          bind_addr: None,
        },
        UpstreamDns::Tls(addr, domain) => NameServerConfig {
          socket_addr: *addr,
          protocol: Protocol::Tls,
          tls_dns_name: Some(domain.to_string()),
          trust_nx_responses: true,
          tls_config: None,
          bind_addr: None,
        },
        UpstreamDns::Https(addr, domain) => NameServerConfig {
          socket_addr: *addr,
          protocol: Protocol::Https,
          tls_dns_name: Some(domain.to_string()),
          trust_nx_responses: true,
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

  if args.blacklist {
    let mut blacklist = Blacklist::new(catalog);
    blacklist.update().await?;

    let mut server = ServerFuture::new(blacklist);

    for addr in args.udp_listen_addr {
      info!("Listening on {}/udp", addr);
      server.register_socket(UdpSocket::bind(addr).await?);
    }

    for addr in args.tcp_listen_addr {
      info!("Listening on {}/tcp", addr);
      server.register_listener(TcpListener::bind(addr).await?, Duration::from_secs(10));
    }

    server.block_until_done().await?;
  } else {
    let mut server = ServerFuture::new(catalog);

    for addr in args.udp_listen_addr {
      info!("Listening on {}/udp", addr);
      server.register_socket(UdpSocket::bind(addr).await?);
    }

    for addr in args.tcp_listen_addr {
      info!("Listening on {}/tcp", addr);
      server.register_listener(TcpListener::bind(addr).await?, Duration::from_secs(10));
    }

    server.block_until_done().await?;
  };

  Ok(())
}
