use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::anyhow;
use clap::Parser;
use trust_dns_server::resolver::Name;
use url::Url;

#[derive(Parser)]
pub(super) struct Args {
  #[arg(
    short,
    long,
    env = "RDNS_UDP_LISTEN_ADDR",
    default_value = "0.0.0.0:53"
  )]
  pub(super) udp_listen_addr: Vec<SocketAddr>,
  #[arg(
    short,
    long,
    env = "RDNS_TCP_LISTEN_ADDR",
    default_value = "0.0.0.0:53"
  )]
  pub(super) tcp_listen_addr: Vec<SocketAddr>,

  #[arg(
    long,
    env = "RDNS_REVERSE_DNS_NETBOX_URL",
    requires = "reverse_dns_netbox_token"
  )]
  pub(super) reverse_dns_netbox_url: Option<Url>,
  #[arg(
    long,
    env = "RDNS_REVERSE_DNS_NETBOX_TOKEN",
    requires = "reverse_dns_netbox_url"
  )]
  pub(super) reverse_dns_netbox_token: Option<String>,

  #[arg(
    short,
    long,
    env = "RDNS_FORWARDING",
    num_args(0..),
    default_value = ".:https:1.1.1.2:443/security.cloudflare-dns.com,https:1.0.0.2:443/security.cloudflare-dns.com,https:[2606:4700:4700::1112]:443/security.cloudflare-dns.com,https:[2606:4700:4700::1002]:443/security.cloudflare-dns.com"
  )]
  pub(super) forwarding: Vec<Forwarding>,
}

#[derive(Clone)]
pub(super) struct Forwarding {
  pub(super) name: Name,
  pub(super) upstreams: Vec<UpstreamDns>,
}

#[derive(Clone)]
pub(super) enum UpstreamDns {
  Tcp(SocketAddr),
  Udp(SocketAddr),
  Tls(SocketAddr, String),
  Https(SocketAddr, String),
}

impl FromStr for Forwarding {
  type Err = anyhow::Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let (name, raw_upstreams) = s
      .split_once(':')
      .ok_or_else(|| anyhow!("Missing delimiter \":\" to split zone and upstream."))?;

    let mut upstreams = Vec::new();

    for raw in raw_upstreams.split(',') {
      let (protocol, host) = raw
        .split_once(':')
        .ok_or_else(|| anyhow!("Invalid upstream format"))?;

      match protocol {
        "tcp" => upstreams.push(UpstreamDns::Tcp(host.parse()?)),
        "udp" => upstreams.push(UpstreamDns::Udp(host.parse()?)),
        "tls" => {
          let (addr, domain) = host
            .split_once('/')
            .ok_or_else(|| anyhow!("Missing domain name for tls upstream"))?;
          upstreams.push(UpstreamDns::Tls(addr.parse()?, domain.to_string()))
        }
        "https" => {
          let (addr, domain) = host
            .split_once('/')
            .ok_or_else(|| anyhow!("Missing domain name for https upstream"))?;
          upstreams.push(UpstreamDns::Https(addr.parse()?, domain.to_string()))
        }
        unknown => {
          return Err(anyhow!(
            "Invalid upstream protocol {}, allowed: [tcp, udp, tls, https]",
            unknown
          ));
        }
      }
    }

    Ok(Forwarding {
      name: Name::from_str(name)?,
      upstreams,
    })
  }
}
