use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clap::Parser;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::Deserialize;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;
use trust_dns_server::authority::{
    AuthorityObject, Catalog, LookupError, LookupObject, LookupOptions, LookupRecords,
    MessageRequest, UpdateResult, ZoneType,
};
use trust_dns_server::client::rr::{IntoName, LowerName, RecordType};
use trust_dns_server::proto::rr::RecordType::PTR;
use trust_dns_server::proto::rr::{RData, Record, RecordSet};
use trust_dns_server::server::RequestInfo;
use trust_dns_server::ServerFuture;

#[derive(Parser)]
struct Cli {
    #[arg(long, env = "DNS_HOLE_UDP_LISTEN_ADDR", default_value = "0.0.0.0:53")]
    udp_listen_addr: Vec<SocketAddr>,
    #[arg(long, env = "DNS_HOLE_TCP_LISTEN_ADDR", default_value = "0.0.0.0:53")]
    tcp_listen_addr: Vec<SocketAddr>,
    #[arg(short = 't', long, env = "NETBOX_TOKEN")]
    netbox_token: String,
}

#[derive(Deserialize)]
struct SearchResponse<T> {
    results: Vec<T>,
}

#[derive(Deserialize)]
struct IpAddress {
    assigned_object: AssignedObject,
}

#[derive(Deserialize)]
struct AssignedObject {
    name: String,
    virtual_machine: Option<VirtualMachine>,
    device: Option<Device>,
}

#[derive(Deserialize)]
struct VirtualMachine {
    name: String,
}

#[derive(Deserialize)]
struct Device {
    name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Cli::parse();

    let client = Client::new();

    let mut catalog = Catalog::new();
    catalog.upsert(
        LowerName::from_str("in-addr.arpa.")?,
        Box::new(Test {
            client,
            token: args.netbox_token,
        }),
    );

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

    Ok(())
}

async fn query_names(
    client: &Client,
    token: &str,
    ip: &LowerName,
) -> anyhow::Result<Vec<LowerName>> {
    let ip = Ipv4Addr::from_str(ip.to_string().strip_suffix(".in-addr.arpa.").unwrap())?;
    let [a, b, c, d] = ip.octets();

    let ip = Ipv4Addr::new(d, c, b, a);

    println!("{}", ip);

    let response = client
        .get(format!(
            "https://netbox.secshell.pve3.secshell.net/api/ipam/ip-addresses/?q={}",
            ip
        ))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Token {}", token))
        .send()
        .await?
        .error_for_status()?;

    let search_response = response.json::<SearchResponse<IpAddress>>().await?;

    let mut names = Vec::new();

    for result in search_response.results {
        let name = result
            .assigned_object
            .device
            .map(|device| device.name)
            .or_else(|| {
                result
                    .assigned_object
                    .virtual_machine
                    .map(|virtual_machine| virtual_machine.name)
            })
            .expect("can't be");

        names.push(LowerName::from_str(&format!(
            "{}_.{}",
            result.assigned_object.name.replace('.', "vlan"),
            name
        ))?);
    }

    Ok(names)
}

struct Test {
    client: Client,
    token: String,
}

#[async_trait]
impl AuthorityObject for Test {
    fn box_clone(&self) -> Box<dyn AuthorityObject> {
        Box::new(Test {
            client: self.client.clone(),
            token: self.token.to_string(),
        })
    }

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        unimplemented!()
    }

    fn origin(&self) -> &LowerName {
        unimplemented!()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        unimplemented!()
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        let query = request_info.query;

        if query.query_type() == PTR {
            let name = query.name();
            let names = query_names(&self.client, &self.token, name).await.unwrap();

            let mut records = RecordSet::new(&name.into_name().unwrap(), RecordType::PTR, 2354789);

            for n in names {
                let mut record = Record::with(name.into_name().unwrap(), RecordType::PTR, 600);
                record.set_data(Some(RData::PTR(n.into_name().unwrap())));

                records.insert(record, 23456);
            }

            Ok(Box::new(LookupRecords::new(
                lookup_options,
                Arc::new(records),
            )))
        } else {
            unimplemented!()
        }
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        unimplemented!()
    }
}
