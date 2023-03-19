use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::Deserialize;
use trust_dns_server::authority::{
  AuthorityObject, LookupError, LookupObject, LookupOptions, LookupRecords, MessageRequest,
  UpdateResult, ZoneType,
};
use trust_dns_server::proto::rr::{LowerName, RData, Record, RecordSet, RecordType};
use trust_dns_server::resolver::IntoName;
use trust_dns_server::server::RequestInfo;
use url::Url;

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

pub(crate) struct NetboxClient {
  client: Client,
  base_url: Url,
  token: String,
}

impl NetboxClient {
  pub(crate) fn new(base_url: Url, token: String) -> Self {
    Self {
      client: Client::new(),
      base_url,
      token,
    }
  }

  async fn query_names(&self, ip: &LowerName) -> anyhow::Result<Vec<LowerName>> {
    let ip = Ipv4Addr::from_str(ip.to_string().strip_suffix(".in-addr.arpa.").unwrap())?;
    let [a, b, c, d] = ip.octets();

    let ip = Ipv4Addr::new(d, c, b, a);

    println!("{}", ip);

    let response = self
      .client
      .get(self.base_url.join("api/ipam/ip-addresses/?q={}")?)
      .query(&[('q', ip)])
      .header(CONTENT_TYPE, "application/json")
      .header(AUTHORIZATION, format!("Token {}", self.token))
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

      names.push(LowerName::from_str(&name)?);
    }

    Ok(names)
  }
}

pub(crate) struct NetboxIpv4Authority {
  client: Arc<NetboxClient>,
}

impl NetboxIpv4Authority {
  pub(crate) fn new(client: Arc<NetboxClient>) -> Self {
    Self { client }
  }
}

#[async_trait]
impl AuthorityObject for NetboxIpv4Authority {
  fn box_clone(&self) -> Box<dyn AuthorityObject> {
    Box::new(NetboxIpv4Authority {
      client: self.client.clone(),
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

    if query.query_type() == RecordType::PTR {
      let name = query.name();
      let names = self.client.query_names(name).await.unwrap();

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
