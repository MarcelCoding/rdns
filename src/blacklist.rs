use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::time::Duration;

use fnv::FnvHasher;
use futures_util::TryStreamExt;
use reqwest::Client;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::task::JoinSet;
use tokio_util::io::StreamReader;
use tracing::{error, info};
use trust_dns_server::client::rr::LowerName;
use url::Url;

pub(crate) struct Blacklist {
  blacklist: Vec<u64>,
  sources: HashSet<Url>,
}

impl Blacklist {
  pub(crate) fn new() -> Self {
    Self {
      blacklist: Vec::default(),
      sources: HashSet::from_iter(vec![
        Url::parse("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt").unwrap(),
        Url::parse("https://adaway.org/hosts.txt").unwrap(),
        Url::parse("https://dbl.oisd.nl/").unwrap(),
        Url::parse("https://v.firebog.net/hosts/static/w3kbl.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/SoftCreatR/fakerando-domains/main/all.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts").unwrap(),
        Url::parse("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts").unwrap(),
        Url::parse("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts").unwrap(),
        Url::parse("https://raw.githubusercontent.com/wlqY8gkVb9w1Ck5MVD4lBre9nWJez8/W10TelemetryBlocklist/master/W10TelemetryBlocklist").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/child-protection").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Fake-Science").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Corona-Blocklist").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/notserious").unwrap(),
        Url::parse("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt").unwrap(),
        Url::parse("https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt").unwrap(),
        Url::parse("https://raw.github.com/notracking/hosts-blocklists/master/hostnames.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Win10Telemetry").unwrap(),
        Url::parse("https://v.firebog.net/hosts/Easyprivacy.txt").unwrap(),
        Url::parse("https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/samsung").unwrap(),
        Url::parse("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/combined_disguised_trackers_justdomains.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/gambling").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/child-protection").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/proxies").unwrap(),
        // Url::parse("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/doh-vpn-proxy-bypass.txt").unwrap(),
        Url::parse("https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt").unwrap(),
        Url::parse("https://urlhaus.abuse.ch/downloads/hostfile/").unwrap(),
        Url::parse("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/nosafesearch.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Streaming").unwrap(),
        Url::parse("https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt").unwrap(),
        Url::parse("https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Monstanner/DuckDuckGo-Fakeshops-Blocklist/main/Blockliste").unwrap(),
        Url::parse("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/easylist").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/spam.mails").unwrap(),
        Url::parse("https://v.firebog.net/hosts/Easyprivacy.txt").unwrap(),
        Url::parse("https://v.firebog.net/hosts/Easylist.txt").unwrap(),
        Url::parse("https://v.firebog.net/hosts/Prigent-Ads.txt").unwrap(),
        Url::parse("https://v.firebog.net/hosts/AdguardDNS.txt").unwrap(),
        Url::parse("https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/crypto").unwrap(),
        Url::parse("https://v.firebog.net/hosts/Prigent-Malware.txt").unwrap(),
        Url::parse("https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt").unwrap(),
        Url::parse("https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADomains.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/domains.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Fake-Science").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/MS-Office-Telemetry").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/spam.mails").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/easylist").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/samsung").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/proxies").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/crypto").unwrap(),
        Url::parse("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts").unwrap(),
        Url::parse("https://raw.githubusercontent.com/autinerd/anti-axelspringer-hosts/master/axelspringer-hosts").unwrap(),
        Url::parse("https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/namePlayer/dhl-scamlist/main/dns-blocklists/pihole-blacklist").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/notserious").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware").unwrap(),
        Url::parse("https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Amazon.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Baidu.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Google.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/HP.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/LG.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Samsung.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Synology.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Twitch.txt").unwrap(),
        //Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Ubisoft.txt").unwrap()
        Url::parse("https://raw.githubusercontent.com/bloodhunterd/pi-hole-blocklists/master/Xiaomi.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt").unwrap(),
        Url::parse("https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Win10Telemetry").unwrap(),
        Url::parse("https://raw.githubusercontent.com/wlqY8gkVb9w1Ck5MVD4lBre9nWJez8/W10TelemetryBlocklist/master/W10TelemetryBlocklist").unwrap(),
      ]),
    }
  }

  pub(crate) async fn update(&mut self) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    let client = Client::new();
    for source in &self.sources {
      let source = source.clone();
      let client = client.clone();

      join_set.spawn(Blacklist::update_source(client, source));
      tokio::time::sleep(Duration::from_millis(5)).await;
    }

    while let Some(result) = join_set.join_next().await.transpose()? {
      match result {
        Ok(hashes) => {
          let count = hashes.len();
          let mut actual = count;
          for hash in hashes {
            match self.blacklist.binary_search(&hash) {
              Ok(_) => actual -= 1,
              Err(_) => self.blacklist.push(hash),
            }
          }
          self.blacklist.shrink_to_fit();
          info!(
            "Added {} new of {} names ({} total), {} sources remaining",
            actual,
            count,
            self.blacklist.len(),
            join_set.len()
          );
        }
        Err(err) => error!("Unable to fetch source: {:?}", err),
      }
    }

    self.blacklist.sort();

    Ok(())
  }

  async fn update_source(client: Client, url: Url) -> anyhow::Result<Vec<u64>> {
    info!("Starting {}", url);

    let response = client.get(url.clone()).send().await?.error_for_status()?;

    fn convert_err(err: reqwest::Error) -> std::io::Error {
      todo!()
    }

    let reader = StreamReader::new(response.bytes_stream().map_err(convert_err));
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    let mut hashes = Vec::new();

    while let Some(line) = lines.next_line().await? {
      let line = line.trim();

      let line = match line.split_once('#') {
        None => line,
        Some((line, _)) => line,
      };

      let line = match line.split_once('\t') {
        None => match line.split_once(' ') {
          None => line,
          Some((_, domain)) => domain,
        },
        Some((_, domain)) => domain,
      };

      for entry in line.split(' ') {
        if entry.is_empty() {
          continue;
        }

        match LowerName::from_str(entry) {
          Ok(name) => {
            let string = name.to_string();

            let mut data = Vec::with_capacity(string.as_bytes().len());
            for x in string.as_bytes() {
              data.push(*x);
            }

            let mut hasher = FnvHasher::default();
            data.hash(&mut hasher);
            hashes.push(hasher.finish())
          }
          Err(err) => error!("Unable to parse domain \"{}\": {:?}", line, err),
        }
      }
    }

    hashes.shrink_to_fit();

    info!("Finished {}", url);

    Ok(hashes)
  }

  pub(crate) fn is_blocked(&self, qname: &LowerName) -> bool {
    let mut hasher = FnvHasher::default();

    let string = qname.to_string();
    let x1 = string.as_bytes();
    x1[..x1.len() - 1].hash(&mut hasher);

    let i = hasher.finish();

    self.blacklist.binary_search(&i).is_ok()
  }
}
