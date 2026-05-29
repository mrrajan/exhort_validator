use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use csv::{ReaderBuilder, Writer};
use log::info;
use regex::Regex;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Semaphore;

const FINDING_TPA_MISS: &str = "TPA_MISS";
const FINDING_VERSION_NA: &str = "VERSION_NOT_AFFECTED";
const FINDING_ECO_MISMATCH: &str = "ECOSYSTEM_MISMATCH";
const FINDING_CROSS_PACKAGE: &str = "CROSS_PACKAGE";
const FINDING_CVE_WITHDRAWN: &str = "CVE_WITHDRAWN";
const FINDING_UNKNOWN: &str = "UNKNOWN";

const VERDICT_TPA_GAP: &str = "TPA_GAP";
const VERDICT_OSV_NOISE: &str = "OSV_NOISE";

const CSAF_AFFECTED_STATUSES: &[&str] = &[
    "fixed",
    "known_affected",
    "first_fixed",
    "first_affected",
    "under_investigation",
];
const CSAF_NOT_AFFECTED_STATUSES: &[&str] = &["known_not_affected"];

fn finding_priority(finding: &str) -> u8 {
    match finding {
        FINDING_TPA_MISS => 0,
        FINDING_VERSION_NA => 1,
        FINDING_ECO_MISMATCH => 2,
        FINDING_CROSS_PACKAGE => 3,
        FINDING_CVE_WITHDRAWN => 4,
        _ => 5,
    }
}

fn finding_to_verdict(finding: &str) -> &str {
    match finding {
        FINDING_TPA_MISS => VERDICT_TPA_GAP,
        FINDING_VERSION_NA | FINDING_ECO_MISMATCH | FINDING_CROSS_PACKAGE | FINDING_CVE_WITHDRAWN => {
            VERDICT_OSV_NOISE
        }
        _ => "",
    }
}

struct RpmPurl {
    name: String,
    rpm_version: String,
    rhel_major: Option<u32>,
}

fn parse_rpm_purl(purl: &str) -> Option<RpmPurl> {
    let body = purl.strip_prefix("pkg:rpm/")?;
    let (path, ver_part) = body.split_once('@')?;
    let path_parts: Vec<&str> = path.splitn(2, '/').collect();
    if path_parts.len() < 2 {
        return None;
    }
    let name = path_parts[1].to_string();

    let (version, epoch) = if let Some((ver, qs)) = ver_part.split_once('?') {
        let epoch = qs
            .split('&')
            .find_map(|param| {
                let (k, v) = param.split_once('=')?;
                if k == "epoch" {
                    v.parse::<u32>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        (ver.to_string(), epoch)
    } else {
        (ver_part.to_string(), 0)
    };

    let rpm_version = if epoch > 0 {
        format!("{}:{}", epoch, version)
    } else {
        version.clone()
    };

    let el_re = Regex::new(r"\.el(\d+)(?:_|\.|$)").unwrap();
    let rhel_major = el_re
        .captures(&version)
        .and_then(|c| c.get(1)?.as_str().parse::<u32>().ok());

    Some(RpmPurl {
        name,
        rpm_version,
        rhel_major,
    })
}

fn osv_ecosystem_rhel_major(ecosystem: &str) -> Option<u32> {
    let re = Regex::new(r":enterprise_linux:(\d+):").unwrap();
    re.captures(ecosystem)
        .and_then(|c| c.get(1)?.as_str().parse::<u32>().ok())
}

fn is_redhat_advisory(adv_id: &str) -> bool {
    let re = Regex::new(r"^RH(?:SA|BA|EA)-\d{4}:\d+$").unwrap();
    re.is_match(adv_id)
}

fn require_rpmdev_vercmp() -> Result<(), Box<dyn Error>> {
    match Command::new("which").arg("rpmdev-vercmp").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err("rpmdev-vercmp not found in PATH (install rpmdevtools)".into()),
    }
}

lazy_static::lazy_static! {
    static ref RPM_CMP_CACHE: Mutex<HashMap<(String, String), i32>> = Mutex::new(HashMap::new());
}

fn rpm_cmp(a: &str, b: &str) -> Result<i32, Box<dyn Error>> {
    let key = (a.to_string(), b.to_string());
    {
        let cache = RPM_CMP_CACHE.lock().unwrap();
        if let Some(&result) = cache.get(&key) {
            return Ok(result);
        }
    }

    let output = Command::new("rpmdev-vercmp")
        .arg(a)
        .arg(b)
        .output()
        .map_err(|e| format!("rpmdev-vercmp failed: {}", e))?;

    let out = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    let result = if out.contains('<') {
        -1
    } else if out.contains('>') {
        1
    } else if output.status.success() || out.contains('=') {
        0
    } else {
        return Err(format!("rpmdev-vercmp failed for {} vs {}: {}", a, b, out.trim()).into());
    };

    RPM_CMP_CACHE
        .lock()
        .unwrap()
        .insert(key, result);
    Ok(result)
}

fn version_in_events(rpm_version: &str, events: &[Value]) -> bool {
    if events.is_empty() {
        return false;
    }
    let mut introduced: Option<&str> = Some("0");

    for event in events {
        if let Some(intro) = event.get("introduced").and_then(|v| v.as_str()) {
            introduced = Some(if intro.is_empty() { "0" } else { intro });
        }
        if let Some(fixed) = event.get("fixed").and_then(|v| v.as_str()) {
            if let Some(intro) = introduced {
                if rpm_cmp(intro, rpm_version).unwrap_or(1) <= 0
                    && rpm_cmp(rpm_version, fixed).unwrap_or(0) < 0
                {
                    return true;
                }
                introduced = None;
            }
        }
        if let Some(last) = event.get("last_affected").and_then(|v| v.as_str()) {
            if let Some(intro) = introduced {
                if rpm_cmp(intro, rpm_version).unwrap_or(1) <= 0
                    && rpm_cmp(rpm_version, last).unwrap_or(-1) <= 0
                {
                    return true;
                }
                introduced = None;
            }
        }
    }

    if let Some(intro) = introduced {
        if rpm_cmp(intro, rpm_version).unwrap_or(1) <= 0 {
            return true;
        }
    }
    false
}

fn version_in_affected(rpm_version: &str, affected: &Value) -> bool {
    if let Some(versions) = affected.get("versions").and_then(|v| v.as_array()) {
        let bare = rpm_version
            .split_once(':')
            .map(|(_, v)| v)
            .unwrap_or(rpm_version);
        for ver in versions {
            if let Some(v) = ver.as_str() {
                if v == rpm_version || v == bare {
                    return true;
                }
            }
        }
    }

    if let Some(ranges) = affected.get("ranges").and_then(|v| v.as_array()) {
        for rng in ranges {
            if rng.get("type").and_then(|v| v.as_str()) == Some("ECOSYSTEM") {
                if let Some(events) = rng.get("events").and_then(|v| v.as_array()) {
                    if version_in_events(rpm_version, events) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn advisory_cves(data: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for key in &["upstream", "aliases"] {
        if let Some(arr) = data.get(*key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if s.starts_with("CVE-") {
                        ids.push(s.to_string());
                    }
                }
            }
        }
    }
    ids
}

fn ecosystems_match(purl: &RpmPurl, ecosystem: &str) -> bool {
    match (purl.rhel_major, osv_ecosystem_rhel_major(ecosystem)) {
        (Some(purl_major), Some(eco_major)) => purl_major == eco_major,
        _ => false,
    }
}

fn classify_affected_entry(purl: &RpmPurl, affected: &Value) -> Option<&'static str> {
    let pkg = affected.get("package")?;
    let affected_name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if purl.name != affected_name {
        return None;
    }

    let ecosystem = pkg.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("");
    if !ecosystems_match(purl, ecosystem) {
        return Some(FINDING_ECO_MISMATCH);
    }

    if version_in_affected(&purl.rpm_version, affected) {
        Some(FINDING_TPA_MISS)
    } else {
        Some(FINDING_VERSION_NA)
    }
}

fn classify_advisory(purl: &RpmPurl, cve_id: &str, data: &Value) -> (String, String) {
    let adv_id = data
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if !is_redhat_advisory(&adv_id) {
        return (FINDING_UNKNOWN.to_string(), adv_id);
    }

    let cves = advisory_cves(data);
    if !cves.iter().any(|c| c == cve_id) {
        return (FINDING_UNKNOWN.to_string(), adv_id);
    }

    let mut best = FINDING_UNKNOWN;
    if let Some(affected_arr) = data.get("affected").and_then(|v| v.as_array()) {
        for affected in affected_arr {
            if let Some(entry_finding) = classify_affected_entry(purl, affected) {
                if finding_priority(entry_finding) < finding_priority(best) {
                    best = entry_finding;
                    if best == FINDING_TPA_MISS {
                        break;
                    }
                }
            }
        }
    }
    (best.to_string(), adv_id)
}

fn csaf_product_matches_package(product_id: &str, package_name: &str) -> bool {
    if let Ok(re) = Regex::new(&format!(":{}\\-", regex::escape(package_name))) {
        re.is_match(product_id)
    } else {
        false
    }
}

fn csaf_verify_tpa_miss(
    purl: &RpmPurl,
    cve_id: &str,
    _adv_id: &str,
    csaf_data: Option<&Value>,
) -> &'static str {
    let csaf_data = match csaf_data {
        Some(d) => d,
        None => return FINDING_TPA_MISS,
    };

    let vulns = match csaf_data.get("vulnerabilities").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return FINDING_TPA_MISS,
    };

    for v in vulns {
        if v.get("cve").and_then(|c| c.as_str()) != Some(cve_id) {
            continue;
        }
        let status = match v.get("product_status") {
            Some(s) => s,
            None => continue,
        };

        let mut affected_products = Vec::new();
        for s in CSAF_AFFECTED_STATUSES {
            if let Some(arr) = status.get(*s).and_then(|v| v.as_array()) {
                for p in arr {
                    if let Some(ps) = p.as_str() {
                        affected_products.push(ps);
                    }
                }
            }
        }

        let mut not_affected_products = Vec::new();
        for s in CSAF_NOT_AFFECTED_STATUSES {
            if let Some(arr) = status.get(*s).and_then(|v| v.as_array()) {
                for p in arr {
                    if let Some(ps) = p.as_str() {
                        not_affected_products.push(ps);
                    }
                }
            }
        }

        let in_affected = affected_products
            .iter()
            .any(|p| csaf_product_matches_package(p, &purl.name));
        let in_not_affected = not_affected_products
            .iter()
            .any(|p| csaf_product_matches_package(p, &purl.name));

        if in_not_affected && !in_affected {
            return FINDING_CROSS_PACKAGE;
        }

        if in_affected {
            if let Some(fixed_arr) = status.get("fixed").and_then(|v| v.as_array()) {
                for p in fixed_arr {
                    if let Some(ps) = p.as_str() {
                        if csaf_product_matches_package(ps, &purl.name) {
                            let pattern =
                                format!(":{}\\-(.+?)\\.[a-z]", regex::escape(&purl.name));
                            if let Ok(re) = Regex::new(&pattern) {
                                if let Some(caps) = re.captures(ps) {
                                    if let Some(csaf_fixed) = caps.get(1) {
                                        if rpm_cmp(&purl.rpm_version, csaf_fixed.as_str())
                                            .unwrap_or(-1)
                                            >= 0
                                        {
                                            return FINDING_VERSION_NA;
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
            return FINDING_TPA_MISS;
        }

        return FINDING_CROSS_PACKAGE;
    }

    FINDING_TPA_MISS
}

fn check_cve_withdrawn(cve_data: Option<&Value>) -> bool {
    let data = match cve_data {
        Some(d) => d,
        None => return false,
    };
    if data.get("withdrawn").is_some() {
        return true;
    }
    if let Some(details) = data.get("details").and_then(|v| v.as_str()) {
        let lower = details.to_lowercase();
        return lower.contains("rejected") || lower.contains("withdrawn");
    }
    false
}

fn categorize_row(
    purl_str: &str,
    cve_id: &str,
    purl_advisories: &HashMap<String, Vec<String>>,
    adv_data: &HashMap<String, Value>,
) -> (String, String, String) {
    let purl = match parse_rpm_purl(purl_str) {
        Some(p) => p,
        None => return (FINDING_UNKNOWN.to_string(), String::new(), String::new()),
    };

    let mut best_finding = FINDING_UNKNOWN.to_string();
    let mut best_adv = String::new();

    if let Some(adv_ids) = purl_advisories.get(purl_str) {
        for adv_id in adv_ids {
            let data = match adv_data.get(adv_id) {
                Some(d) => d,
                None => continue,
            };
            let (finding, matched) = classify_advisory(&purl, cve_id, data);
            if finding_priority(&finding) < finding_priority(&best_finding) {
                best_finding = finding;
                best_adv = matched;
                if best_finding == FINDING_TPA_MISS {
                    break;
                }
            }
        }
    }

    let verdict = finding_to_verdict(&best_finding).to_string();
    (best_finding, verdict, best_adv)
}

fn load_cache(path: &Path) -> HashMap<String, Value> {
    if !path.is_file() {
        return HashMap::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn save_cache(path: &Path, data: &HashMap<String, Value>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string(data) {
        let _ = std::fs::write(path, json);
    }
}

fn load_purl_advisories(qb_path: &Path) -> Result<HashMap<String, Vec<String>>, Box<dyn Error>> {
    let mut purl_advisories: HashMap<String, Vec<String>> = HashMap::new();
    let mut rdr = ReaderBuilder::new().from_path(qb_path)?;
    let headers = rdr.headers()?.clone();
    let osv_id_idx = headers.iter().position(|h| h == "OSV_ID");
    let purl_idx = headers.iter().position(|h| h == "PURL");
    if let (Some(oi), Some(pi)) = (osv_id_idx, purl_idx) {
        for result in rdr.records() {
            let record = result?;
            let osv_id = record.get(oi).unwrap_or("").trim().to_string();
            let purl = record.get(pi).unwrap_or("").trim().to_string();
            if !osv_id.is_empty() && !purl.is_empty() {
                purl_advisories.entry(purl).or_default().push(osv_id);
            }
        }
    }
    Ok(purl_advisories)
}

async fn fetch_osv_advisory(
    client: &reqwest::Client,
    sem: &Semaphore,
    adv_id: &str,
) -> (String, Option<Value>) {
    let _permit = sem.acquire().await.unwrap();
    let url = format!("https://api.osv.dev/v1/vulns/{}", adv_id);
    match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(data) => (adv_id.to_string(), Some(data)),
            Err(_) => (adv_id.to_string(), None),
        },
        _ => (adv_id.to_string(), None),
    }
}

async fn fetch_csaf_advisory(
    client: &reqwest::Client,
    sem: &Semaphore,
    adv_id: &str,
) -> (String, Option<Value>) {
    let _permit = sem.acquire().await.unwrap();
    let filename = adv_id.to_lowercase().replace(':', "_");
    let year = filename
        .split('-')
        .nth(1)
        .and_then(|s| s.split('_').next())
        .unwrap_or("2024");
    let url = format!(
        "https://security.access.redhat.com/data/csaf/v2/advisories/{}/{}.json",
        year, filename
    );
    match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(data) => (adv_id.to_string(), Some(data)),
            Err(_) => (adv_id.to_string(), None),
        },
        _ => (adv_id.to_string(), None),
    }
}

async fn fetch_needed_advisories(
    client: &reqwest::Client,
    needed: &[String],
    cache_path: &Path,
    concurrency: usize,
) -> HashMap<String, Value> {
    let mut adv_data = load_cache(cache_path);
    let to_fetch: Vec<&String> = needed.iter().filter(|id| !adv_data.contains_key(*id)).collect();

    if to_fetch.is_empty() {
        info!("All {} advisories loaded from cache", needed.len());
        return adv_data;
    }

    info!(
        "Fetching {} advisories ({} cached)...",
        to_fetch.len(),
        adv_data.len()
    );

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();
    for adv_id in &to_fetch {
        let client = client.clone();
        let sem = Arc::clone(&sem);
        let adv_id = adv_id.to_string();
        handles.push(tokio::spawn(async move {
            fetch_osv_advisory(&client, &sem, &adv_id).await
        }));
    }

    let mut done = 0usize;
    for handle in handles {
        if let Ok((adv_id, Some(data))) = handle.await {
            adv_data.insert(adv_id, data);
        }
        done += 1;
        if done % 500 == 0 {
            info!("  Fetched {}/{}...", done, to_fetch.len());
            save_cache(cache_path, &adv_data);
        }
    }

    save_cache(cache_path, &adv_data);
    let fetched = needed.iter().filter(|id| adv_data.contains_key(*id)).count();
    info!("Cache: {}/{} advisories at {:?}", fetched, needed.len(), cache_path);
    adv_data
}

async fn fetch_csaf_advisories(
    client: &reqwest::Client,
    needed: &[String],
    cache_path: &Path,
    concurrency: usize,
) -> HashMap<String, Value> {
    let mut csaf_cache = load_cache(cache_path);
    let to_fetch: Vec<&String> = needed.iter().filter(|id| !csaf_cache.contains_key(*id)).collect();

    if to_fetch.is_empty() {
        info!("All {} CSAF docs loaded from cache", needed.len());
        return csaf_cache;
    }

    info!(
        "Fetching {} CSAF docs ({} cached)...",
        to_fetch.len(),
        csaf_cache.len()
    );

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();
    for adv_id in &to_fetch {
        let client = client.clone();
        let sem = Arc::clone(&sem);
        let adv_id = adv_id.to_string();
        handles.push(tokio::spawn(async move {
            fetch_csaf_advisory(&client, &sem, &adv_id).await
        }));
    }

    let mut done = 0usize;
    for handle in handles {
        if let Ok((adv_id, Some(data))) = handle.await {
            csaf_cache.insert(adv_id, data);
        }
        done += 1;
        if done % 20 == 0 {
            info!("  CSAF: {}/{}...", done, to_fetch.len());
            save_cache(cache_path, &csaf_cache);
        }
    }

    save_cache(cache_path, &csaf_cache);
    let fetched = needed.iter().filter(|id| csaf_cache.contains_key(*id)).count();
    info!("CSAF cache: {}/{} at {:?}", fetched, needed.len(), cache_path);
    csaf_cache
}

async fn fetch_cve_statuses(
    client: &reqwest::Client,
    cve_ids: &[String],
    cache_path: &Path,
    concurrency: usize,
) -> HashMap<String, Value> {
    let mut cve_cache = load_cache(cache_path);
    let to_fetch: Vec<&String> = cve_ids.iter().filter(|id| !cve_cache.contains_key(*id)).collect();

    if to_fetch.is_empty() {
        info!("All {} CVE statuses loaded from cache", cve_ids.len());
        return cve_cache;
    }

    info!(
        "Fetching {} CVE statuses ({} cached)...",
        to_fetch.len(),
        cve_cache.len()
    );

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();
    for cve_id in &to_fetch {
        let client = client.clone();
        let sem = Arc::clone(&sem);
        let cve_id = cve_id.to_string();
        handles.push(tokio::spawn(async move {
            fetch_osv_advisory(&client, &sem, &cve_id).await
        }));
    }

    let mut done = 0usize;
    for handle in handles {
        if let Ok((cve_id, Some(data))) = handle.await {
            cve_cache.insert(cve_id, data);
        }
        done += 1;
        if done % 200 == 0 {
            info!("  CVE: {}/{}...", done, to_fetch.len());
            save_cache(cache_path, &cve_cache);
        }
    }

    save_cache(cache_path, &cve_cache);
    let fetched = cve_ids.iter().filter(|id| cve_cache.contains_key(*id)).count();
    info!("CVE cache: {}/{} at {:?}", fetched, cve_ids.len(), cache_path);
    cve_cache
}

pub async fn run_categorize(
    client: &reqwest::Client,
    comparison_path: &str,
    querybatch_path: Option<&str>,
    cache_dir: &str,
    concurrency: usize,
    limit: usize,
) -> Result<(), Box<dyn Error>> {
    require_rpmdev_vercmp()?;

    let comparison = PathBuf::from(comparison_path);
    if !comparison.is_file() {
        return Err(format!("Comparison CSV not found: {}", comparison_path).into());
    }

    let qb_path = if let Some(qb) = querybatch_path {
        PathBuf::from(qb)
    } else {
        let pattern = "test_results/source/*_osv_querybatch_*.csv";
        let mut matches: Vec<PathBuf> = glob::glob(pattern)?
            .filter_map(|p| p.ok())
            .collect();
        matches.sort();
        matches
            .last()
            .cloned()
            .ok_or("No querybatch CSV found in test_results/source/")?
    };
    info!("Querybatch: {:?}", qb_path);

    let purl_advisories = load_purl_advisories(&qb_path)?;

    let mut all_rows: Vec<HashMap<String, String>> = Vec::new();
    let mut missing_tpa: Vec<HashMap<String, String>> = Vec::new();
    let fieldnames: Vec<String>;

    {
        let mut rdr = ReaderBuilder::new().from_path(&comparison)?;
        fieldnames = rdr.headers()?.iter().map(|h| h.to_string()).collect();
        let fields = fieldnames.clone();
        for result in rdr.records() {
            let record = result?;
            let mut row: HashMap<String, String> = HashMap::new();
            for (i, field) in fields.iter().enumerate() {
                row.insert(field.clone(), record.get(i).unwrap_or("").to_string());
            }
            if row.get("missing_in").map(|s| s.as_str()) == Some("TPA") {
                missing_tpa.push(row.clone());
            }
            all_rows.push(row);
        }
    }

    let missing_tpa = if limit > 0 {
        missing_tpa.into_iter().take(limit).collect::<Vec<_>>()
    } else {
        missing_tpa
    };

    let missing_keys: std::collections::HashSet<(String, String)> = missing_tpa
        .iter()
        .filter_map(|r| {
            Some((r.get("purl")?.clone(), r.get("cve_id")?.clone()))
        })
        .collect();

    info!("Rows missing in TPA: {}", missing_tpa.len());

    let mut needed_advs: std::collections::HashSet<String> = std::collections::HashSet::new();
    for row in &missing_tpa {
        if let Some(purl) = row.get("purl") {
            if let Some(advs) = purl_advisories.get(purl) {
                needed_advs.extend(advs.iter().cloned());
            }
        }
    }
    info!("Unique advisories needed: {}", needed_advs.len());

    let cache_path = PathBuf::from(cache_dir).join("osv_advisories.json");
    let needed_vec: Vec<String> = needed_advs.into_iter().collect();
    let adv_data = fetch_needed_advisories(client, &needed_vec, &cache_path, concurrency).await;

    let mut cat_cache: HashMap<(String, String), (String, String, String)> = HashMap::new();
    for row in &missing_tpa {
        let purl = row.get("purl").cloned().unwrap_or_default();
        let cve_id = row.get("cve_id").cloned().unwrap_or_default();
        let key = (purl.clone(), cve_id.clone());
        if !cat_cache.contains_key(&key) {
            cat_cache.insert(
                key,
                categorize_row(&purl, &cve_id, &purl_advisories, &adv_data),
            );
        }
    }

    // Phase 2: CSAF cross-verification for TPA_MISS findings
    let tpa_miss_entries: Vec<((String, String), (String, String, String))> = cat_cache
        .iter()
        .filter(|(_, v)| v.0 == FINDING_TPA_MISS)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    if !tpa_miss_entries.is_empty() {
        info!(
            "Phase 2: CSAF cross-verifying {} TPA_MISS records...",
            tpa_miss_entries.len()
        );
        let csaf_adv_ids: Vec<String> = tpa_miss_entries
            .iter()
            .filter(|(_, v)| !v.2.is_empty())
            .map(|(_, v)| v.2.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let csaf_cache_path = PathBuf::from(cache_dir).join("csaf_advisories.json");
        let csaf_data = fetch_csaf_advisories(
            client,
            &csaf_adv_ids,
            &csaf_cache_path,
            concurrency.min(5),
        )
        .await;

        for (key, (_, _, adv_id)) in &tpa_miss_entries {
            if let Some(purl) = parse_rpm_purl(&key.0) {
                let revised = csaf_verify_tpa_miss(&purl, &key.1, adv_id, csaf_data.get(adv_id));
                if revised != FINDING_TPA_MISS {
                    cat_cache.insert(
                        key.clone(),
                        (
                            revised.to_string(),
                            finding_to_verdict(revised).to_string(),
                            adv_id.clone(),
                        ),
                    );
                }
            }
        }
    }

    // Phase 3: CVE withdrawn/rejected check for remaining TPA_MISS
    let remaining_miss: Vec<(String, String)> = cat_cache
        .iter()
        .filter(|(_, v)| v.0 == FINDING_TPA_MISS)
        .map(|(k, _)| k.clone())
        .collect();

    if !remaining_miss.is_empty() {
        info!(
            "Phase 3: checking CVE status for {} remaining TPA_MISS...",
            remaining_miss.len()
        );
        let cve_ids: Vec<String> = remaining_miss
            .iter()
            .filter(|(_, cve)| cve.starts_with("CVE-"))
            .map(|(_, cve)| cve.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let cve_cache_path = PathBuf::from(cache_dir).join("cve_statuses.json");
        let cve_data = fetch_cve_statuses(client, &cve_ids, &cve_cache_path, concurrency).await;

        for key in &remaining_miss {
            if check_cve_withdrawn(cve_data.get(&key.1)) {
                let adv_id = cat_cache.get(key).map(|v| v.2.clone()).unwrap_or_default();
                cat_cache.insert(
                    key.clone(),
                    (
                        FINDING_CVE_WITHDRAWN.to_string(),
                        VERDICT_OSV_NOISE.to_string(),
                        adv_id,
                    ),
                );
            }
        }
    }

    // Write output
    let extra_cols = ["finding", "verdict", "matched_advisory"];
    let mut out_fields = fieldnames.clone();
    for col in &extra_cols {
        if !out_fields.contains(&col.to_string()) {
            out_fields.push(col.to_string());
        }
    }

    info!("Writing categorized output...");
    let mut wtr = Writer::from_path(&comparison)?;
    wtr.write_record(&out_fields)?;

    for row in &all_rows {
        let missing_in = row.get("missing_in").map(|s| s.as_str()).unwrap_or("");
        let mut out_row = row.clone();

        if missing_in == "TPA" {
            let purl = row.get("purl").cloned().unwrap_or_default();
            let cve_id = row.get("cve_id").cloned().unwrap_or_default();
            let key = (purl, cve_id);
            if missing_keys.contains(&key) {
                let (finding, verdict, adv) = cat_cache
                    .get(&key)
                    .cloned()
                    .unwrap_or((FINDING_UNKNOWN.to_string(), String::new(), String::new()));
                out_row.insert("finding".to_string(), finding);
                out_row.insert("verdict".to_string(), verdict);
                out_row.insert("matched_advisory".to_string(), adv);
            } else {
                out_row.insert("finding".to_string(), String::new());
                out_row.insert("verdict".to_string(), String::new());
                out_row.insert("matched_advisory".to_string(), String::new());
            }
        } else if missing_in == "OSV" {
            out_row.insert("finding".to_string(), "TPA_ONLY".to_string());
            out_row.insert("verdict".to_string(), String::new());
            out_row.insert("matched_advisory".to_string(), String::new());
        }

        let values: Vec<String> = out_fields
            .iter()
            .map(|f| out_row.get(f).cloned().unwrap_or_default())
            .collect();
        wtr.write_record(&values)?;
    }
    wtr.flush()?;

    // Summary
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut verdict_counts: HashMap<String, usize> = HashMap::new();

    for (key, (finding, verdict, _)) in &cat_cache {
        if missing_keys.contains(key) {
            *counts.entry(finding.clone()).or_default() += 1;
            if !verdict.is_empty() {
                *verdict_counts.entry(verdict.clone()).or_default() += 1;
            }
        }
    }

    let classifiable_findings = [
        FINDING_TPA_MISS,
        FINDING_VERSION_NA,
        FINDING_ECO_MISMATCH,
        FINDING_CROSS_PACKAGE,
        FINDING_CVE_WITHDRAWN,
    ];
    let classifiable: usize = classifiable_findings
        .iter()
        .map(|f| counts.get(*f).copied().unwrap_or(0))
        .sum();
    let osv_noise: usize = classifiable_findings
        .iter()
        .filter(|f| **f != FINDING_TPA_MISS)
        .map(|f| counts.get(*f).copied().unwrap_or(0))
        .sum();

    info!("=== FINDINGS (missing_in == TPA) ===");
    let mut sorted_counts: Vec<_> = counts.iter().collect();
    sorted_counts.sort_by(|a, b| b.1.cmp(a.1));
    for (label, count) in &sorted_counts {
        info!("  {}: {}", label, count);
    }

    info!("=== VERDICT (headline) ===");
    let mut sorted_verdicts: Vec<_> = verdict_counts.iter().collect();
    sorted_verdicts.sort_by(|a, b| b.1.cmp(a.1));
    for (label, count) in &sorted_verdicts {
        info!("  {}: {}", label, count);
    }

    if classifiable > 0 {
        let tpa_miss_count = counts.get(FINDING_TPA_MISS).copied().unwrap_or(0);
        info!(
            "OSV noise: {}/{} ({:.1}% of classifiable rows)",
            osv_noise,
            classifiable,
            100.0 * osv_noise as f64 / classifiable as f64
        );
        info!(
            "TPA gaps: {}/{} ({:.1}%)",
            tpa_miss_count,
            classifiable,
            100.0 * tpa_miss_count as f64 / classifiable as f64
        );
    }

    info!("Wrote: {}", comparison_path);
    Ok(())
}
