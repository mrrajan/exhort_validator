use crate::sbom_cdx;
use chrono;
use csv::Writer;
use cvss::v3::Base;
use cvss::v4::Vector;
use log::{error, info, warn};
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct Vulnerability {
    pub id: String,
    pub cvssScore: String,
}

impl Vulnerability {
    fn new(cve: &str, cvss: String) -> Self {
        Vulnerability {
            id: cve.to_string(),
            cvssScore: cvss,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vulns {
    vulnerabilities: Option<Vec<Vulnerability>>,
}

impl Vulns {
    fn new(vul: Option<Vec<Vulnerability>>) -> Self {
        Vulns { vulnerabilities: vul }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvQuerybatchResponse {
    #[serde(default)]
    results: Vec<OsvVulns>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct OsvVulns {
    #[serde(default)]
    pub vulns: Vec<OsvVulnId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Advisory summary from [querybatch](https://google.github.io/osv.dev/post-v1-querybatch/) (`id` + `modified` only).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsvVulnId {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

#[derive(Serialize, Debug)]
struct OsvQueryPackage {
    purl: String,
}

#[derive(Serialize, Debug)]
struct OsvQueryItem {
    package: OsvQueryPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Serialize, Debug)]
struct OsvQuerybatchRequest {
    queries: Vec<OsvQueryItem>,
}

/// Max PURLs per querybatch request (conservative; OSV also paginates large result sets).
pub const OSV_QUERYBATCH_CHUNK_SIZE: usize = 100;

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvQuerybatchRow {
    pub PURL: String,
    pub OSV_ID: String,
    pub MODIFIED: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct OSVAlias {
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    upstream: Vec<String>,
    #[serde(default)]
    severity: Vec<OSVSeverity>,
}

impl OSVAlias {
    pub fn get_alias(&self) -> &Vec<String> {
        &self.aliases
    }

    pub fn get_cve_ids(&self) -> Vec<&str> {
        self.upstream
            .iter()
            .chain(self.aliases.iter())
            .filter(|id| id.starts_with("CVE-"))
            .map(|s| s.as_str())
            .collect()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVSeverity {
    #[serde(rename = "type")]
    cvsstype: String,
    score: String,
}

impl OsvQuerybatchResponse {
    pub fn iter_results(&self) -> impl Iterator<Item = &OsvVulns> {
        self.results.iter()
    }

    fn into_results(self) -> Vec<OsvVulns> {
        self.results
    }
}

impl OsvVulns {
    pub fn iter_vulns(&self) -> impl Iterator<Item = &OsvVulnId> {
        self.vulns.iter()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVResults {
    #[serde(rename = "ref")]
    pub reference: String,
    pub issues: Option<Vec<Vulnerability>>,
    pub transitive: Option<Vec<Depends>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Depends {
    #[serde(rename = "ref")]
    pub reference: String,
    pub vulnerabilities: Option<Vec<Vulnerability>>,
}

impl Depends {
    pub fn new(package: String, vuln: Option<Vec<Vulnerability>>) -> Self {
        Depends {
            reference: package,
            vulnerabilities: vuln,
        }
    }
}

impl OSVResults {
    pub fn new(reference: String, issues: Option<Vec<Vulnerability>>, transitive: Option<Vec<Depends>>) -> Self {
        OSVResults {
            reference: reference,
            issues: issues,
            transitive: transitive,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVHeader {
    pub PURL: String,
    pub CVE_ID: String,
    pub CVSS: String,
}

fn build_osv_querybatch_request(purls: &[String], page_tokens: Option<&[Option<String>]>) -> OsvQuerybatchRequest {
    OsvQuerybatchRequest {
        queries: purls
            .iter()
            .enumerate()
            .map(|(i, purl)| OsvQueryItem {
                package: OsvQueryPackage {
                    purl: purl.clone(),
                },
                page_token: page_tokens.and_then(|tokens| tokens.get(i).cloned()).flatten(),
            })
            .collect(),
    }
}

/// Call OSV `/v1/querybatch` for all PURLs (chunked, with pagination). Result order matches input PURLs.
pub async fn query_osv_batch(
    client: &reqwest::Client,
    semaphore: &Arc<Semaphore>,
    purls: &[String],
) -> Result<Vec<OsvVulns>, Box<dyn Error>> {
    if purls.is_empty() {
        return Ok(Vec::new());
    }

    let total_chunks = (purls.len() + OSV_QUERYBATCH_CHUNK_SIZE - 1) / OSV_QUERYBATCH_CHUNK_SIZE;
    info!("OSV querybatch: processing {} chunk(s) concurrently...", total_chunks);

    let mut handles = Vec::with_capacity(total_chunks);
    for chunk in purls.chunks(OSV_QUERYBATCH_CHUNK_SIZE) {
        let client = client.clone();
        let sem = Arc::clone(semaphore);
        let owned_chunk: Vec<String> = chunk.to_vec();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            query_osv_batch_chunk(&client, &owned_chunk).await.map_err(|e| e.to_string())
        });
        handles.push(handle);
    }

    let mut merged = Vec::with_capacity(purls.len());
    let mut failed_chunks = 0u32;
    for (idx, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(chunk_results)) => merged.extend(chunk_results),
            Ok(Err(e)) => {
                error!("OSV querybatch chunk {} failed: {}", idx, e);
                failed_chunks += 1;
                let chunk_size = std::cmp::min(
                    OSV_QUERYBATCH_CHUNK_SIZE,
                    purls.len() - idx * OSV_QUERYBATCH_CHUNK_SIZE,
                );
                merged.extend(std::iter::repeat_with(OsvVulns::default).take(chunk_size));
            }
            Err(e) => {
                error!("OSV querybatch chunk {} panicked: {}", idx, e);
                failed_chunks += 1;
                let chunk_size = std::cmp::min(
                    OSV_QUERYBATCH_CHUNK_SIZE,
                    purls.len() - idx * OSV_QUERYBATCH_CHUNK_SIZE,
                );
                merged.extend(std::iter::repeat_with(OsvVulns::default).take(chunk_size));
            }
        }
    }
    if failed_chunks > 0 {
        warn!(
            "OSV: {} of {} chunk(s) failed; results are partial",
            failed_chunks, total_chunks
        );
    }
    Ok(merged)
}

async fn query_osv_batch_chunk(
    client: &reqwest::Client,
    purls: &[String],
) -> Result<Vec<OsvVulns>, Box<dyn Error>> {
    let mut accumulated: Vec<OsvVulns> = vec![OsvVulns::default(); purls.len()];
    let mut page_tokens: Vec<Option<String>> = vec![None; purls.len()];

    loop {
        let body = build_osv_querybatch_request(purls, Some(&page_tokens));
        let response = post_osv_querybatch(client, &body).await?;

        if response.results.len() != purls.len() {
            return Err(format!(
                "OSV querybatch returned {} results for {} queries",
                response.results.len(),
                purls.len()
            )
            .into());
        }

        let mut more_pages = false;
        for (i, result) in response.into_results().into_iter().enumerate() {
            accumulated[i].vulns.extend(result.vulns);
            if let Some(token) = result.next_page_token {
                page_tokens[i] = Some(token);
                more_pages = true;
            } else {
                page_tokens[i] = None;
            }
        }

        if !more_pages {
            break;
        }
    }

    Ok(accumulated)
}

async fn post_osv_querybatch(
    client: &reqwest::Client,
    body: &OsvQuerybatchRequest,
) -> Result<OsvQuerybatchResponse, Box<dyn Error>> {
    let response = client
        .post("https://api.osv.dev/v1/querybatch")
        .header("Accept", "application/json")
        .json(body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("OSV querybatch failed ({status}): {text}").into());
    }

    Ok(response.json::<OsvQuerybatchResponse>().await?)
}

/// Resolve advisory IDs from querybatch into CVE-level records by calling `/v1/vulns/{id}`.
/// Deduplicates advisory IDs first — each unique advisory is resolved once, then mapped to all PURLs.
pub async fn resolve_advisories_to_cves(
    client: &reqwest::Client,
    semaphore: &Arc<Semaphore>,
    by_purl: &HashMap<String, OsvVulns>,
) -> Vec<OSVHeader> {
    // Build mapping: advisory_id -> list of PURLs that reference it
    let mut advisory_to_purls: HashMap<String, Vec<String>> = HashMap::new();
    for (purl, result) in by_purl {
        for vuln in &result.vulns {
            advisory_to_purls
                .entry(vuln.id.clone())
                .or_default()
                .push(purl.clone());
        }
    }

    let total_entries: usize = advisory_to_purls.values().map(|v| v.len()).sum();
    info!(
        "OSV: resolving {} unique advisory(ies) to CVEs ({} total entries, {:.1}x dedup)...",
        advisory_to_purls.len(),
        total_entries,
        total_entries as f64 / advisory_to_purls.len() as f64
    );

    // Resolve each unique advisory concurrently
    let unique_ids: Vec<String> = advisory_to_purls.keys().cloned().collect();
    let mut handles = Vec::with_capacity(unique_ids.len());
    for advisory_id in &unique_ids {
        let client = client.clone();
        let sem = Arc::clone(semaphore);
        let advisory_id = advisory_id.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let detail = get_osv_cve(&client, advisory_id.clone()).await;
            (advisory_id, detail)
        });
        handles.push(handle);
    }

    // Collect resolved advisory details
    let mut resolved: HashMap<String, OSVAlias> = HashMap::with_capacity(unique_ids.len());
    for handle in handles {
        match handle.await {
            Ok((advisory_id, detail)) => {
                resolved.insert(advisory_id, detail);
            }
            Err(e) => {
                error!("OSV advisory resolution task panicked: {}", e);
            }
        }
    }

    info!(
        "OSV: resolved {}/{} unique advisories, mapping to PURLs...",
        resolved.len(),
        unique_ids.len()
    );

    // Map resolved advisories back to all PURLs
    let mut osv_headers: Vec<OSVHeader> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for (advisory_id, purls) in &advisory_to_purls {
        let detail = match resolved.get(advisory_id) {
            Some(d) => d,
            None => continue,
        };
        let cve_ids = detail.get_cve_ids();

        let cvss_vector = detail
            .severity
            .iter()
            .find(|s| s.score.contains("CVSS:3") || s.score.contains("CVSS:4"))
            .map(|s| s.score.clone());

        // Compute CVSS scores once per advisory (shared across PURLs)
        let mut cve_scores: Vec<(String, String)> = Vec::new();
        if cve_ids.is_empty() {
            cve_scores.push((advisory_id.clone(), String::new()));
        } else {
            for cve_id in &cve_ids {
                let score = match &cvss_vector {
                    Some(vector) => get_cvss(vector.clone(), cve_id).await,
                    None => String::new(),
                };
                cve_scores.push((cve_id.to_string(), score));
            }
        }

        for purl in purls {
            for (cve_id, score) in &cve_scores {
                if !seen.insert((purl.clone(), cve_id.clone())) {
                    continue;
                }
                osv_headers.push(OSVHeader {
                    PURL: purl.clone(),
                    CVE_ID: cve_id.clone(),
                    CVSS: score.clone(),
                });
            }
        }
    }

    osv_headers
}

/// Query OSV querybatch for all PURLs and write JSON + CSV under `test_results/source/`.
pub async fn retrieve_osv_querybatch(
    client: &reqwest::Client,
    semaphore: &Arc<Semaphore>,
    purls: Vec<String>,
    sbom_type: &str,
) -> Result<(HashMap<String, OsvVulns>, Vec<OSVHeader>), Box<dyn Error>> {
    info!("OSV querybatch: querying {} package(s)...", purls.len());
    let batch_results = query_osv_batch(client, semaphore, &purls).await?;

    let mut by_purl: HashMap<String, OsvVulns> = HashMap::new();
    for (purl, result) in purls.iter().zip(batch_results.iter()) {
        by_purl.insert(purl.clone(), result.clone());
    }

    let now = chrono::offset::Local::now();
    let timestamp = now.format("%Y%m%y_%H%M%S");

    let json_path = format!(
        "test_results/source/{}_osv_querybatch_{}.json",
        sbom_type, timestamp
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&json_path)?;
    file.write_all(to_string_pretty(&by_purl)?.as_bytes())?;

    let csv_path = format!(
        "test_results/source/{}_osv_querybatch_{}.csv",
        sbom_type, timestamp
    );
    let mut wtr = Writer::from_path(&csv_path)?;
    let mut rows: Vec<OsvQuerybatchRow> = Vec::new();
    for (purl, result) in &by_purl {
        if result.vulns.is_empty() {
            rows.push(OsvQuerybatchRow {
                PURL: purl.clone(),
                OSV_ID: String::new(),
                MODIFIED: String::new(),
            });
            continue;
        }
        for vuln in &result.vulns {
            rows.push(OsvQuerybatchRow {
                PURL: purl.clone(),
                OSV_ID: vuln.id.clone(),
                MODIFIED: vuln.modified.clone().unwrap_or_default(),
            });
        }
    }
    for row in &rows {
        wtr.serialize(row)?;
    }
    wtr.flush()?;

    info!(
        "OSV querybatch: wrote {} ({} advisory row(s))",
        json_path,
        rows.len()
    );

    info!("OSV: resolving advisories to CVEs via /v1/vulns/...");
    let osv_cve_headers = resolve_advisories_to_cves(client, semaphore, &by_purl).await;

    let cve_csv_path = format!(
        "test_results/source/{}_osv_cves_{}.csv",
        sbom_type, timestamp
    );
    let mut cve_wtr = Writer::from_path(&cve_csv_path)?;
    for row in &osv_cve_headers {
        cve_wtr.serialize(row)?;
    }
    cve_wtr.flush()?;

    info!(
        "OSV: resolved {} CVE(s) from {} advisory(ies), wrote {}",
        osv_cve_headers.len(),
        rows.len(),
        cve_csv_path
    );

    Ok((by_purl, osv_cve_headers))
}

pub async fn retrieve_sbom_osv_vulns(purls: Vec<String>, sbom_type: &str) -> Result<Vec<OSVHeader>, Box<dyn Error>> {
    info!("OSV: Initiate process...");
    let now = chrono::offset::Local::now();
    let custom_datetime_format = now.format("%Y%m%y_%H%M%S");
    let mut vulmap: HashMap<String, Option<Vec<Vulnerability>>> = HashMap::new();
    for purl in purls {
        info!("Getting vuln info for {:?}...", &purl);
        let purl_vuln: Option<Vec<Vulnerability>> = get_osv_vulnerability(&purl).await;
        vulmap.insert(purl.clone(), purl_vuln);
    }
    info!("Vuln info gathing finished!");

    let vulnerable_dependencies: HashMap<String, Option<Vec<Vulnerability>>> = remove_dep_without_vulns(vulmap);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(format!(
            "test_results/source/{}_osv_{}.json",
            sbom_type.to_string(),
            custom_datetime_format.to_string()
        ))
        .expect("File creation failed");
    let json_str = to_string_pretty(&vulnerable_dependencies).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    info!("OSV-NVD Dependency Analysis Completed!");

    let mut wtr = Writer::from_path(format!(
        "test_results/source/{}_osv_{}.csv",
        sbom_type.to_string(),
        custom_datetime_format.to_string()
    ))?;
    let mut osv_rows: Vec<OSVHeader> = Vec::new();
    for (purl, vulnlist) in &vulnerable_dependencies {
        for vuln in vulnlist {
            for vul in vuln {
                osv_rows.push(OSVHeader {
                    PURL: purl.to_string(),
                    CVE_ID: vul.id.clone(),
                    CVSS: vul.cvssScore.clone(),
                });
            }
        }
    }
    for row in &osv_rows {
        wtr.serialize(row)?;
    }
    let _ = wtr.flush();
    info!("OSV: Response Retrieved...");
    Ok(osv_rows)
}

pub async fn get_package_vulnmap(key: String, vulmap: HashMap<String, Option<Vec<Vulnerability>>>) -> Depends {
    match vulmap.get(&key) {
        Some(vuln) => Depends::new(key, vuln.clone()),
        None => panic!("Impossible! Key not found in vulmap: {}", key),
    }
}
pub async fn get_osv_vulnerability(purl: &str) -> Option<Vec<Vulnerability>> {
    get_osv_response((&purl).to_string()).await
}

pub async fn get_osv_payload(purl: String) -> String {
    let json_str = r#"{"queries": [{"package": {"purl": "<purl>"}}]}"#;
    format!("{}", json_str.replace("<purl>", &purl))
}

pub async fn get_osv_response(purl: String) -> Option<Vec<Vulnerability>> {
    let client = reqwest::Client::new();
    let osv_response = retrieve_osv_ghsa(&client, purl).await;

    if osv_response.results.is_empty() {
        return Some(Vec::new());
    }

    let mut unique_vulns: HashSet<Vulnerability> = HashSet::new();

    for osv_vuln in &osv_response.results {
        if osv_vuln.vulns.is_empty() {
            continue;
        }

        for ghsa in &osv_vuln.vulns {
            let cves = get_osv_cve(&client, ghsa.id.clone()).await;

            if cves.aliases.is_empty() {
                continue;
            }

            let cvss_vector = cves
                .severity
                .iter()
                .find(|cvss| cvss.score.contains("CVSS:3") || cvss.score.contains("CVSS:4"))
                .map(|cvss| cvss.score.clone());

            for alias in &cves.aliases {
                if !alias.contains("CVE") {
                    continue;
                }

                let osv_score = match &cvss_vector {
                    Some(vector) => get_cvss(vector.clone(), alias).await,
                    None => String::new(),
                };

                unique_vulns.insert(Vulnerability::new(alias, osv_score));
            }
        }
    }

    Some(unique_vulns.into_iter().collect())
}

pub async fn retrieve_osv_ghsa(client: &reqwest::Client, purl: String) -> OsvQuerybatchResponse {
    let url = "https://api.osv.dev/v1/querybatch";
    let body = get_osv_payload(purl.clone());
    let response = client
        .post(url)
        .header("Accept", "application/json")
        .body(body.await)
        .send()
        .await
        .expect("Error from response")
        .json::<OsvQuerybatchResponse>()
        .await
        .expect("Error");
    response
}

pub async fn get_json_response(client: &reqwest::Client, url: String) -> serde_json::Value {
    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text_res = response.text().await.unwrap();
    if status != StatusCode::OK {
        error!("NVD API failed with Error body: {}", text_res);
    }
    let json_response: serde_json::Value = serde_json::from_str(&text_res).expect("Failure");
    json_response
}

pub async fn get_osv_cve(client: &reqwest::Client, ghsa_id: String) -> OSVAlias {
    let url = format!("https://api.osv.dev/v1/vulns/{}", ghsa_id);
    let response = match client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("OSV /v1/vulns/{} request failed: {}", ghsa_id, e);
            return OSVAlias {
                aliases: vec![],
                upstream: vec![],
                severity: vec![],
            };
        }
    };
    let status = response.status();
    if status != StatusCode::OK {
        error!("OSV /v1/vulns/{} returned {}", ghsa_id, status);
        return OSVAlias {
            aliases: vec![],
            upstream: vec![],
            severity: vec![],
        };
    }
    match response.json::<OSVAlias>().await {
        Ok(json) => json,
        Err(err) => {
            error!("OSV /v1/vulns/{} parse error: {}", ghsa_id, err);
            OSVAlias {
                aliases: vec![],
                upstream: vec![],
                severity: vec![],
            }
        }
    }
}

pub async fn get_cvss(vector: String, id: &str) -> String {
    let mut cvss = String::new();
    if vector.starts_with("CVSS:4") {
        cvss = match Vector::from_str(&vector) {
            Ok(base) => base.score().value().to_string(),
            Err(e) => {
                warn!("Error from vector {} {}", vector, e);
                String::from("0.0")
            }
        }
    } else if vector.starts_with("CVSS:3") {
        cvss = match Base::from_str(&vector) {
            Ok(base) => base.score().value().to_string(),
            Err(e) => {
                warn!("Error from vector {} {}", vector, e);
                String::from("0.0")
            }
        }
        //cvss = Base::from_str(&vector).expect("Error for Vector").score().value().to_string();
    } else {
        warn!("Unsupported CVSS for CVE {} with vector {}", id, vector);
    }
    // match Base::from_str(&vector) {
    //     Ok(base) => {
    //         cvss = base.score().value().to_string();
    //     }
    //     Err(e) => {

    //     }
    // }
    cvss
}

/* Obselete - using CVSS crate to retrieve CVSS from vector
pub async fn get_nvd(cve: &str) -> Value {
    let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=".to_owned() + cve;
    let json_response: serde_json::Value = get_json_response(url).await;
    let v31base =
        json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"].clone();
    let v30base =
        json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"].clone();
    let v2base =
        json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"].clone();
    let mut base = v31base.clone();
    if !(v31base.is_null()) {
        base = v31base.clone();
    } else {
        if !(v30base.is_null()) {
            base = v30base.clone();
        } else if !(v2base.is_null()) {
            base = v2base.clone();
        }
    }
    base
}
*/
pub async fn get_dep_tree(data: &sbom_cdx::CycloneDXBOM) -> HashMap<&str, Option<Vec<String>>> {
    let mut deptree: HashMap<&str, Option<Vec<String>>> = HashMap::new();
    for comp in data.iter_component() {
        match &comp.purl {
            Some(purl) => {
                let mut dependencies: Option<Vec<String>> = None;
                if !(data.dependencies == None) {
                    for dep in data.iter_dependents() {
                        if *purl == dep.dependency_ref {
                            if let Some(dependency) = &dep.dependsOn {
                                dependencies = dep.dependsOn.clone();
                            }
                        }
                    }
                }
                deptree.insert(purl, dependencies);
            }
            None => {
                info!("No Package URL found");
            }
        }
    }
    deptree
}

pub fn flatten_dependencies(
    purl: &str,
    deptree: HashMap<&str, Option<Vec<String>>>,
    exist_dep: Option<HashSet<String>>,
) -> Vec<String> {
    let mut flat_hs: HashSet<String> = exist_dep.unwrap_or_else(HashSet::new);
    if let Some(dependency) = deptree.get(purl).cloned().flatten() {
        for dep in dependency {
            if flat_hs.contains(&dep) {
                continue;
            }
            flat_hs.insert(dep.clone());
            let x = flatten_dependencies(&dep, deptree.clone(), Some(flat_hs.clone()));
            for y in x {
                flat_hs.insert(y);
            }
        }
    }
    let unique_flatdep = flat_hs.into_iter().collect();
    unique_flatdep
}

pub fn remove_dep_without_vulns(
    vulnmap: HashMap<String, Option<Vec<Vulnerability>>>,
) -> HashMap<String, Option<Vec<Vulnerability>>> {
    let mut depwithvuln: HashMap<String, Option<Vec<Vulnerability>>> = HashMap::new();
    for (reference, vuln) in vulnmap {
        if !(vuln.clone().expect("").is_empty()) {
            depwithvuln.insert(reference, vuln);
        }
    }
    depwithvuln
}
