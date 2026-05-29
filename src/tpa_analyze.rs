use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use csv::Writer;
use log::{error, info, warn};
use reqwest;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use serde_json::{from_str, to_string_pretty};
use tokio::sync::Semaphore;
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

/// PURLs per analyze request (keep modest to limit payload size).
pub const TPA_CHUNK_SIZE: usize = 25;
/// Max in-flight TPA analyze requests (1 = strictly serial).
pub const TPA_CONCURRENCY: usize = 1;
/// Pause between chunk requests when concurrency is 1 (ms).
pub const TPA_CHUNK_DELAY_MS: u64 = 300;

#[derive(Serialize, Deserialize, Debug)]
pub struct Score {
    #[serde(rename = "type")]
    pub cvssType: String,
    pub value: f32,
    pub severity: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Labels {
    //pub importer: String,
    #[serde(rename = "type")]
    pub importerType: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AffContent {
    pub identifier: String,
    pub title: String,
    pub labels: Labels,
    pub scores: Vec<Score>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Affected {
    pub affected: Vec<AffContent>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vulnerability {
    pub identifier: String,
    pub status: Affected,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TPAResponse {
    #[serde(flatten)]
    pub tpa_response: HashMap<String, PackageResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PackageResponse {
    pub details: Vec<Vulnerability>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TPAHeaders {
    pub PURL: String,
    pub CVE_ID: String,
    pub OSV_ID: String,
    pub CVSS: String,
    pub CVSSType: String,
    pub Source: String,
}

fn is_purl_valid_for_tpa(purl: &str) -> bool {
    let no_namespace_types = ["cargo", "golang", "pypi", "nuget", "gem"];
    if let Some(rest) = purl.strip_prefix("pkg:") {
        if let Some((type_and_path, _version)) = rest.split_once('@') {
            let segments: Vec<&str> = type_and_path.splitn(3, '/').collect();
            if segments.len() >= 3 {
                let purl_type = segments[0];
                if no_namespace_types.contains(&purl_type) {
                    return false;
                }
            }
        }
    }
    true
}

pub async fn tpa_purl_vuln_analyze(
    client: &reqwest::Client,
    _semaphore: &Arc<Semaphore>,
    tpa_base_url: &str,
    tpa_access_token: Option<&str>,
    purls: Vec<String>,
) -> Vec<TPAHeaders> {
    let original_count = purls.len();
    let purls: Vec<String> = purls.into_iter().filter(|p| is_purl_valid_for_tpa(p)).collect();
    let filtered = original_count - purls.len();
    if filtered > 0 {
        warn!(
            "RHTPA: filtered out {} PURL(s) with invalid namespace for their type",
            filtered
        );
    }

    let total_chunks = (purls.len() + TPA_CHUNK_SIZE - 1) / TPA_CHUNK_SIZE;
    info!(
        "RHTPA: {} PURLs in {} chunk(s) of {} (max {} concurrent, {}ms between chunks)...",
        purls.len(),
        total_chunks,
        TPA_CHUNK_SIZE,
        TPA_CONCURRENCY,
        TPA_CHUNK_DELAY_MS
    );
    let tpa_analyze_endpoint = format!("{}/api/v2/vulnerability/analyze", tpa_base_url);
    info!("TPA Endpoint: {}", tpa_analyze_endpoint);

    if let Some(token) = tpa_access_token {
        if token.is_empty() {
            info!("RHTPA: No access token provided, calling API without authentication");
        }
    } else {
        info!("RHTPA: No access token provided, calling API without authentication");
    }

    let tpa_sem = Arc::new(Semaphore::new(TPA_CONCURRENCY));
    let delay = std::time::Duration::from_millis(TPA_CHUNK_DELAY_MS);
    let mut all_headers: Vec<TPAHeaders> = Vec::new();

    for (idx, chunk) in purls.chunks(TPA_CHUNK_SIZE).enumerate() {
        if idx > 0 && TPA_CHUNK_DELAY_MS > 0 {
            tokio::time::sleep(delay).await;
        }
        let _permit = tpa_sem.acquire().await.unwrap();
        let chunk_headers = tpa_purl_vuln_analyze_chunk(
            client,
            &tpa_analyze_endpoint,
            tpa_access_token,
            chunk,
        )
        .await;
        all_headers.extend(chunk_headers);

        let done = idx + 1;
        if done == 1 || done == total_chunks || done % 20 == 0 {
            info!("RHTPA: progress {}/{} chunk(s)", done, total_chunks);
        }
    }

    if !all_headers.is_empty() {
        if let Err(e) = write_tpa_combined_csv(&all_headers) {
            error!("Failed to write combined TPA CSV: {}", e);
        }
    }

    info!("RHTPA: Retrieved {} total record(s)", all_headers.len());
    all_headers
}

async fn tpa_purl_vuln_analyze_chunk(
    client: &reqwest::Client,
    endpoint: &str,
    tpa_access_token: Option<&str>,
    purls: &[String],
) -> Vec<TPAHeaders> {
    let content_body = format!(
        "{{\"purls\":[{}]}}",
        purls
            .iter()
            .map(|purl| format!("\"{}\"", purl))
            .collect::<Vec<_>>()
            .join(",")
    );

    let mut request = client
        .post(endpoint)
        .header("Content-Type", "application/json");

    if let Some(token) = tpa_access_token.filter(|t| !t.is_empty()) {
        request = request.header("Authorization", format!("Bearer {}", token));
    }

    match request.body(content_body).send().await {
        Ok(response) => {
            let status = response.status();
            let text_response = response.text().await.unwrap_or_default();
            if status == StatusCode::OK {
                let tpa_response: TPAResponse = match from_str(&text_response) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("TPA parse error for chunk: {}", e);
                        return Vec::new();
                    }
                };
                extract_tpa_headers(tpa_response)
            } else {
                error!("TPA chunk error: status={}, body={}", status, &text_response[..std::cmp::min(text_response.len(), 500)]);
                Vec::new()
            }
        }
        Err(e) => {
            error!("TPA chunk request failed: {}", e);
            Vec::new()
        }
    }
}

fn extract_tpa_headers(tpa_response: TPAResponse) -> Vec<TPAHeaders> {
    let mut tpa_values: Vec<TPAHeaders> = Vec::new();
    for (purl, package_details) in tpa_response.tpa_response {
        for vuln in package_details.details {
            for affected in vuln.status.affected {
                for score in affected.scores {
                    tpa_values.push(TPAHeaders {
                        PURL: purl.to_string(),
                        CVE_ID: vuln.identifier.to_string(),
                        OSV_ID: affected.identifier.to_string(),
                        CVSS: score.value.to_string(),
                        CVSSType: score.cvssType.to_string(),
                        Source: affected.labels.importerType.to_string(),
                    });
                }
            }
        }
    }
    tpa_values
}

fn write_tpa_combined_csv(headers: &[TPAHeaders]) -> Result<(), Box<dyn Error>> {
    let now: chrono::DateTime<chrono::Local> = chrono::offset::Local::now();
    let timestamp = now.format("%Y%m%y_%H%M%S");
    let csv_path = format!("test_results/source/tpa_response_{}.csv", timestamp);
    let mut wtr = Writer::from_path(&csv_path)?;
    for row in headers {
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    info!("RHTPA: wrote combined CSV to {}", csv_path);
    Ok(())
}

pub async fn write_tpa_result(tpa_response: TPAResponse) -> Result<Vec<TPAHeaders>, Box<dyn Error>> {
    info!("Writing TPA Response to output files...");
    let now: chrono::DateTime<chrono::Local> = chrono::offset::Local::now();
    let custom_datetime_format = now.format("%Y%m%y_%H%M%S");
    let file_path = format!("test_results/source/tpa_response_{}", custom_datetime_format);
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_path.clone() + ".json")
        .await
        .expect("Error while creating TPA log file");
    let response_str = to_string_pretty(&tpa_response).expect("Error while parsing TPA response to json");
    file.write_all(response_str.as_bytes())
        .await
        .expect("Error writing TPA response to log");
    let mut wtr = Writer::from_path(file_path.clone() + ".csv")?;
    let mut tpa_values: Vec<TPAHeaders> = Vec::new();
    for (purl, packageDetails) in tpa_response.tpa_response {
        for vuln in packageDetails.details {
            for affected in vuln.status.affected {
                for score in affected.scores {
                    tpa_values.push(TPAHeaders {
                        PURL: purl.to_string(),
                        CVE_ID: vuln.identifier.to_string(),
                        OSV_ID: affected.identifier.to_string(),
                        CVSS: score.value.to_string(),
                        CVSSType: score.cvssType.to_string(),
                        Source: affected.labels.importerType.to_string(),
                    });
                }
            }
        }
    }
    for row in &tpa_values {
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    info!("RHTPA: Retrieved Response...");
    Ok(tpa_values)
}
