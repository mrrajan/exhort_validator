use csv::Writer;
use log::error;
use log::info;
use reqwest;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use serde_json::from_str;
use serde_json::to_string_pretty;
use std::error::Error;
use tokio::fs::{File, OpenOptions as TokioOpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize, Debug)]
pub struct ExhortResponse {
    pub providers: Providers,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Providers {
    pub rhtpa: RHTPA,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RHTPA {
    pub sources: Sources,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Sources {
    pub cve: Option<Source>,
    #[serde(rename = "osv-github")]
    pub osv: Option<Source>,
    #[serde(rename = "redhat-csaf", default)]
    pub csaf: Option<Source>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Source {
    pub dependencies: Vec<Dependency>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub purl: String,
    #[serde(default)]
    pub issues: Vec<Issue>,
    #[serde(default)]
    pub transitive: Vec<Transitive>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Transitive {
    #[serde(rename = "ref")]
    pub purl: String,
    pub issues: Vec<Issue>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Issue {
    pub id: String,
    #[serde(default)]
    pub title: String,
    pub source: String,
    #[serde(rename = "cvssScore")]
    pub cvss_score: f32,
    pub severity: String,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub unique: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExhortRecord {
    pub PURL: String,
    pub CVE_ID: String,
    pub TITLE: String,
    pub SOURCE: String,
    pub CVSS: String,
    pub SEVERITY: String,
    pub TYPE: String,
}

pub async fn get_exhort_response(
    client: &reqwest::Client,
    sbom_type: &str,
    file_path: &str,
    exhort_api: &str,
) -> Vec<ExhortRecord> {
    info!("Exhort: Initiate process...");
    info!("Exhort API URL: {}", exhort_api);
    let mut file = File::open(file_path).await.expect("Error opening the file");
    let mut content_str = String::new();
    file.read_to_string(&mut content_str).await.expect("");
    let content_type = if sbom_type == "cdx" {
        "application/vnd.cyclonedx+json"
    } else {
        "application/vnd.spdx+json"
    };
    let response = client
        .post(exhort_api.to_owned())
        .header("Content-Type", content_type)
        .header("Accept", "application/json")
        .body(content_str)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text_res = response.text().await.unwrap();
    if !(status == StatusCode::OK) {
        error!("Exhort Returns error response : {}", text_res);
        Vec::new()
    } else {
        let exhort_response = from_str(&text_res).expect("Error while parsing ");
        match write_exhort_result(exhort_response).await {
            Ok(records) => records,
            Err(e) => {
                error!("Error writing Exhort result: {}", e);
                Vec::new()
            }
        }
    }
}

pub async fn write_exhort_result(exhort_response: ExhortResponse) -> Result<Vec<ExhortRecord>, Box<dyn Error>> {
    info!("Writing Exhort Response to output files...");
    let now: chrono::DateTime<chrono::Local> = chrono::offset::Local::now();
    let custom_datetime_format = now.format("%Y%m%y_%H%M%S");
    let file_path = format!("test_results/source/exhort_response_{}", custom_datetime_format);

    // Write JSON log file
    let mut file = TokioOpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_path.clone() + ".json")
        .await
        .expect("Error while creating Exhort log file");
    let response_str = to_string_pretty(&exhort_response).expect("Error while parsing Exhort response to json");
    file.write_all(response_str.as_bytes())
        .await
        .expect("Error writing Exhort response to log");

    // Write CSV file with vulnerabilities
    let mut wtr = Writer::from_path(file_path.clone() + ".csv")?;

    // Extract vulnerabilities from both CVE and OSV sources
    let sources = vec![
        ("cve", &exhort_response.providers.rhtpa.sources.cve),
        ("osv-github", &exhort_response.providers.rhtpa.sources.osv),
        ("redhat-csaf", &exhort_response.providers.rhtpa.sources.csaf),
    ];
    let mut exhort_rows: Vec<ExhortRecord> = Vec::new();
    for (_source_name, source) in sources {
        if let Some(src) = source {
            for dependency in &src.dependencies {
                // Direct issues in the main dependency package
                for issue in &dependency.issues {
                    exhort_rows.push(ExhortRecord {
                        PURL: dependency.purl.clone(),
                        CVE_ID: issue.id.clone(),
                        TITLE: issue.title.clone(),
                        SOURCE: issue.source.clone(),
                        CVSS: issue.cvss_score.to_string(),
                        SEVERITY: issue.severity.clone(),
                        TYPE: "Direct".to_string(),
                    });
                }

                // Issues in transitive dependencies
                for transitive in &dependency.transitive {
                    for issue in &transitive.issues {
                        exhort_rows.push(ExhortRecord {
                            PURL: transitive.purl.clone(),
                            CVE_ID: issue.id.clone(),
                            TITLE: issue.title.clone(),
                            SOURCE: issue.source.clone(),
                            CVSS: issue.cvss_score.to_string(),
                            SEVERITY: issue.severity.clone(),
                            TYPE: "Transitive".to_string(),
                        });
                    }
                }
            }
        }
    }
    for row in &exhort_rows {
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    info!("Exhort: Retrieved Response...");
    Ok(exhort_rows)
}
