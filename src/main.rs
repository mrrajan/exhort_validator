mod categorize;
mod compare;
mod exhort;
mod osv;
mod sbom;
mod sbom_cdx;
mod sbom_spdx;
mod tpa_analyze;

use clap::{Arg, Command};
use log::{error, info};
use simplelog::*;
use std::sync::Arc;
use tokio::sync::Semaphore;

fn load_purls_from_txt(path: &str) -> Vec<String> {
    let content = std::fs::read_to_string(path).expect("Failed to read PURLs file");
    content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

#[tokio::main]
async fn main() {
    let matches = Command::new("Trust Breaker")
        .about("Extracts PURLs from an SBOM and retrieves OSV querybatch and RHTPA results.")
        .arg(
            Arg::new("sbom_file")
                .help("Absolute path to the SBOM file (CycloneDX or SPDX)")
                .short('s')
                .long("sbom_file")
                .required(false),
        )
        .arg(
            Arg::new("sbom_type")
                .help("SBOM type: cdx or spdx")
                .short('t')
                .long("sbom_type")
                .required(true),
        )
        .arg(
            Arg::new("purls_file")
                .help("Path to a pre-extracted PURLs text file (one PURL per line); skips SBOM extraction")
                .short('p')
                .long("purls_file")
                .required(false),
        )
        .arg(
            Arg::new("tpa_url")
                .help("RHTPA base URL (optional; omit -a for unauthenticated calls)")
                .short('r')
                .long("tpa_url")
                .required(false),
        )
        .arg(
            Arg::new("tpa_token")
                .help("RHTPA access token (optional)")
                .short('a')
                .long("tpa_token")
                .required(false),
        )
        .arg(
            Arg::new("exhort_url")
                .help("Exhort API URL (optional)")
                .short('e')
                .long("exhort_url")
                .required(false),
        )
        .arg(
            Arg::new("categorize")
                .help("Categorize TPA gaps after comparison (requires rpmdev-vercmp)")
                .short('c')
                .long("categorize")
                .action(clap::ArgAction::SetTrue)
                .required(false),
        )
        .get_matches();

    let sbom_type = matches.get_one::<String>("sbom_type").unwrap();

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            std::fs::File::create("exhort_validator.log").unwrap(),
        ),
    ])
    .unwrap();

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(20)
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .expect("Failed to build HTTP client");

    let semaphore = Arc::new(Semaphore::new(20));

    let purls = if let Some(purls_path) = matches.get_one::<String>("purls_file") {
        info!("Loading PURLs from file: {}", purls_path);
        let loaded = load_purls_from_txt(purls_path);
        if loaded.is_empty() {
            error!("No PURLs found in file: {}", purls_path);
            return;
        }
        info!("Loaded {} PURL(s) from file", loaded.len());
        loaded
    } else if let Some(sbom_file) = matches.get_one::<String>("sbom_file") {
        let extracted = sbom::extract_purls_from_sbom(sbom_file, sbom_type).await;
        if extracted.is_empty() {
            error!("No PURLs found in SBOM (sbom_type must be `cdx` or `spdx`)");
            return;
        }
        info!("Extracted {} PURL(s) from SBOM", extracted.len());
        if let Err(e) = sbom::save_purls_to_file(&extracted, sbom_type) {
            error!("Failed to save PURLs to file: {}", e);
            return;
        }
        extracted
    } else {
        error!("Either --sbom_file (-s) or --purls_file (-p) is required");
        return;
    };

    // --- OSV ---
    let osv_cve_data = match osv::retrieve_osv_querybatch(
        &client,
        &semaphore,
        purls.clone(),
        sbom_type,
    )
    .await
    {
        Ok((_advisory_map, cve_headers)) => {
            info!("OSV: resolved {} CVE(s) from advisories", cve_headers.len());
            cve_headers
        }
        Err(e) => {
            error!("OSV querybatch failed: {}", e);
            Vec::new()
        }
    };

    // --- TPA ---
    let tpa_data = if let Some(tpa_base_url) = matches.get_one::<String>("tpa_url") {
        let tpa_access_token = matches.get_one::<String>("tpa_token").map(|s| s.as_str());
        let results = tpa_analyze::tpa_purl_vuln_analyze(
            &client,
            &semaphore,
            tpa_base_url,
            tpa_access_token,
            purls.clone(),
        )
        .await;
        info!("RHTPA: retrieved {} vulnerability record(s)", results.len());
        results
    } else {
        info!("No -r/--tpa_url provided; skipping RHTPA retrieval");
        Vec::new()
    };

    // --- Exhort ---
    let sbom_file = matches.get_one::<String>("sbom_file");
    let exhort_data = if let Some(exhort_url) = matches.get_one::<String>("exhort_url") {
        if let Some(sbom_path) = sbom_file {
            let results =
                exhort::get_exhort_response(&client, sbom_type, sbom_path, exhort_url).await;
            info!("Exhort: retrieved {} vulnerability record(s)", results.len());
            results
        } else {
            error!("Exhort requires --sbom_file (-s); skipping");
            Vec::new()
        }
    } else {
        info!("No -e/--exhort_url provided; skipping Exhort retrieval");
        Vec::new()
    };

    // --- Comparison ---
    if !osv_cve_data.is_empty() || !tpa_data.is_empty() || !exhort_data.is_empty() {
        if let Err(e) = compare::compare_sources(osv_cve_data, tpa_data, exhort_data).await {
            error!("Comparison failed: {}", e);
        }
    } else {
        info!("No vulnerability data from any source; skipping comparison");
    }

    // --- Categorize TPA gaps ---
    if matches.get_flag("categorize") {
        let comparison_csv = "test_results/comparison/comparison_osv_vs_tpa.csv";
        info!("Categorizing TPA gaps in {}...", comparison_csv);
        if let Err(e) = categorize::run_categorize(
            &client,
            comparison_csv,
            None,
            "test_results/cache",
            20,
            0,
        )
        .await
        {
            error!("Categorization failed: {}", e);
        }
    }

    info!("Run complete.");
}
