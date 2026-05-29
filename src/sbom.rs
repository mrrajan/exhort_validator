use crate::sbom_cdx;
use crate::sbom_spdx;
use log::info;
use serde_json::to_string_pretty;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;

/// Extract all package URLs from an SBOM file (`sbom_type`: `cdx` or `spdx`).
pub async fn extract_purls_from_sbom(filepath: &str, sbom_type: &str) -> Vec<String> {
    match sbom_type {
        "cdx" => {
            let bom = sbom_cdx::get_cdx_components(filepath).await;
            sbom_cdx::get_cdx_purl(bom).await
        }
        "spdx" => {
            let packages = sbom_spdx::get_spdx_sbom_package(filepath).await;
            sbom_spdx::get_spdx_purl(packages).await
        }
        _ => Vec::new(),
    }
}

/// Write extracted PURLs to `test_results/source/` before slow downstream steps (OSV, TPA).
pub fn save_purls_to_file(purls: &[String], sbom_type: &str) -> Result<(String, String), Box<dyn Error>> {
    let timestamp = chrono::offset::Local::now().format("%Y%m%y_%H%M%S");
    let json_path = format!("test_results/source/{}_purls_{}.json", sbom_type, timestamp);
    let txt_path = format!("test_results/source/{}_purls_{}.txt", sbom_type, timestamp);

    let mut json_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&json_path)?;
    json_file.write_all(to_string_pretty(purls)?.as_bytes())?;

    let mut txt_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&txt_path)?;
    for purl in purls {
        writeln!(txt_file, "{purl}")?;
    }

    info!(
        "Saved {} PURL(s) to {} and {}",
        purls.len(),
        json_path,
        txt_path
    );
    Ok((json_path, txt_path))
}
