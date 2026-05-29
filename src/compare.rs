use crate::exhort::ExhortRecord;
use crate::osv::OSVHeader;
use crate::tpa_analyze::TPAHeaders;
use csv::Writer;
use log::info;
use serde_derive::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;

#[derive(Serialize, Debug, Clone)]
pub struct OsvTpaComparisonRecord {
    pub purl: String,
    pub cve_id: String,
    pub osv_cvss: String,
    pub tpa_cvss: String,
    pub missing_in: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct TpaExhortComparisonRecord {
    pub purl: String,
    pub cve_id: String,
    pub tpa_cvss: String,
    pub exhort_cvss: String,
    pub missing_in: String,
}

fn normalize_osv_data(osv_data: &[OSVHeader]) -> HashMap<String, HashMap<String, String>> {
    let mut normalized = HashMap::new();

    for record in osv_data {
        normalized
            .entry(record.PURL.clone())
            .or_insert_with(HashMap::new)
            .insert(record.CVE_ID.clone(), record.CVSS.clone());
    }

    normalized
}

fn normalize_tpa_data(
    tpa_data: &[TPAHeaders],
    filter_source: Option<&str>,
) -> HashMap<String, HashMap<String, String>> {
    let mut normalized = HashMap::new();

    for record in tpa_data {
        if let Some(source) = filter_source {
            if record.Source.to_lowercase() != source.to_lowercase() {
                continue;
            }
        }

        normalized
            .entry(record.PURL.clone())
            .or_insert_with(HashMap::new)
            .insert(record.CVE_ID.clone(), record.CVSS.clone());
    }

    normalized
}

fn normalize_exhort_data(exhort_data: &[ExhortRecord]) -> HashMap<String, HashMap<String, String>> {
    let mut normalized = HashMap::new();

    for record in exhort_data {
        normalized
            .entry(record.PURL.clone())
            .or_insert_with(HashMap::new)
            .insert(record.CVE_ID.clone(), record.CVSS.clone());
    }

    normalized
}

fn compare_osv_vs_tpa(osv_data: &[OSVHeader], tpa_data: &[TPAHeaders]) -> Result<(), Box<dyn Error>> {
    info!("Starting comparison: OSV vs TPA (all sources)...");

    let osv_normalized = normalize_osv_data(osv_data);
    let tpa_normalized = normalize_tpa_data(tpa_data, None);

    let mut all_records: HashSet<(String, String)> = HashSet::new();

    for (purl, cves) in &osv_normalized {
        for cve in cves.keys() {
            all_records.insert((purl.clone(), cve.clone()));
        }
    }

    for (purl, cves) in &tpa_normalized {
        for cve in cves.keys() {
            all_records.insert((purl.clone(), cve.clone()));
        }
    }

    let mut comparison_records = Vec::new();

    for (purl, cve_id) in &all_records {
        let osv_entry = osv_normalized
            .get(purl)
            .and_then(|cves| cves.get(cve_id));

        let tpa_entry = tpa_normalized
            .get(purl)
            .and_then(|cves| cves.get(cve_id));

        let in_osv = osv_entry.is_some();
        let in_tpa = tpa_entry.is_some();

        let mut missing_in = Vec::new();
        if !in_osv {
            missing_in.push("OSV");
        }
        if !in_tpa {
            missing_in.push("TPA");
        }

        if !missing_in.is_empty() {
            comparison_records.push(OsvTpaComparisonRecord {
                purl: purl.clone(),
                cve_id: cve_id.clone(),
                osv_cvss: osv_entry.cloned().unwrap_or_default(),
                tpa_cvss: tpa_entry.cloned().unwrap_or_default(),
                missing_in: missing_in.join(", "),
            });
        }
    }

    write_osv_tpa_csv("test_results/comparison/comparison_osv_vs_tpa.csv", &comparison_records)?;

    info!("OSV vs TPA comparison complete!");
    Ok(())
}

fn compare_tpa_vs_exhort(tpa_data: &[TPAHeaders], exhort_data: &[ExhortRecord]) -> Result<(), Box<dyn Error>> {
    info!("Starting comparison: TPA vs Exhort...");

    let tpa_normalized = normalize_tpa_data(tpa_data, None); // No filter, use all TPA data
    let exhort_normalized = normalize_exhort_data(exhort_data);

    let mut all_records: HashSet<(String, String)> = HashSet::new();

    for (purl, cves) in &tpa_normalized {
        for cve in cves.keys() {
            all_records.insert((purl.clone(), cve.clone()));
        }
    }

    for (purl, cves) in &exhort_normalized {
        for cve in cves.keys() {
            all_records.insert((purl.clone(), cve.clone()));
        }
    }

    let mut comparison_records = Vec::new();

    for (purl, cve_id) in &all_records {
        let tpa_entry = tpa_normalized
            .get(purl)
            .and_then(|cves| cves.get(cve_id));

        let exhort_entry = exhort_normalized
            .get(purl)
            .and_then(|cves| cves.get(cve_id));

        let in_tpa = tpa_entry.is_some();
        let in_exhort = exhort_entry.is_some();

        let mut missing_in = Vec::new();
        if !in_tpa {
            missing_in.push("TPA");
        }
        if !in_exhort {
            missing_in.push("Exhort");
        }

        if !missing_in.is_empty() {
            comparison_records.push(TpaExhortComparisonRecord {
                purl: purl.clone(),
                cve_id: cve_id.clone(),
                tpa_cvss: tpa_entry.cloned().unwrap_or_default(),
                exhort_cvss: exhort_entry.cloned().unwrap_or_default(),
                missing_in: missing_in.join(", "),
            });
        }
    }

    write_tpa_exhort_csv(
        "test_results/comparison/comparison_tpa_vs_exhort.csv",
        &comparison_records,
    )?;

    info!("TPA vs Exhort comparison complete!");
    Ok(())
}

pub async fn compare_sources(
    osv_data: Vec<OSVHeader>,
    tpa_data: Vec<TPAHeaders>,
    exhort_data: Vec<ExhortRecord>,
) -> Result<(), Box<dyn Error>> {
    compare_osv_vs_tpa(&osv_data, &tpa_data)?;
    compare_tpa_vs_exhort(&tpa_data, &exhort_data)?;
    info!("All comparisons complete! Generated CSV files.");
    Ok(())
}

fn write_osv_tpa_csv(filename: &str, records: &[OsvTpaComparisonRecord]) -> Result<(), Box<dyn Error>> {
    let mut wtr = Writer::from_path(filename)?;

    for record in records {
        wtr.serialize(record)?;
    }

    wtr.flush()?;
    Ok(())
}

fn write_tpa_exhort_csv(filename: &str, records: &[TpaExhortComparisonRecord]) -> Result<(), Box<dyn Error>> {
    let mut wtr = Writer::from_path(filename)?;

    for record in records {
        wtr.serialize(record)?;
    }

    wtr.flush()?;
    Ok(())
}
