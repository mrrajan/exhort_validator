use exhort_validator::{run_command, string_slicer};
use reqwest;
use serde_derive::{Serialize, Deserialize};
use serde_json::{Value, to_string_pretty, Map};
use std::fs::OpenOptions;
use std::io::Write;
use xmltojson::to_json;

#[derive(Serialize,Deserialize, Debug)]
pub struct ApiResponse{
    ok: bool,
    issues: Issues

}

#[derive(Serialize,Deserialize, Debug)]
pub struct Issues{
    vulnerabilities: Vec<Vulns>
}

#[derive(Serialize,Deserialize, Debug)]
pub struct Vulns{
    id: String,
    url: String,
    title: String,
    from: Vec<String>,
    severity: String,
    cvssScore: f64,
    exploitMaturity: String,
    identifiers: CVE
}

#[derive(Serialize,Deserialize, Debug)]
pub struct CVE{
    CVE: Option<Vec<String>>
}

pub fn retrieve_snyk_endpoints(input: serde_json::Value)-> Vec<String>{
    let mut end_points = Vec::new();
    for k in input["dependencies"]["dependency"].as_array().unwrap(){
        end_points.push(format!("/{}/{}@{}",k["groupId"].as_str().unwrap(),k["artifactId"].as_str().unwrap(),k["version"].as_str().unwrap()));
    }
    end_points
}

pub async fn get_snyk_response(endpoint: &str, snyk_token: &str )->ApiResponse{
    let url = format!("https://api.snyk.io/v1/test/maven{}",endpoint.replace("@", "/"));
    let response =reqwest::Client::new()
        .get(url.to_owned())
        .header("Authorization",snyk_token)
        .send()
        .await
        .expect("API Request failed")
        .text().await.expect("Text Parse failed");
    let parsed_data: ApiResponse = serde_json::from_str(&response).expect("JSON to string parse failed");
    parsed_data
}

pub async fn pom_synk_response(snyk_token: &str)-> serde_json::Map<std::string::String, Value>{
    let mut snyk_response: Map<String, Value> = Map::new();
    let command = "mvn";
    let args = &["help:effective-pom"];
    let output = run_command(command, args);
    let stdout_str = String::from_utf8(output).expect("Failed to convert to String");
    let mut start = "<dependencyManagement>";
    let mut end = "</dependencyManagement>";
    let mut updated_str = string_slicer(stdout_str, start, end, true);
    start = "<dependencies>";
    end = "</dependencies>";
    updated_str = string_slicer(updated_str, start, end, false);
    let dependency_json: serde_json::Value = to_json(&updated_str).expect("Failed to convert pom xml to json");
    let end_points = retrieve_snyk_endpoints(dependency_json);
    for ep in end_points{
        snyk_response.insert(ep.to_string(),serde_json::to_value(get_snyk_response(&ep, snyk_token).await).expect("error"));
    }
    let mut file = OpenOptions::new().write(true).create(true)
    .append(true)
    .open("temp.json").expect("File creation failed");
    let json_str = to_string_pretty(&snyk_response).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    snyk_response
}
