use std::{process::Command, fs::File, io::Write, fs};
use reqwest::{Response, Error, dns::Resolving};
use serde_derive::{Serialize, Deserialize};
use serde_json::Value;
use xmltojson::to_json;

#[derive(Serialize,Deserialize, Debug)]
struct ApiResponse{
    ok: bool,
    issues: Issues

}

#[derive(Serialize,Deserialize, Debug)]
struct Issues{
    vulnerabilities: Vec<Vulns>
}

#[derive(Serialize,Deserialize, Debug)]
struct Vulns{
    id: String,
    url: String,
    title: String,
    from: Vec<String>,
    severity: String,
    cvssScore: f64,
    exploitMaturity: String,
    identifiers: Vec<CVE>
}

#[derive(Serialize,Deserialize, Debug)]
struct CVE{
    CVE: Vec<String>
}


pub fn run_command(command: &str, args: &[&str]) -> std::process::Output {
    Command::new(&command)
        .args(args)
        .output()
        .expect("Failed to execute the command")
}

pub fn string_slicer(input:String, start:&str, end: &str, exclude: bool)-> String{
    let start_pos = input.find(start).expect("Start position not found");
    let end_pos = input.find(end).expect("End position not found");
    if exclude{
        let before = &input[..start_pos];
        let after = &input[end_pos + end.len()..]; 
        before.to_string()+after
    }else{
        input[start_pos..end_pos+end.len()].to_string()
    }
}

pub async fn get_pom_dependency_json(){
    let command = "mvn";
    let args = &["help:effective-pom"];
    let output = run_command(command, args);
    if output.status.success() {
        let stdout_str = String::from_utf8(output.stdout).expect("Failed to parse stdout");
        let mut start = "<dependencyManagement>";
        let mut end = "</dependencyManagement>";
        let mut updated_str = string_slicer(stdout_str, start, end, true);
        start = "<dependencies>";
        end = "</dependencies>";
        updated_str = string_slicer(updated_str, start, end, false);
        let dependency_json: serde_json::Value = to_json(&updated_str).expect("error");
        let end_points = retrieve_snyk_endpoints(dependency_json);
        for ep in end_points{
            get_snyk_response(&ep).await;
        }
        
    } else {
        let stderr_str = String::from_utf8(output.stderr).expect("Failed to parse stderr");
        eprintln!("Command failed:\n{}", stderr_str);
    }
}

pub fn retrieve_snyk_endpoints(input: serde_json::Value)-> Vec<String>{
    let mut end_points = Vec::new();
    for k in input["dependencies"]["dependency"].as_array().unwrap(){
        end_points.push(format!("/{}/{}/{}",k["groupId"].as_str().unwrap(),k["artifactId"].as_str().unwrap(),k["version"].as_str().unwrap()));
    }
    end_points
}

pub async fn get_snyk_response(endpoint: &str){
    let url = format!("https://api.snyk.io/v1/test/maven{}",endpoint);
    let response = reqwest::Client::new()
        .get(url.to_owned())
        .header("Authorization", "<token>")
        .send()
        .await
        .expect("msg")
        .text().await.expect("msg");
    let parsed_data: ApiResponse = serde_json::from_str(&response).expect("msg");
    println!("{:?}",parsed_data);
}
