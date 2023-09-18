use exhort_validator::{pom_synk_response, exhort_response};

#[tokio::main]
async fn main(){
    let snyk_token = "<token-here>";
    println!("--------------------------------------------------------------------------------------------------------");
    println!("{:?}",pom_synk_response(snyk_token).await);
    println!("--------------------------------------------------------------------------------------------------------");
    println!("{:?}",exhort_response(snyk_token).await);
    println!("--------------------------------------------------------------------------------------------------------");
}

