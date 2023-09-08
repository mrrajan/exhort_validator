use exhort_validator::get_pom_dependency_json;

#[tokio::main]
async fn main(){
    get_pom_dependency_json().await;
}

