use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use ipnetwork::IpNetwork;
use serde_json::json;
use std::collections::HashMap;

async fn handle_request(
    req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    if let Some(ip) = query.get("ip") {
        if !ip.is_empty() {
            return redirect_to_ip(ip, &req);
        }
    }

    let ip = req.uri().path().replace("/ip/", "");
    if ip.is_empty() {
        return handle_empty_ip(&req);
    }

    if ip.parse::<IpNetwork>().is_err() {
        return invalid_query_response(&ip);
    }

    match fetch_ip_data(&ip).await {
        Ok(ipapi) => HttpResponse::Ok().json(ipapi),
        Err(err) => HttpResponse::InternalServerError().json(json!({"error": err})),
    }
}

fn redirect_to_ip(ip: &str, req: &HttpRequest) -> HttpResponse {
    let host = req.connection_info().host().to_string();
    HttpResponse::Found()
        .append_header(("Location", format!("https://{}/ip/{}", host, ip)))
        .finish()
}

fn handle_empty_ip(req: &HttpRequest) -> HttpResponse {
    if let Some(user_agent) = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
    {
        if user_agent.contains("bot")
            || user_agent.contains("Bot")
            || user_agent.contains("compatible;")
        {
            let host = req.connection_info().host().to_string();
            return HttpResponse::Ok()
                .content_type("text/html; charset=UTF-8")
                .body(format!("<h1>An IP API that provides general data about ip addresses, such as location or internet provider, and identifies nordvpn users.</h1><p>To use the api keep the following url format: https://{}/ip/[ip]<br><br>For example: <a target='_blank' href='https://{}/ip/1.1.1.1'>https://{}/ip/1.1.1.1</a></p>", host, host, host));
        } else if let Some(cf_ip) = req
            .headers()
            .get("HTTP_CF_CONNECTING_IP")
            .and_then(|ip| ip.to_str().ok())
        {
            return redirect_to_ip(cf_ip, req);
        } else if let Some(user_ip) = req.peer_addr().map(|addr| addr.ip().to_string()) {
            return redirect_to_ip(&user_ip, req);
        }
    }
    invalid_query_response("")
}

fn invalid_query_response(ip: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "status": "fail",
        "message": "invalid query",
        "query": ip
    }))
}

async fn fetch_ip_data(ip: &str) -> Result<serde_json::Value, String> {
    let nord_url = format!(
        "https://nordvpn.com/wp-admin/admin-ajax.php?action=get_user_info_data&ip={}",
        ip
    );
    let ipapi_url = format!("http://ip-api.com/json/{}?fields=66846719&lang=en", ip);

    let nord_resp = reqwest::get(&nord_url)
        .await
        .map_err(|_| "Failed to fetch NordVPN data")?;
    let nord_text = nord_resp
        .text()
        .await
        .map_err(|_| "Failed to read NordVPN response")?;
    let nord: serde_json::Value =
        serde_json::from_str(&nord_text).map_err(|_| "Failed to parse NordVPN response")?;

    let ipapi_resp = reqwest::get(&ipapi_url)
        .await
        .map_err(|_| "Failed to fetch IP-API data")?;
    let ipapi_text = ipapi_resp
        .text()
        .await
        .map_err(|_| "Failed to read IP-API response")?;
    let mut ipapi: serde_json::Value =
        serde_json::from_str(&ipapi_text).map_err(|_| "Failed to parse IP-API response")?;

    if let Some(domain) = nord["host"]["domain"].as_str() {
        ipapi["host_domain"] = json!(domain);
    }
    if let Some(lat) = nord["coordinates"]["latitude"].as_f64() {
        ipapi["lat"] = json!(lat);
    }
    if let Some(lon) = nord["coordinates"]["longitude"].as_f64() {
        ipapi["lon"] = json!(lon);
    }
    if let Some(status) = nord["status"].as_bool() {
        ipapi["nordvpn_connected"] = json!(status);
    }
    ipapi["sources"] = json!(["http://ip-api.com", "https://nordvpn.com"]);

    Ok(ipapi)
}

async fn not_found() -> impl Responder {
    HttpResponse::NotFound().json(json!({
        "status": "fail",
        "message": "invalid query",
        "query": ""
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/ip/{ip}", web::get().to(handle_request))
            .route("/ip/", web::get().to(handle_request))
            .default_service(web::route().to(not_found))
    })
    .bind("127.0.0.1:19666")?
    .run()
    .await
}
