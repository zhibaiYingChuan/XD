use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

static PROXY_RUNNING: AtomicBool = AtomicBool::new(false);

const LLM_DOMAINS: &[&str] = &[
    "api.openai.com",
    "openai.com",
    "api.anthropic.com",
    "anthropic.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
];

pub async fn start_proxy(app: AppHandle, port: u16) -> Result<(), String> {
    if PROXY_RUNNING.load(Ordering::SeqCst) {
        return Err("Proxy already running".to_string());
    }

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| format!("Failed to bind proxy port: {}", e))?;

    PROXY_RUNNING.store(true, Ordering::SeqCst);
    eprintln!("[XuanDun] Proxy started on 127.0.0.1:{}", port);

    tokio::spawn(async move {
        while PROXY_RUNNING.load(Ordering::SeqCst) {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let app = app.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_proxy_connection(stream, &app).await {
                                    eprintln!("[XuanDun] Proxy connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => eprintln!("[XuanDun] Proxy accept error: {}", e),
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }
    });

    Ok(())
}

pub fn stop_proxy() -> Result<(), String> {
    PROXY_RUNNING.store(false, Ordering::SeqCst);
    eprintln!("[XuanDun] Proxy stopped");
    Ok(())
}

pub fn is_proxy_running() -> bool {
    PROXY_RUNNING.load(Ordering::SeqCst)
}

async fn handle_proxy_connection(
    mut client: tokio::net::TcpStream,
    app: &AppHandle,
) -> Result<(), String> {
    let mut buf = vec![0u8; 65536];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read(&mut buf),
    )
    .await
    .map_err(|e| format!("Read timeout: {}", e))?
    .map_err(|e| format!("Read error: {}", e))?;

    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = request_str.lines().next().unwrap_or("");

    if first_line.starts_with("CONNECT ") {
        handle_connect_tunnel(client, first_line, &buf[..n]).await
    } else {
        handle_http_request(client, &request_str, &buf[..n], app).await
    }
}

async fn handle_connect_tunnel(
    mut client: tokio::net::TcpStream,
    first_line: &str,
    _raw: &[u8],
) -> Result<(), String> {
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid CONNECT request".to_string());
    }

    let host_port = parts[1];
    let (host, port) = if host_port.contains(':') {
        let hp: Vec<&str> = host_port.split(':').collect();
        (hp[0].to_string(), hp[1].parse::<u16>().unwrap_or(443))
    } else {
        (host_port.to_string(), 443)
    };

    let mut server = tokio::net::TcpStream::connect(format!("{}:{}", host, port))
        .await
        .map_err(|e| format!("Connect to {}:{} failed: {}", host, port, e))?;

    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    client.write_all(response.as_bytes()).await.map_err(|e| e.to_string())?;

    let (mut cr, mut cw) = client.split();
    let (mut sr, mut sw) = server.split();

    let client_to_server = tokio::io::copy(&mut cr, &mut sw);
    let server_to_client = tokio::io::copy(&mut sr, &mut cw);

    let _ = tokio::try_join!(client_to_server, server_to_client);
    Ok(())
}

async fn handle_http_request(
    mut client: tokio::net::TcpStream,
    request_str: &str,
    _raw: &[u8],
    app: &AppHandle,
) -> Result<(), String> {
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Invalid HTTP request".to_string());
    }

    let method = parts[0];
    let url = parts[1];

    let parsed_url = url.parse::<url::Url>().map_err(|e| format!("Invalid URL: {}", e))?;
    let host = parsed_url.host_str().unwrap_or("");
    let port = parsed_url.port_or_known_default().unwrap_or(80);
    let path = if parsed_url.path().is_empty() { "/" } else { parsed_url.path() };

    let is_llm_request = LLM_DOMAINS.iter().any(|d| host == *d || host.ends_with(&format!(".{}", d)));

    if is_llm_request && method == "POST" {
        if let Some(body_start) = request_str.find("\r\n\r\n") {
            let body = &request_str[body_start + 4..];
            if let Some(prompt_text) = extract_prompt_from_body(body) {
                let engine_url = {
                    let state = app.state::<std::sync::Mutex<crate::engine::EngineState>>();
                    let s = state.lock().map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
                    s.get_engine_url()
                };

                let result = crate::engine::send_protect_request(&engine_url, &prompt_text, "proxy", "balanced").await;
                if let Ok(r) = result {
                    if !r.allowed {
                        eprintln!("[XuanDun] Proxy blocked request to {}: trust_level={}", host, r.trust_level);
                        let response = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{{\"error\":\"Blocked by XuanDun\",\"trust_level\":\"{}\"}}",
                            r.trust_level
                        );
                        client.write_all(response.as_bytes()).await.map_err(|e| e.to_string())?;

                        let _ = app.notification()
                            .builder()
                            .title("道体·玄盾 - 攻击拦截")
                            .body(&format!("拦截发往 {} 的恶意请求，信任等级: {}", host, r.trust_level))
                            .show();
                        return Ok(());
                    }
                }
            }
        }
    }

    let mut server = tokio::net::TcpStream::connect(format!("{}:{}", host, port))
        .await
        .map_err(|e| format!("Connect to {}:{} failed: {}", host, port, e))?;

    let rewritten_request = rewrite_request(request_str, host, path);
    server.write_all(rewritten_request.as_bytes()).await.map_err(|e| e.to_string())?;

    let mut response_buf = vec![0u8; 65536];
    let mut total_written = 0usize;
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            server.read(&mut response_buf),
        )
        .await;

        match n {
            Ok(Ok(0)) => break,
            Ok(Ok(bytes_read)) => {
                client.write_all(&response_buf[..bytes_read]).await.map_err(|e| e.to_string())?;
                total_written += bytes_read;
            }
            Ok(Err(e)) => {
                eprintln!("[XuanDun] Proxy read error: {}", e);
                break;
            }
            Err(_) => {
                eprintln!("[XuanDun] Proxy read timeout");
                break;
            }
        }

        if total_written > 10 * 1024 * 1024 {
            break;
        }
    }

    Ok(())
}

fn rewrite_request(request_str: &str, host: &str, path: &str) -> String {
    let mut lines = request_str.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return request_str.to_string();
    }

    let method = parts[0];
    let version = parts[2];
    let mut result = format!("{} {} {}\r\n", method, path, version);

    for line in lines {
        if line.is_empty() {
            result.push_str("\r\n");
            break;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            result.push_str(&format!("Host: {}\r\n", host));
        } else if lower.starts_with("proxy-") {
            continue;
        } else {
            result.push_str(&format!("{}\r\n", line));
        }
    }

    let body_start = request_str.find("\r\n\r\n");
    if let Some(idx) = body_start {
        let body = &request_str[idx + 4..];
        if !body.is_empty() {
            result.push_str(body);
        }
    }

    result
}

fn extract_prompt_from_body(body: &str) -> Option<String> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(prompt) = json.get("prompt").and_then(|v| v.as_str()) {
            return Some(prompt.to_string());
        }
        if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
            let last_msg = messages.last()?;
            return last_msg.get("content").and_then(|v| v.as_str()).map(|s| s.to_string());
        }
        if let Some(content) = json.get("content").and_then(|v| v.as_str()) {
            return Some(content.to_string());
        }
    }
    None
}
