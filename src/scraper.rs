use fantoccini::{ClientBuilder, Locator};
use serde_json::Value;
use std::net::TcpListener;
use std::process::{Child, Command};

pub struct ChromeDriver {
    process: Child,
}

impl ChromeDriver {
    pub async fn start(port: u16) -> Result<Self, String> {
        let cmd = std::env::var("CHROMEDRIVER_PATH").unwrap_or_else(|_| "chromedriver".to_string());
        let process = Command::new(cmd)
            .arg(format!("--port={}", port))
            .arg("--whitelisted-ips=")
            .spawn()
            .map_err(|e| format!("Failed to spawn chromedriver: {}", e))?;

        // Poll for port availability
        let mut started = false;
        for _ in 0..20 {
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .is_ok()
            {
                started = true;
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        if !started {
            return Err("Timed out waiting for ChromeDriver to start".to_string());
        }

        Ok(Self { process })
    }
}

impl Drop for ChromeDriver {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn find_available_port() -> Result<u16, String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("Failed to bind to port 0: {}", e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("Failed to get local addr: {}", e))?;
    Ok(addr.port())
}

pub async fn scrape_url(url: &str) -> Result<String, String> {
    // 1. Find port
    let port = find_available_port()?;
    // println!("Starting ChromeDriver on port {}", port);

    // 2. Start ChromeDriver
    let _driver_guard = ChromeDriver::start(port).await?;

    // 3. Connect Fantoccini
    let mut caps = serde_json::map::Map::new();
    let chrome_opts = serde_json::json!({
        "args": ["--headless", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage", "--disable-software-rasterizer", "--window-size=1920,1080"]
    });
    caps.insert("goog:chromeOptions".to_string(), chrome_opts);

    let mut client = None;
    for i in 0..10 {
        match ClientBuilder::native()
            .capabilities(caps.clone())
            .connect(&format!("http://localhost:{}", port))
            .await
        {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if i == 9 {
                    return Err("Failed to connect to chromedriver after retries".to_string());
                }
            }
        }
    }
    let client = client.ok_or("Failed to connect to ChromeDriver".to_string())?;

    // 4. Navigate
    client.goto(url).await.map_err(|e| e.to_string())?;

    // Wait for content
    let _ = client
        .execute("return document.readyState", vec![])
        .await
        .map_err(|e| e.to_string())?;

    // Check for 'complete'
    for _ in 0..10 {
        if let Ok(Value::String(state)) = client.execute("return document.readyState", vec![]).await
        {
            if state == "complete" {
                break;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Short buffer
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // 5. Extract Text
    let mut text = String::new();

    // Main Body
    if let Ok(body) = client.find(Locator::Css("body")).await {
        if let Ok(t) = body.text().await {
            text.push_str(&t);
        }
    }

    // Iframes
    if let Ok(iframes) = client.find_all(Locator::Css("iframe")).await {
        for (i, _frame) in iframes.iter().enumerate() {
            text.push_str(&format!("\n\n--- IFrame {} ---\n", i));
            if let Ok(_) = client.enter_frame(Some(i as u16)).await {
                if let Ok(body) = client.find(Locator::Css("body")).await {
                    if let Ok(t) = body.text().await {
                        text.push_str(&t);
                    }
                }
                let _ = client.enter_parent_frame().await;
            }
        }
    }

    // Explicitly close
    let _ = client.close().await;

    Ok(text)
}
