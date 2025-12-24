use fantoccini::{ClientBuilder, Locator};
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient};
use recipe_viewer::create_app;
use sqlx::sqlite::SqlitePoolOptions;
use std::process::{Child, Command};
use std::time::Duration;
use tokio::task::JoinHandle;

struct ChromeDriver {
    process: Child,
}

impl ChromeDriver {
    async fn start(port: u16) -> Result<Self, String> {
        let cmd = std::env::var("CHROMEDRIVER_PATH").unwrap_or_else(|_| "chromedriver".to_string());
        let process = Command::new(cmd)
            .arg(format!("--port={}", port))
            .arg("--whitelisted-ips=")
            .spawn()
            .map_err(|e| format!("Failed to spawn chromedriver: {}", e))?;
        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(1500)).await;
        Ok(Self { process })
    }
}

impl Drop for ChromeDriver {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

async fn find_available_port() -> u16 {
    tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TestContext {
    app_port: u16,
    _app_handle: JoinHandle<()>,
    _driver_guard: ChromeDriver,
    client: fantoccini::Client,
    db_path: std::path::PathBuf,
}

impl TestContext {
    async fn setup() -> Self {
        let app_port = find_available_port().await;
        let driver_port = find_available_port().await;

        // Database setup
        let db_path =
            std::env::temp_dir().join(format!("recipe_ui_test_{}.db", rand::random::<u32>()));
        let db_opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .with_regexp();

        let pool = SqlitePoolOptions::new()
            .connect_with(db_opts)
            .await
            .expect("Failed to connect to test database");

        sqlx::migrate!().run(&pool).await.unwrap();

        // App setup
        let oauth_client = BasicClient::new(ClientId::new("test-id".to_string()))
            .set_client_secret(ClientSecret::new("test-secret".to_string()))
            .set_auth_uri(
                AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            )
            .set_token_uri(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap(),
            )
            .set_redirect_uri(RedirectUrl::new("http://localhost/callback".to_string()).unwrap());

        let app = create_app(pool, oauth_client, true).await;
        let addr = format!("127.0.0.1:{}", app_port);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

        let _app_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // ChromeDriver setup
        let _driver_guard = ChromeDriver::start(driver_port)
            .await
            .expect("Failed to start ChromeDriver");

        // Fantoccini setup
        let mut caps = serde_json::map::Map::new();
        let chrome_opts = serde_json::json!({
            "args": ["--headless", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage", "--window-size=1920,1080"]
        });
        caps.insert("goog:chromeOptions".to_string(), chrome_opts);

        let mut client = None;
        for i in 0..10 {
            match ClientBuilder::native()
                .capabilities(caps.clone())
                .connect(&format!("http://localhost:{}", driver_port))
                .await
            {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(e) => {
                    if i == 9 {
                        panic!("Failed to connect to ChromeDriver after 10 attempts: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        let client = client.unwrap();

        Self {
            app_port,
            _app_handle,
            _driver_guard,
            client,
            db_path,
        }
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db_path);
    }
}

#[tokio::test]
async fn test_ui_homepage_and_navigation() {
    let ctx = TestContext::setup().await;
    let url = format!("http://localhost:{}", ctx.app_port);

    ctx.client.goto(&url).await.unwrap();

    // Check title
    let navbar_brand = ctx
        .client
        .find(Locator::Css("a.text-xl.font-bold"))
        .await
        .unwrap();
    assert!(navbar_brand.text().await.unwrap().contains("Recipe Viewer"));

    // Navigate to New Recipe (should redirect to / if not authed)
    ctx.client
        .goto(&format!("{}/recipes/new", url))
        .await
        .unwrap();
    assert!(
        ctx.client
            .current_url()
            .await
            .unwrap()
            .as_ref()
            .ends_with("/")
    );

    // Login via test route
    ctx.client
        .goto(&format!("{}/test/set_session", url))
        .await
        .unwrap();
    assert!(ctx.client.source().await.unwrap().contains("Session set"));

    // Now navigate to New Recipe again
    ctx.client
        .goto(&format!("{}/recipes/new", url))
        .await
        .unwrap();
    assert!(
        ctx.client
            .current_url()
            .await
            .unwrap()
            .as_ref()
            .ends_with("/recipes/new")
    );

    let h1 = ctx.client.find(Locator::Css("h1")).await.unwrap();
    assert!(h1.text().await.unwrap().contains("New Recipe"));

    ctx.client.clone().close().await.unwrap();
}

#[tokio::test]
async fn test_ui_full_recipe_creation() {
    let ctx = TestContext::setup().await;
    let base_url = format!("http://localhost:{}", ctx.app_port);

    // 1. Login
    ctx.client
        .goto(&format!("{}/test/set_session", base_url))
        .await
        .unwrap();

    // 2. Go to New Recipe
    ctx.client
        .goto(&format!("{}/recipes/new", base_url))
        .await
        .unwrap();

    // 3. Fill Title
    let title = "UI Test Pasta";
    let title_input = ctx.client.find(Locator::Id("title")).await.unwrap();
    title_input.send_keys(title).await.unwrap();

    // 4. Fill Ingredients (The first row should already exist)
    // We'll just fill the first one for simplicity, or add one.
    let qty_input = ctx.client.find(Locator::Css(".ing-qty")).await.unwrap();
    qty_input.send_keys("200").await.unwrap();
    let unit_input = ctx.client.find(Locator::Css(".ing-unit")).await.unwrap();
    unit_input.send_keys("g").await.unwrap();
    let name_input = ctx.client.find(Locator::Css(".ing-name")).await.unwrap();
    name_input.send_keys("Spaghetti").await.unwrap();

    // Add another ingredient
    let add_btn = ctx
        .client
        .find(Locator::Id("add-ingredient-btn"))
        .await
        .unwrap();
    add_btn.click().await.unwrap();

    // Find all rows
    let rows = ctx
        .client
        .find_all(Locator::Css("#ingredients-container div.flex"))
        .await
        .unwrap();
    // Use the last one (index might be tricky if we don't know initial state exactly,
    // but we know we added one to the 6 initial ones if empty, or just fill the ones that exist).
    // Initial setup adds 6 empty rows.
    let row = &rows[1]; // Filling the second row
    row.find(Locator::Css(".ing-qty"))
        .await
        .unwrap()
        .send_keys("1")
        .await
        .unwrap();
    row.find(Locator::Css(".ing-unit"))
        .await
        .unwrap()
        .send_keys("cup")
        .await
        .unwrap();
    row.find(Locator::Css(".ing-name"))
        .await
        .unwrap()
        .send_keys("Tomato Sauce")
        .await
        .unwrap();

    // 5. Fill Instructions
    let instr_input = ctx.client.find(Locator::Id("instructions")).await.unwrap();
    instr_input
        .send_keys("Boil water.\nCook pasta.\nAdd sauce.")
        .await
        .unwrap();

    // 6. Add Tags
    let tag_input = ctx.client.find(Locator::Id("tag-input")).await.unwrap();
    tag_input.send_keys("dinner").await.unwrap();
    tag_input.send_keys("\n").await.unwrap(); // Enter to add

    // 7. Submit
    let submit_btn = ctx
        .client
        .find(Locator::Css("button[type='submit']"))
        .await
        .unwrap();
    submit_btn.click().await.unwrap();

    // 8. Verify redirection and content
    // We expect to be on /recipes/{id}
    tokio::time::sleep(Duration::from_millis(1000)).await; // Wait for redirect
    let current_url = ctx.client.current_url().await.unwrap();
    assert!(current_url.as_ref().contains("/recipes/"));

    let detail_h1 = ctx.client.find(Locator::Css("h1")).await.unwrap();
    assert_eq!(detail_h1.text().await.unwrap(), title);

    // 9. Verify Ingredients on detail page
    let ing_items = ctx
        .client
        .find_all(Locator::Css("ul.divide-y li"))
        .await
        .unwrap();
    assert_eq!(ing_items.len(), 2);

    let ing1_text = ing_items[0].text().await.unwrap();
    assert!(ing1_text.contains("200"));
    assert!(ing1_text.contains("g"));
    assert!(ing1_text.contains("Spaghetti"));

    let ing2_text = ing_items[1].text().await.unwrap();
    assert!(ing2_text.contains("1"));
    assert!(ing2_text.contains("cup"));
    assert!(ing2_text.contains("Tomato Sauce"));

    ctx.client.clone().close().await.unwrap();
}

#[tokio::test]
async fn test_ui_recipe_import_prefill() {
    let ctx = TestContext::setup().await;
    let base_url = format!("http://localhost:{}", ctx.app_port);

    // 1. Login
    ctx.client
        .goto(&format!("{}/test/set_session", base_url))
        .await
        .unwrap();

    // 2. Navigate with prefill
    let prefill_url = "https://example.com/test-recipe";
    ctx.client
        .goto(&format!("{}/recipes/new?url={}", base_url, prefill_url))
        .await
        .unwrap();

    // 3. Verify URL field
    let url_input = ctx.client.find(Locator::Id("url")).await.unwrap();
    assert_eq!(url_input.prop("value").await.unwrap().unwrap(), prefill_url);

    // 4. Verify Bookmarklet presence
    let bookmarklet = ctx
        .client
        .find(Locator::Id("bookmarklet-link"))
        .await
        .unwrap();
    let href = bookmarklet.attr("href").await.unwrap().unwrap();
    assert!(href.starts_with("javascript:"));
    assert!(href.contains("recipes/new?url="));

    ctx.client.clone().close().await.unwrap();
}
