use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient};
use recipe_viewer::create_app;
use serde_json::Value;
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;

async fn setup_test_app() -> axum::Router {
    let db_path = std::env::temp_dir().join(format!("recipe_test_{}.db", rand::random::<u32>()));

    let db_opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .with_regexp();

    let pool = SqlitePoolOptions::new()
        .connect_with(db_opts)
        .await
        .expect("Failed to connect to test database");

    sqlx::migrate!().run(&pool).await.unwrap();

    let oauth_client = BasicClient::new(ClientId::new("test-id".to_string()))
        .set_client_secret(ClientSecret::new("test-secret".to_string()))
        .set_auth_uri(
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
        )
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap())
        .set_redirect_uri(RedirectUrl::new("http://localhost/callback".to_string()).unwrap());

    create_app(pool, oauth_client, true).await
}

#[tokio::test]
async fn test_homepage() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_search() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/?q=pizza")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_new_recipe_form_prefill() {
    let app = setup_test_app().await;

    // Access form with x-test-user header
    let response = app
        .oneshot(
            Request::builder()
                .uri("/recipes/new?url=https://example.com/pizza")
                .header("x-test-user", "test@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("https://example.com/pizza"));
    assert!(body_str.contains("id=\"bookmarklet-link\""));
    assert!(body_str.contains("Recipe Importer Bookmarklet"));
}

#[tokio::test]
async fn test_import_recipe_streaming() {
    // This test actually calls the scraper + AI, so it requires dependencies.
    // We'll use a simple URL to check the protocol steps.
    let app = setup_test_app().await;

    let payload = serde_json::json!({
        "url": "https://example.com"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recipes/import")
                .header("Content-Type", "application/json")
                .header("x-test-user", "test@example.com")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    // Parse NDJSON
    let lines: Vec<&str> = body_str.trim().split('\n').collect();
    println!("DEBUG received lines: {:?}", lines);

    // 1. First message should always be "Fetching"
    let msg1: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(msg1["status"], "info");
    assert!(
        msg1["message"]
            .as_str()
            .unwrap()
            .contains("Fetching content")
    );

    if lines.len() == 2 {
        // Case: Failed early (e.g. Missing API Key or Scraping Failed)
        let msg2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(msg2["status"], "error");
        // Verify it's a valid JSON structure we expect
    } else if lines.len() >= 3 {
        // Case: Scraping succeeded, attempted extraction

        // 2. Extracting
        let msg2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(msg2["status"], "info");
        assert!(
            msg2["message"]
                .as_str()
                .unwrap()
                .contains("Extracting recipe information")
        );
        // Check for model name presence if extraction started
        assert!(msg2["message"].as_str().unwrap().contains("gemini"));

        // 3. Complete or Error
        let msg3: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert!(msg3["status"] == "complete" || msg3["status"] == "error");
    } else {
        panic!("Unexpected number of lines: {}", lines.len());
    }
}

#[tokio::test]
async fn test_ingredient_search() {
    let app = setup_test_app().await;

    // 1. Create a recipe with specific ingredients
    let payload = serde_json::json!({
        "title": "Garlic Pasta",
        "instructions": "Cook pasta, add garlic.",
        "ingredients": [
            { "name": "Garlic", "quantity": "2", "unit": "cloves" },
            { "name": "Pasta", "quantity": "1", "unit": "lb" }
        ],
        "tags": []
    });

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recipes")
                .header("Content-Type", "application/json")
                .header("x-test-user", "test@example.com")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 2. Search for "Garlic" (Match)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/?q=ingredient:garlic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body_str.contains("Garlic Pasta"),
        "Should find recipe with ingredient 'Garlic'"
    );

    // 3. Search for "Onion" (No Match)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/?q=ingredient:onion")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("Garlic Pasta"),
        "Should NOT find recipe with ingredient 'Onion'"
    );

    // 4. Regex Search "G.*c" (Match)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/?q=ingredient:g.*c")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body_str.contains("Garlic Pasta"),
        "Should find recipe with ingredient regex 'g.*c'"
    );
}

#[tokio::test]
async fn test_multi_tag_search() {
    let app = setup_test_app().await;

    // 1. Create two recipes with different tags
    let payload1 = serde_json::json!({
        "title": "Spicy Taco",
        "instructions": "Make tacos.",
        "ingredients": [],
        "tags": ["mexican", "spicy"]
    });
    let payload2 = serde_json::json!({
        "title": "Mild Burrito",
        "instructions": "Make burritos.",
        "ingredients": [],
        "tags": ["mexican", "mild"]
    });

    for p in &[payload1, payload2] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/recipes")
                    .header("Content-Type", "application/json")
                    .header("x-test-user", "test@example.com")
                    .body(Body::from(p.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // 2. Search for one tag
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/?q=tag:spicy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_str = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body_str.contains("Spicy Taco"));
    assert!(!body_str.contains("Mild Burrito"));

    // 3. Search for OR'd tags
    // The handler expects "?q=tag:spicy OR tag:mild"
    let q = urlencoding::encode("tag:spicy OR tag:mild");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&format!("/?q={}", q))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_str = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body_str.contains("Spicy Taco"));
    assert!(body_str.contains("Mild Burrito"));
}

#[tokio::test]
async fn test_live_search() {
    let app = setup_test_app().await;

    // Search with HTMX headers
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/?q=taco")
                .header("HX-Request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_str = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Verify that the response contains the expected HTMX targets
    assert!(body_str.contains("id=\"search-results\""));
    assert!(body_str.contains("id=\"header-search-wrapper\""));
    assert!(body_str.contains("hx-swap-oob=\"true\""));
}

#[tokio::test]
async fn test_tag_exact_match() {
    let app = setup_test_app().await;

    // 1. Create recipes with overlapping tag names
    let payload1 = serde_json::json!({
        "title": "Spicy Dish",
        "instructions": "...",
        "ingredients": [],
        "tags": ["spicy"]
    });
    let payload2 = serde_json::json!({
        "title": "Extra Spicy Dish",
        "instructions": "...",
        "ingredients": [],
        "tags": ["spicier"]
    });

    for p in &[payload1, payload2] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/recipes")
                    .header("Content-Type", "application/json")
                    .header("x-test-user", "test@example.com")
                    .body(Body::from(p.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // 2. Search for "tag:spicy"
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/?q=tag:spicy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_str = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // 3. Verify ONLY "Spicy Dish" matches, NOT "Extra Spicy Dish"
    assert!(body_str.contains("Spicy Dish"));
    assert!(!body_str.contains("Extra Spicy Dish"));
}

#[tokio::test]
async fn test_tag_with_spaces() {
    let app = setup_test_app().await;

    // 1. Create a recipe with a tag containing a space
    let payload = serde_json::json!({
        "title": "Thin Crust Pizza",
        "instructions": "...",
        "ingredients": [],
        "tags": ["thin crust"]
    });

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recipes")
                .header("Content-Type", "application/json")
                .header("x-test-user", "test@example.com")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 2. Search for the tag with quotes (exact match)
    // The handler should normalize this and also return it in active_tags
    let q = urlencoding::encode("tag:\"thin crust\"");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&format!("/?q={}", q))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_str = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    assert!(body_str.contains("Thin Crust Pizza"));

    // 3. Verify highlighting (the badge should have the indigo-600 class)
    // and the toggle link should be correct (removing the tag)
    assert!(body_str.contains("bg-indigo-600 text-white"));
    assert!(body_str.contains("thin crust"));
}

#[tokio::test]
async fn test_auth_required_redirect() {
    let app = setup_test_app().await;

    // 1. Attempt to access a protected page with a query parameter
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/recipes/new?url=http://foo.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_str = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // 2. Verify we see the "Authentication Required" page
    assert!(body_str.contains("Authentication Required"));
    assert!(body_str.contains("Sign in with Google"));

    // 3. Verify the link includes the 'next' parameter correctly including query
    // Askama urlencode filter: encodes ?, =, : but not /
    assert!(body_str.contains("next=/recipes/new%3Furl%3Dhttp%3A//foo.com"));
}

#[tokio::test]
async fn test_print_view() {
    let app = setup_test_app().await;

    // 1. Create a recipe
    let payload = serde_json::json!({
        "title": "Printable Recipe",
        "instructions": "Step 1. Print it.",
        "ingredients": [
            { "name": "Paper", "quantity": "1", "unit": "sheet" }
        ],
        "tags": []
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recipes")
                .header("Content-Type", "application/json")
                .header("x-test-user", "test@example.com")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get the ID from the location header or just assume it's 1 since it's a fresh DB
    let location = create_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    // location is like /recipes/1
    let recipe_id = location.split('/').last().unwrap();

    // 2. Request print view
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&format!("/recipes/{}/print", recipe_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    // 3. Verify content
    assert!(body_str.contains("Printable Recipe"));
    assert!(body_str.contains("Print View")); // Title tag
    assert!(body_str.contains("Paper"));
    assert!(body_str.contains("Step 1. Print it."));
    // Ensure minimal branding (no nav)
    assert!(!body_str.contains("<nav"));
}
