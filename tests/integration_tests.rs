use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient};
use recipe_viewer::create_app;
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
}
