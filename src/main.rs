mod ai;
mod handlers;
mod models;
mod search;
mod state;
mod templates;

use crate::state::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use dotenvy::dotenv;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient};
use sqlx::sqlite::SqlitePoolOptions;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use time::Duration;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:recipes.db".to_string());
    let google_client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID");
    let google_client_secret =
        env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET");
    let google_redirect_url = env::var("GOOGLE_REDIRECT_URL")
        .unwrap_or_else(|_| "http://localhost:3000/auth/callback".to_string());

    let db_opts = sqlx::sqlite::SqliteConnectOptions::from_str(&database_url)
        .expect("Failed to parse DATABASE_URL")
        .create_if_missing(true)
        .with_regexp(); // Enable REGEXP function

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(db_opts)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    sqlx::migrate!().run(&pool).await.unwrap();

    let oauth_client = BasicClient::new(ClientId::new(google_client_id))
        .set_client_secret(ClientSecret::new(google_client_secret))
        .set_auth_uri(
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .expect("Invalid authorization endpoint"),
        )
        .set_token_uri(
            TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                .expect("Invalid token endpoint"),
        )
        .set_redirect_uri(RedirectUrl::new(google_redirect_url).expect("Invalid redirect URL"));

    let session_store = SqliteStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .expect("Failed to run session migrations");

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // For local development
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::hours(24)));

    let state = AppState { pool, oauth_client };

    let app = Router::new()
        .route("/", get(handlers::list_recipes))
        .route("/recipes/new", get(handlers::create_recipe_form))
        .route("/recipes", post(handlers::create_recipe))
        .route("/recipes/import", post(handlers::import_recipe))
        .route(
            "/recipes/{id}",
            get(handlers::recipe_detail)
                .post(handlers::update_recipe)
                .delete(handlers::delete_recipe),
        )
        .route(
            "/recipes/{id}/versions/{version}",
            get(handlers::recipe_revision_detail),
        )
        .route("/recipes/{id}/tags", post(handlers::update_recipe_tags))
        .route("/recipes/{id}/ratings", post(handlers::update_rating))
        .route("/recipes/{id}/edit", get(handlers::edit_recipe_form))
        .route(
            "/recipes/{id}/restore/{version}",
            post(handlers::restore_recipe_revision),
        )
        .route(
            "/recipes/{id}/convert",
            get(handlers::convert_recipe_form).post(handlers::convert_recipe),
        )
        .route("/auth/google", get(handlers::google_auth))
        .route("/auth/callback", get(handlers::google_auth_callback))
        .route("/logout", get(handlers::logout))
        .layer(session_layer)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
