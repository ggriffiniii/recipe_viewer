pub mod ai;
pub mod handlers;
pub mod models;
pub mod scraper;
pub mod search;
pub mod state;
pub mod templates;

use crate::state::AppState;
use crate::state::OAuthClient;
use axum::{
    Router,
    routing::{get, post},
};
use sqlx::SqlitePool;
use time::Duration;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;

pub async fn create_app(pool: SqlitePool, oauth_client: OAuthClient, test_mode: bool) -> Router {
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
        .route("/favicon.ico", get(handlers::favicon))
        .route("/favicon.svg", get(handlers::favicon))
        .route("/logout", get(handlers::logout));

    let app = if test_mode {
        app.route("/test/set_session", get(test_handlers::set_test_session))
            .layer(axum::middleware::from_fn(test_handlers::mock_auth_layer))
    } else {
        app
    };

    app.layer(session_layer).with_state(state)
}

mod test_handlers {
    use crate::handlers::SessionUser;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware::Next;
    use axum::response::Response;
    use tower_sessions::Session;

    pub async fn mock_auth_layer(session: Session, request: Request<Body>, next: Next) -> Response {
        if let Some(email) = request.headers().get("x-test-user") {
            let email_str = email.to_str().unwrap_or("test@example.com").to_string();
            session
                .insert("user", SessionUser { email: email_str })
                .await
                .unwrap();
        }
        next.run(request).await
    }

    use axum::response::IntoResponse;
    pub async fn set_test_session(session: Session) -> impl IntoResponse {
        session
            .insert(
                "user",
                SessionUser {
                    email: "test@example.com".to_string(),
                },
            )
            .await
            .unwrap();
        "Session set"
    }
}
