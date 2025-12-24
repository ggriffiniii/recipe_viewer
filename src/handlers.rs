use crate::state::OAuthClient;
use axum::{
    extract::{Form, Json, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use oauth2::{AuthorizationCode, CsrfToken, Scope, TokenResponse};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

// Define a user struct for session
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionUser {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

use crate::templates::{
    HtmlTemplate, RecipeConvertTemplate, RecipeDetailTemplate, RecipeListTemplate, RecipeWithTags,
};
use sqlx::SqlitePool;

#[derive(sqlx::FromRow)]
struct TagWithRecipeId {
    #[sqlx(flatten)]
    tag: crate::models::Tag,
    recipe_id: i64,
}

#[derive(Deserialize)]
pub struct RecipeSearch {
    q: Option<String>,
}

use sqlx::{QueryBuilder, Sqlite};

pub async fn list_recipes(
    State(pool): State<SqlitePool>,
    Query(search): Query<RecipeSearch>,
    session: Session,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let mut query_builder: QueryBuilder<Sqlite> = QueryBuilder::new(
        r#"
        SELECT r.id, rev.id as revision_id, rev.revision_number, rev.title, rev.instructions, rev.url, rev.overview, r.created_at, rev.created_at as revision_created_at
        FROM recipes r
        JOIN revisions rev ON r.id = rev.recipe_id
        WHERE rev.id = (
            SELECT MAX(id) FROM revisions WHERE recipe_id = r.id
        )
        "#,
    );

    if let Some(ref q) = search.q
        && !q.trim().is_empty()
        && let Some(query) = crate::search::parse(q)
    {
        query_builder.push(" AND ");
        query.to_sql(&mut query_builder);
    }

    query_builder.push(" ORDER BY r.created_at DESC");

    let recipes = query_builder
        .build_query_as::<crate::models::RecipeWithRevision>()
        .fetch_all(&pool)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tags_with_ids = sqlx::query_as::<_, TagWithRecipeId>(
        "SELECT t.*, rt.recipe_id FROM tags t JOIN recipe_tags rt ON t.id = rt.tag_id",
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut tags_by_recipe: std::collections::HashMap<i64, Vec<crate::models::Tag>> =
        std::collections::HashMap::new();
    for tr in tags_with_ids {
        tags_by_recipe.entry(tr.recipe_id).or_default().push(tr.tag);
    }

    // Fetch all ratings
    let ratings_result = sqlx::query_as::<_, crate::models::Rating>("SELECT * FROM ratings")
        .fetch_all(&pool)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut ratings_by_recipe: std::collections::HashMap<i64, Vec<crate::models::Rating>> =
        std::collections::HashMap::new();
    for rating in ratings_result {
        ratings_by_recipe
            .entry(rating.recipe_id)
            .or_default()
            .push(rating);
    }

    let recipes_with_tags: Vec<RecipeWithTags> = recipes
        .into_iter()
        .map(|r| {
            let tags = tags_by_recipe.remove(&r.id).unwrap_or_default();
            let ratings = ratings_by_recipe.remove(&r.id).unwrap_or_default();
            RecipeWithTags {
                recipe: r,
                tags,
                ratings,
            }
        })
        .collect();

    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    let user_email = user.map(|u| u.email);

    Ok(HtmlTemplate(RecipeListTemplate {
        recipes: recipes_with_tags,
        user: user_email,
        q: search.q,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub url: String,
}

use fantoccini::{ClientBuilder, Locator};
use std::net::TcpListener;
use std::process::{Child, Command};

struct ChromeDriver {
    process: Child,
}

impl ChromeDriver {
    fn start(port: u16) -> Result<Self, String> {
        let cmd = std::env::var("CHROMEDRIVER_PATH").unwrap_or_else(|_| "chromedriver".to_string());
        let process = Command::new(cmd)
            .arg(format!("--port={}", port))
            .arg("--whitelisted-ips=")
            .spawn()
            .map_err(|e| format!("Failed to spawn chromedriver: {}", e))?;
        // Give it a moment to start
        std::thread::sleep(std::time::Duration::from_millis(500));
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

pub async fn import_recipe(
    Json(payload): Json<ImportRequest>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    let api_key = std::env::var("GEMINI_API_KEY").map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "GEMINI_API_KEY not set".to_string(),
        )
    })?;

    // 1. Find port
    let port =
        find_available_port().map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    println!("Starting ChromeDriver on port {}", port);

    // 2. Start ChromeDriver (The guard ensures it is killed when this function returns/errors)
    let _driver_guard = ChromeDriver::start(port)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

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
                    eprintln!("Failed to connect to chromedriver after retries");
                }
            }
        }
    }
    let client = client.ok_or((
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to connect to ChromeDriver".to_string(),
    ))?;

    // 4. Navigate
    client
        .goto(&payload.url)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Wait for content (H1 is a good proxy)
    client
        .wait()
        .for_element(Locator::Css("h1"))
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Wait failed: {}", e),
            )
        })?;

    // Give it a moment for iframes to render
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 5. Extract Text
    let mut text = String::new();

    // Main Body
    if let Ok(body) = client.find(Locator::Css("body")).await {
        match body.text().await {
            Ok(t) => text.push_str(&t),
            Err(e) => eprintln!("Failed to get body text: {}", e),
        }
    }

    // Iframes
    // We get all iframe elements first
    if let Ok(iframes) = client.find_all(Locator::Css("iframe")).await {
        println!("Found {} iframes", iframes.len());

        for (i, _frame) in iframes.iter().enumerate() {
            text.push_str(&format!("\n\n--- IFrame {} ---\n", i));
            // Switch to frame
            if let Ok(_) = client.enter_frame(Some(i as u16)).await {
                // Extract body text of frame
                if let Ok(body) = client.find(Locator::Css("body")).await {
                    match body.text().await {
                        Ok(t) => text.push_str(&t),
                        Err(e) => eprintln!("Failed to get frame body text: {}", e),
                    }
                }

                // Switch back to parent
                if let Err(e) = client.enter_parent_frame().await {
                    eprintln!("Failed to switch back to parent frame: {}", e);
                    break;
                }
            } else {
                eprintln!("Failed to enter frame {}", i);
            }
        }
    }

    // Truncate
    let truncated_text = if text.len() > 50_000 {
        &text[..50_000]
    } else {
        &text
    };

    // Explicitly close the session to free resources
    if let Err(e) = client.close().await {
        eprintln!("Failed to close Fantoccini session: {}", e);
    }

    let client_http = reqwest::Client::new();
    let parsed = crate::ai::extract_recipe_from_text(&client_http, &api_key, truncated_text)
        .await
        .map_err(|e| {
            let msg = format!("AI extraction failed: {}", e);
            eprintln!("{}", msg);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, msg)
        })?;

    Ok(Json(parsed))
}

async fn fetch_all_tags_ordered(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT t.name 
        FROM tags t
        LEFT JOIN recipe_tags rt ON t.id = rt.tag_id
        GROUP BY t.id, t.name
        ORDER BY COUNT(rt.recipe_id) DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

async fn fetch_revisions(
    pool: &SqlitePool,
    recipe_id: i64,
) -> Result<Vec<(i64, chrono::NaiveDateTime)>, sqlx::Error> {
    sqlx::query_as::<_, (i64, chrono::NaiveDateTime)>(
        "SELECT revision_number, created_at FROM revisions WHERE recipe_id = ? ORDER BY revision_number DESC",
    )
    .bind(recipe_id)
    .fetch_all(pool)
    .await
}

pub async fn google_auth(
    State(client): State<OAuthClient>,
    session: Session,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Enforce localhost for Google OAuth to avoid cookie domain mismatches
    if let Some(host) = headers.get("host")
        && let Ok(host_str) = host.to_str()
        && host_str.starts_with("127.0.0.1")
    {
        return Redirect::to("http://localhost:3000/auth/google");
    }

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    // Store CSRF token in session for validation
    session
        .insert("csrf_token", csrf_token.secret())
        .await
        .unwrap();

    // Explicitly save the session to ensure the token is written to the store
    // before we redirect the user.
    session.save().await.unwrap();

    Redirect::to(auth_url.as_str())
}

use axum::extract::Path;

#[derive(Deserialize)]
pub struct RecipeScale {
    scale: Option<f64>,
}

pub async fn recipe_detail(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    Query(params): Query<RecipeScale>,
    session: Session,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let recipe = sqlx::query_as::<_, crate::models::RecipeWithRevision>(
        r#"
        SELECT r.id, rev.id as revision_id, rev.revision_number, rev.title, rev.instructions, rev.url, rev.overview, r.created_at, rev.created_at as revision_created_at
        FROM recipes r
        JOIN revisions rev ON r.id = rev.recipe_id
        WHERE r.id = ? AND rev.id = (
            SELECT MAX(id) FROM revisions WHERE recipe_id = r.id
        )
        "#
    )
        .bind(id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(match recipe {
        Some(recipe) => {
            let ingredients = sqlx::query_as::<_, crate::models::Ingredient>(
                "SELECT * FROM ingredients WHERE revision_id = ?",
            )
            .bind(recipe.revision_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let tags = sqlx::query_as::<_, crate::models::Tag>(
                "SELECT t.* FROM tags t JOIN recipe_tags rt ON t.id = rt.tag_id WHERE rt.recipe_id = ?"
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
            let user_email = user.map(|u| u.email);

            let scale = params.scale.unwrap_or(1.0);

            let all_tags = fetch_all_tags_ordered(&pool).await.unwrap_or_default();

            let revisions = fetch_revisions(&pool, id)
                .await
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let ratings = sqlx::query_as::<_, crate::models::Rating>(
                "SELECT * FROM ratings WHERE recipe_id = ?",
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            (
                axum::http::StatusCode::OK,
                HtmlTemplate(RecipeDetailTemplate {
                    recipe,
                    ingredients,
                    tags,
                    user: user_email,
                    scale,
                    all_tags,
                    revisions,
                    ratings,
                }),
            )
                .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "Recipe not found").into_response(),
    })
}

pub async fn recipe_revision_detail(
    State(pool): State<SqlitePool>,
    Path((id, revision_number)): Path<(i64, i64)>,
    Query(params): Query<RecipeScale>,
    session: Session,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let recipe = sqlx::query_as::<_, crate::models::RecipeWithRevision>(
        r#"
        SELECT r.id, rev.id as revision_id, rev.revision_number, rev.title, rev.instructions, rev.url, rev.overview, r.created_at, rev.created_at as revision_created_at
        FROM recipes r
        JOIN revisions rev ON r.id = rev.recipe_id
        WHERE r.id = ? AND rev.revision_number = ?
        "#
    )
    .bind(id)
    .bind(revision_number)
    .fetch_optional(&pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(match recipe {
        Some(recipe) => {
            let ingredients = sqlx::query_as::<_, crate::models::Ingredient>(
                "SELECT * FROM ingredients WHERE revision_id = ?",
            )
            .bind(recipe.revision_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let tags = sqlx::query_as::<_, crate::models::Tag>(
                "SELECT t.* FROM tags t JOIN recipe_tags rt ON t.id = rt.tag_id WHERE rt.recipe_id = ?"
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
            let user_email = user.map(|u| u.email);

            let scale = params.scale.unwrap_or(1.0);

            let all_tags = fetch_all_tags_ordered(&pool).await.unwrap_or_default();

            let revisions = fetch_revisions(&pool, id)
                .await
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let ratings = sqlx::query_as::<_, crate::models::Rating>(
                "SELECT * FROM ratings WHERE recipe_id = ?",
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            (
                axum::http::StatusCode::OK,
                HtmlTemplate(RecipeDetailTemplate {
                    recipe,
                    ingredients,
                    tags,
                    user: user_email,
                    scale,
                    all_tags,
                    revisions,
                    ratings,
                }),
            )
                .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "Revision not found").into_response(),
    })
}

pub async fn restore_recipe_revision(
    State(pool): State<SqlitePool>,
    Path((id, revision_number)): Path<(i64, i64)>,
    session: Session,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Ok(Redirect::to("/").into_response());
    }

    // 1. Fetch the target revision to copy
    let target_rev = sqlx::query_as::<_, crate::models::RecipeWithRevision>(
        r#"
         SELECT r.id, rev.id as revision_id, rev.revision_number, rev.title, rev.instructions, rev.url, rev.overview, r.created_at, rev.created_at as revision_created_at
         FROM recipes r
         JOIN revisions rev ON r.id = rev.recipe_id
         WHERE r.id = ? AND rev.revision_number = ?
         "#
    )
    .bind(id)
    .bind(revision_number)
    .fetch_optional(&pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((axum::http::StatusCode::NOT_FOUND, "Revision not found".to_string()))?;

    // 2. Fetch current latest revision number
    let latest_rev_num: i64 =
        sqlx::query_scalar("SELECT MAX(revision_number) FROM revisions WHERE recipe_id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let new_rev_num = latest_rev_num + 1;

    let mut tx = pool.begin().await.unwrap();

    // 3. Create new revision with target data
    let new_rev_result = sqlx::query(
        "INSERT INTO revisions (recipe_id, revision_number, title, instructions, url, overview) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(new_rev_num)
    .bind(&target_rev.title)
    .bind(&target_rev.instructions)
    .bind(&target_rev.url)
    .bind(&target_rev.overview)
    .execute(&mut *tx)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let new_rev_id = new_rev_result.last_insert_rowid();

    // 4. Fetch target ingredients
    let target_ingredients = sqlx::query_as::<_, crate::models::Ingredient>(
        "SELECT * FROM ingredients WHERE revision_id = ?",
    )
    .bind(target_rev.revision_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 5. Insert new ingredients
    for ing in target_ingredients {
        sqlx::query(
            "INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)",
        )
        .bind(new_rev_id)
        .bind(ing.name)
        .bind(ing.quantity)
        .bind(ing.unit)
        .execute(&mut *tx)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    tx.commit().await.unwrap();

    Ok(Redirect::to(&format!("/recipes/{}", id)).into_response())
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    email: String,
    #[serde(rename = "verified_email")]
    #[allow(dead_code)]
    verified_email: bool,
}

pub async fn google_auth_callback(
    Query(query): Query<AuthRequest>,
    State(client): State<OAuthClient>,
    session: Session,
) -> impl IntoResponse {
    let csrf_secret: Option<String> = session.get("csrf_token").await.unwrap();

    // Verify CSRF state
    if let Some(secret) = csrf_secret {
        if secret != query.state {
            return "CSRF Mismatch".into_response();
        }
    } else {
        return "Missing CSRF Token".into_response();
    }

    let token = client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(&|request: oauth2::HttpRequest| async move {
            let client = reqwest::Client::new();
            let builder = client
                .request(request.method().clone(), request.uri().to_string())
                .headers(request.headers().clone())
                .body(request.body().clone());
            let response = builder.send().await?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await?.to_vec();

            let mut builder = axum::http::Response::builder().status(status);

            for (key, value) in headers {
                if let Some(key) = key {
                    builder = builder.header(key, value);
                }
            }

            Ok::<_, reqwest::Error>(builder.body(body).unwrap())
        })
        .await
        .expect("Failed to exchange token");

    let client = reqwest::Client::new();
    let user_info: GoogleUserInfo = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .expect("Failed to fetch user info")
        .json()
        .await
        .expect("Failed to parse user info");

    session
        .insert(
            "user",
            SessionUser {
                email: user_info.email,
            },
        )
        .await
        .unwrap();

    Redirect::to("/").into_response()
}

pub async fn logout(session: Session) -> impl IntoResponse {
    session.remove::<SessionUser>("user").await.unwrap();
    Redirect::to("/")
}

#[derive(Deserialize)]
pub struct IngredientInput {
    pub quantity: Option<String>,
    pub unit: Option<String>,
    pub name: String,
}

#[derive(Deserialize)]
pub struct RecipeCreatePayload {
    pub title: String,
    pub instructions: String,
    pub ingredients: Vec<IngredientInput>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub overview: String,
}

use crate::templates::RecipeFormTemplate;

fn normalize_unit(u: &str) -> String {
    // Special handling for case-sensitive abbreviations if needed, e.g. T vs t
    // But usually we can just lowercase for standard words.
    // T = tbsp, t = tsp.
    if u == "T" {
        return "tbsp".to_string();
    }

    let lower = u.to_lowercase();
    let trimmed = lower.trim_end_matches('.');

    match trimmed {
        "tsp" | "t" | "teaspoon" | "teaspoons" => "tsp".to_string(),
        "tbsp" | "tbs" | "tbl" | "tablespoon" | "tablespoons" => "tbsp".to_string(),
        "c" | "cup" | "cups" => "cup".to_string(),
        "fl oz" | "fluid oz" | "fluid ounce" | "fluid ounces" => "fl oz".to_string(),
        "oz" | "ounce" | "ounces" => "oz".to_string(),
        "lb" | "lbs" | "pound" | "pounds" => "lb".to_string(),
        "g" | "gram" | "grams" => "g".to_string(),
        "kg" | "kilogram" | "kilograms" => "kg".to_string(),
        "ml" | "milliliter" | "milliliters" => "ml".to_string(),
        "l" | "liter" | "liters" => "l".to_string(),
        "pt" | "pint" | "pints" => "pint".to_string(),
        "qt" | "quart" | "quarts" => "quart".to_string(),
        "gal" | "gallon" | "gallons" => "gallon".to_string(),
        _ => u.to_string(),
    }
}

fn parse_quantity(s: &str) -> Option<f64> {
    if s.contains('-') {
        // Mixed number "1-1/2" -> 1 + 1/2
        let subparts: Vec<&str> = s.split('-').collect();
        if subparts.len() == 2 {
            let whole: f64 = subparts[0].parse().ok()?;
            let frac_parts: Vec<&str> = subparts[1].split('/').collect();
            if frac_parts.len() == 2 {
                let num: f64 = frac_parts[0].parse().ok()?;
                let den: f64 = frac_parts[1].parse().ok()?;
                return Some(whole + (num / den));
            }
        }
    } else if s.contains('/') {
        // Fraction "1/2"
        let frac_parts: Vec<&str> = s.split('/').collect();
        if frac_parts.len() == 2 {
            let num: f64 = frac_parts[0].parse().ok()?;
            let den: f64 = frac_parts[1].parse().ok()?;
            if den == 0.0 {
                return None;
            }
            return Some(num / den);
        }
    } else {
        // Decimal or Integer
        return s.parse().ok();
    }
    None
}

pub async fn create_recipe_form(
    State(pool): State<SqlitePool>,
    session: Session,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Ok(Redirect::to("/").into_response());
    }

    let all_tags = fetch_all_tags_ordered(&pool)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(HtmlTemplate(RecipeFormTemplate {
        is_edit: false,
        recipe: None,
        ingredients: vec![],
        tags: vec![],
        user: user.map(|u| u.email),
        ingredients_json: "[]".to_string(),
        all_tags_json: serde_json::to_string(&all_tags).unwrap_or_else(|_| "[]".to_string()),
        initial_url: params.get("url").cloned(),
    })
    .into_response())
}

pub async fn create_recipe(
    State(pool): State<SqlitePool>,
    session: Session,
    Json(payload): Json<RecipeCreatePayload>,
) -> impl IntoResponse {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Redirect::to("/").into_response();
    }

    let mut tx = pool.begin().await.unwrap();

    let recipe_result = sqlx::query("INSERT INTO recipes DEFAULT VALUES")
        .execute(&mut *tx)
        .await;

    match recipe_result {
        Ok(record) => {
            let recipe_id = record.last_insert_rowid();

            let rev_result = sqlx::query("INSERT INTO revisions (recipe_id, revision_number, title, instructions, url, overview) VALUES (?, ?, ?, ?, ?, ?)")
                .bind(recipe_id)
                .bind(1) // First revision
                .bind(&payload.title)
                .bind(if payload.instructions.trim().is_empty() { None } else { Some(&payload.instructions) })
                .bind(if payload.url.is_empty() { None } else { Some(&payload.url) })
                .bind(if payload.overview.is_empty() { None } else { Some(&payload.overview) })
                .execute(&mut *tx)
                .await;

            if let Ok(rev_record) = rev_result {
                let revision_id = rev_record.last_insert_rowid();

                // Parse and insert ingredients linked to revision
                // Insert structured ingredients
                for ing in payload.ingredients {
                    let quantity = ing.quantity.as_deref().and_then(parse_quantity);
                    let unit = ing.unit.map(|u| normalize_unit(&u));

                    let _ = sqlx::query("INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)")
                            .bind(revision_id)
                            .bind(ing.name)
                            .bind(quantity)
                            .bind(unit)
                            .execute(&mut *tx)
                            .await;
                }

                // Insert tags
                for tag_name in payload.tags {
                    let tag_name = tag_name.trim();
                    if !tag_name.is_empty() {
                        let _ = sqlx::query("INSERT OR IGNORE INTO tags (name) VALUES (?)")
                            .bind(tag_name)
                            .execute(&mut *tx)
                            .await;

                        let tag_id_row: Option<(i64,)> =
                            sqlx::query_as("SELECT id FROM tags WHERE name = ?")
                                .bind(tag_name)
                                .fetch_optional(&mut *tx)
                                .await
                                .unwrap_or(None);

                        if let Some((tag_id,)) = tag_id_row {
                            let _ = sqlx::query(
                                "INSERT INTO recipe_tags (recipe_id, tag_id) VALUES (?, ?)",
                            )
                            .bind(recipe_id)
                            .bind(tag_id)
                            .execute(&mut *tx)
                            .await;
                        }
                    }
                }

                tx.commit().await.unwrap();
                Redirect::to(&format!("/recipes/{}", recipe_id)).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create revision",
                )
                    .into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create recipe",
        )
            .into_response(),
    }
}

pub async fn edit_recipe_form(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    session: Session,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Ok(Redirect::to("/").into_response());
    }

    let recipe = sqlx::query_as::<_, crate::models::RecipeWithRevision>(
        r#"
        SELECT r.id, rev.id as revision_id, rev.revision_number, rev.title, rev.instructions, rev.url, rev.overview, r.created_at, rev.created_at as revision_created_at
        FROM recipes r
        JOIN revisions rev ON r.id = rev.recipe_id
        WHERE r.id = ? AND rev.id = (
            SELECT MAX(id) FROM revisions WHERE recipe_id = r.id
        )
        "#
    )
    .bind(id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match recipe {
        Some(recipe) => {
            let ingredients = sqlx::query_as::<_, crate::models::Ingredient>(
                "SELECT * FROM ingredients WHERE revision_id = ?",
            )
            .bind(recipe.revision_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let tags = sqlx::query_as::<_, crate::models::Tag>(
                "SELECT t.* FROM tags t JOIN recipe_tags rt ON t.id = rt.tag_id WHERE rt.recipe_id = ?"
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let all_tags = fetch_all_tags_ordered(&pool).await.unwrap_or_default();

            Ok(HtmlTemplate(RecipeFormTemplate {
                is_edit: true,
                recipe: Some(recipe),
                ingredients: ingredients.clone(),
                tags,
                user: user.map(|u| u.email),
                ingredients_json: serde_json::to_string(&ingredients)
                    .unwrap_or_else(|_| "[]".to_string()),
                all_tags_json: serde_json::to_string(&all_tags)
                    .unwrap_or_else(|_| "[]".to_string()),
                initial_url: None,
            })
            .into_response())
        }
        None => Ok((axum::http::StatusCode::NOT_FOUND, "Recipe not found").into_response()),
    }
}

pub async fn update_recipe(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    session: Session,
    Json(payload): Json<RecipeCreatePayload>,
) -> impl IntoResponse {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Redirect::to("/").into_response();
    }

    // Get latest revision number
    let latest_rev: Option<i64> =
        sqlx::query_scalar("SELECT MAX(revision_number) FROM revisions WHERE recipe_id = ?")
            .bind(id)
            .fetch_optional(&pool)
            .await
            .unwrap_or(None);

    let next_rev = latest_rev.unwrap_or(0) + 1;

    let mut tx = pool.begin().await.unwrap();

    let result = sqlx::query(
        "INSERT INTO revisions (recipe_id, revision_number, title, instructions, url, overview) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(next_rev)
    .bind(&payload.title)
    .bind(if payload.instructions.trim().is_empty() {
        None
    } else {
        Some(&payload.instructions)
    })
    .bind(if payload.url.is_empty() {
        None
    } else {
        Some(&payload.url)
    })
    .bind(if payload.overview.is_empty() {
        None
    } else {
        Some(&payload.overview)
    })
    .execute(&mut *tx)
    .await;

    match result {
        Ok(record) => {
            let revision_id = record.last_insert_rowid();

            // Re-insert ingredients linked to new revision
            for ing in payload.ingredients {
                let quantity = ing.quantity.as_deref().and_then(parse_quantity);
                let unit = ing.unit.map(|u| normalize_unit(&u));

                let _ = sqlx::query("INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)")
                    .bind(revision_id)
                    .bind(ing.name)
                    .bind(quantity)
                    .bind(unit)
                    .execute(&mut *tx)
                    .await;
            }

            // Update tags (still linked to recipe_id, so wipe and replace)
            let _ = sqlx::query("DELETE FROM recipe_tags WHERE recipe_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await;

            for tag_name in payload.tags {
                let tag_name = tag_name.trim();
                if !tag_name.is_empty() {
                    let _ = sqlx::query("INSERT OR IGNORE INTO tags (name) VALUES (?)")
                        .bind(tag_name)
                        .execute(&mut *tx)
                        .await;

                    let tag_id_row: Option<(i64,)> =
                        sqlx::query_as("SELECT id FROM tags WHERE name = ?")
                            .bind(tag_name)
                            .fetch_optional(&mut *tx)
                            .await
                            .unwrap_or(None);

                    if let Some((tag_id,)) = tag_id_row {
                        let _ = sqlx::query(
                            "INSERT INTO recipe_tags (recipe_id, tag_id) VALUES (?, ?)",
                        )
                        .bind(id)
                        .bind(tag_id)
                        .execute(&mut *tx)
                        .await;
                    }
                }
            }

            tx.commit().await.unwrap();
            Redirect::to(&format!("/recipes/{}", id)).into_response()
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update recipe",
        )
            .into_response(),
    }
}

pub async fn delete_recipe(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    session: Session,
) -> impl IntoResponse {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Redirect::to("/").into_response();
    }

    // Use a transaction to ensure all or nothing
    let mut tx = pool.begin().await.unwrap();

    // 1. Delete Ingredients (depend on revisions)
    sqlx::query("DELETE FROM ingredients WHERE revision_id IN (SELECT id FROM revisions WHERE recipe_id = ?)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 2. Delete Revisions (depend on recipes)
    sqlx::query("DELETE FROM revisions WHERE recipe_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 3. Delete Ratings (depend on recipes)
    sqlx::query("DELETE FROM ratings WHERE recipe_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 4. Delete Recipe Tags (depend on recipes)
    sqlx::query("DELETE FROM recipe_tags WHERE recipe_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();

    // 5. Delete Recipe (root)
    sqlx::query("DELETE FROM recipes WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();

    tx.commit().await.unwrap();

    // Use HX-Redirect to force a client-side redirect to the homepage.
    // This allows HTMX to handle the navigation cleanly.
    ([(
        axum::http::header::HeaderName::from_static("hx-redirect"),
        axum::http::HeaderValue::from_static("/"),
    )])
    .into_response()
}

#[derive(Deserialize)]
pub struct RatingForm {
    rater_name: String,
    score: i64,
}

pub async fn update_rating(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    Form(form): Form<RatingForm>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    if form.score == 0 {
        sqlx::query("DELETE FROM ratings WHERE recipe_id = ? AND rater_name = ?")
            .bind(id)
            .bind(form.rater_name)
            .execute(&pool)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    } else {
        sqlx::query(
            "INSERT INTO ratings (recipe_id, rater_name, score) VALUES (?, ?, ?)
             ON CONFLICT(recipe_id, rater_name) DO UPDATE SET score = excluded.score",
        )
        .bind(id)
        .bind(form.rater_name)
        .bind(form.score)
        .execute(&pool)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Return empty success (for HTMX) or redirect
    Ok(axum::http::StatusCode::OK)
}

#[derive(Deserialize)]
pub struct TagsForm {
    tags_text: String,
}

pub async fn update_recipe_tags(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    session: Session,
    Form(form): Form<TagsForm>,
) -> impl IntoResponse {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Redirect::to("/").into_response();
    }

    // Clear existing tags and re-insert
    let _ = sqlx::query("DELETE FROM recipe_tags WHERE recipe_id = ?")
        .bind(id)
        .execute(&pool)
        .await;

    for tag_name in form.tags_text.split(',') {
        let tag_name = tag_name.trim();
        if !tag_name.is_empty() {
            let _ = sqlx::query("INSERT OR IGNORE INTO tags (name) VALUES (?)")
                .bind(tag_name)
                .execute(&pool)
                .await;

            let tag_id_row: Option<(i64,)> = sqlx::query_as("SELECT id FROM tags WHERE name = ?")
                .bind(tag_name)
                .fetch_optional(&pool)
                .await
                .unwrap_or(None);

            if let Some((tag_id,)) = tag_id_row {
                let _ = sqlx::query("INSERT INTO recipe_tags (recipe_id, tag_id) VALUES (?, ?)")
                    .bind(id)
                    .bind(tag_id)
                    .execute(&pool)
                    .await;
            }
        }
    }

    // Redirect back to detail page
    Redirect::to(&format!("/recipes/{}", id)).into_response()
}

#[derive(Deserialize, Debug)]
pub struct ConversionEntry {
    pub factor: Option<f64>,
    pub target_unit: String,
    pub source_key: String,
    pub source_unit: String,
    pub source_qty: f64,
}

// Helper to convert common units to ml
fn to_ml(qty: f64, unit: &str) -> Option<f64> {
    let u = normalize_unit(unit);
    match u.as_str() {
        "ml" | "milliliter" => Some(qty),
        "l" | "liter" => Some(qty * 1000.0),
        "tsp" | "teaspoon" => Some(qty * 4.92892),
        "tbsp" | "tablespoon" => Some(qty * 14.7868),
        "fl oz" => Some(qty * 29.5735),
        "c" | "cup" => Some(qty * 236.588),
        "pt" | "pint" => Some(qty * 473.176),
        "qt" | "quart" => Some(qty * 946.353),
        "gal" | "gallon" => Some(qty * 3785.41),
        _ => None,
    }
}

#[derive(Deserialize, Debug)]
pub struct ConversionSubmission {
    pub factors: Vec<ConversionEntry>,
}

pub async fn convert_recipe_form(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    session: Session,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Ok(Redirect::to("/").into_response());
    }

    // Get recipe to display title etc
    let recipe = sqlx::query_as::<_, crate::models::RecipeWithRevision>(
        r#"
        SELECT r.id, rev.id as revision_id, rev.revision_number, rev.title, rev.instructions, rev.url, rev.overview, r.created_at, rev.created_at as revision_created_at
        FROM recipes r
        JOIN revisions rev ON r.id = rev.recipe_id
        WHERE r.id = ? AND rev.id = (
             SELECT MAX(id) FROM revisions WHERE recipe_id = r.id
        )
        "#
    )
    .bind(id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((axum::http::StatusCode::NOT_FOUND, "Recipe not found".to_string()))?;

    // Get ingredients
    let ingredients = sqlx::query_as::<_, crate::models::Ingredient>(
        "SELECT * FROM ingredients WHERE revision_id = ?",
    )
    .bind(recipe.revision_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Filter and collect unique volumetric ingredients
    let mut unique_items = std::collections::HashSet::new();
    let mut display_items = Vec::new();

    for ing in ingredients {
        if let (Some(unit), Some(qty)) = (ing.unit.clone(), ing.quantity) {
            let u = normalize_unit(&unit);
            match u.as_str() {
                "cup" | "tbsp" | "tsp" | "fl oz" | "ml" | "l" | "pint" | "quart" | "gallon" => {
                    let key = format!("{} {}", u, ing.name.trim());
                    if unique_items.insert(key.clone()) {
                        display_items.push((key, ing.name.clone(), unit, qty));
                    }
                }
                _ => {}
            }
        }
    }

    display_items.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(HtmlTemplate(RecipeConvertTemplate {
        recipe,
        ingredients: display_items,
        user: user.map(|u| u.email),
    })
    .into_response())
}

pub async fn convert_recipe(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    session: Session,
    Json(form): Json<ConversionSubmission>,
) -> impl IntoResponse {
    let user: Option<SessionUser> = session.get("user").await.unwrap_or(None);
    if user.is_none() {
        return Redirect::to("/").into_response();
    }

    // Prepare map for lookup: "unit name" -> (factor, target_unit)
    // Prepare map for lookup: "unit name" -> (factor, target_unit)
    let mut conversion_map = std::collections::HashMap::new();

    // Validate inputs first
    for entry in &form.factors {
        // Skip validation if no factor provided (user wants to skip this ingredient)
        if entry.factor.is_some() {
            if to_ml(1.0, &entry.source_unit).is_none() {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("Unknown source unit: {}", entry.source_unit),
                )
                    .into_response();
            }

            let valid_target_units = [
                "g",
                "kg",
                "oz",
                "lb",
                "gram",
                "grams",
                "kilogram",
                "kilograms",
                "ounce",
                "ounces",
                "pound",
                "pounds",
            ];
            if !valid_target_units.contains(&entry.target_unit.to_lowercase().as_str()) {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("Unknown target unit: {}", entry.target_unit),
                )
                    .into_response();
            }
        }
    }

    for entry in form.factors {
        if let Some(f) = entry.factor {
            conversion_map.insert(
                entry.source_key.clone(),
                (f, entry.target_unit, entry.source_qty, entry.source_unit),
            );
        }
    }

    // Fetch current recipe data to copy
    let mut tx = pool.begin().await.unwrap();

    let recipe = sqlx::query_as::<_, crate::models::RecipeWithRevision>(
        r#"
         SELECT r.id, rev.id as revision_id, rev.revision_number, rev.title, rev.instructions, rev.url, rev.overview, r.created_at, rev.created_at as revision_created_at
         FROM recipes r
         JOIN revisions rev ON r.id = rev.recipe_id
         WHERE r.id = ? AND rev.id = (
             SELECT MAX(id) FROM revisions WHERE recipe_id = r.id
         )
         "#
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .unwrap();

    if let Some(r) = recipe {
        let next_rev = r.revision_number + 1;

        let new_rev_result = sqlx::query(
            "INSERT INTO revisions (recipe_id, revision_number, title, instructions, url, overview) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(next_rev)
        .bind(&r.title)
        .bind(&r.instructions)
        .bind(&r.url)
        .bind(&r.overview)
        .execute(&mut *tx)
        .await;

        if let Ok(record) = new_rev_result {
            let new_rev_id = record.last_insert_rowid();

            // Fetch old ingredients
            let old_ingredients = sqlx::query_as::<_, crate::models::Ingredient>(
                "SELECT * FROM ingredients WHERE revision_id = ?",
            )
            .bind(r.revision_id)
            .fetch_all(&mut *tx)
            .await
            .unwrap();

            for ing in old_ingredients {
                let mut new_qty = ing.quantity;
                let mut new_unit = ing.unit.clone();

                if let (Some(q), Some(u)) = (ing.quantity, &ing.unit) {
                    let norm_u = normalize_unit(&u);
                    let key = format!("{} {}", norm_u, ing.name.trim());
                    // Need to match against the key we generated in the form
                    // The form generated key using `normalize_unit(original_unit) + name`.
                    // So if we have `1 cup flour`, key is `cup Flour`.
                    // The conversion entry has this key.

                    if let Some((rule_weight, target_unit, rule_src_qty, rule_src_unit)) =
                        conversion_map.get(&key)
                    {
                        // Calculate density: rule_weight / rule_vol_ml
                        if let (Some(ing_ml), Some(rule_ml)) =
                            (to_ml(q, u), to_ml(*rule_src_qty, rule_src_unit))
                        {
                            if rule_ml > 0.0 {
                                let density = rule_weight / rule_ml; // g/ml
                                let final_weight = ing_ml * density;
                                new_qty = Some(final_weight);
                                new_unit = Some(target_unit.clone());
                            }
                        }
                    }
                }

                let _ = sqlx::query("INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)")
                .bind(new_rev_id)
                .bind(ing.name)
                .bind(new_qty)
                .bind(new_unit)
                .execute(&mut *tx)
                .await;
            }

            tx.commit().await.unwrap();
            return Redirect::to(&format!("/recipes/{}", id)).into_response();
        }
    }

    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to convert recipe",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_unit() {
        assert_eq!(normalize_unit("cups"), "cup");
        assert_eq!(normalize_unit("T"), "tbsp");
        assert_eq!(normalize_unit("tsp."), "tsp");
        assert_eq!(normalize_unit("ounce"), "oz");
        assert_eq!(normalize_unit("Gram"), "g");
        assert_eq!(normalize_unit("pints"), "pint");
        assert_eq!(normalize_unit("to taste"), "to taste");
    }

    #[test]
    fn test_parse_quantity() {
        assert_eq!(parse_quantity("1"), Some(1.0));
        assert_eq!(parse_quantity("1.5"), Some(1.5));
        assert_eq!(parse_quantity("1/2"), Some(0.5));
        assert_eq!(parse_quantity("1-1/2"), Some(1.5));
        assert_eq!(parse_quantity("abc"), None);
        assert_eq!(parse_quantity("1/0"), None);
    }
}
