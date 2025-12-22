use crate::state::OAuthClient;
use axum::{
    extract::{Form, Query, State},
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

use crate::templates::{HtmlTemplate, RecipeDetailTemplate, RecipeListTemplate, RecipeWithTags};
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
        .map(|recipe| {
            let tags = tags_by_recipe.remove(&recipe.id).unwrap_or_default();
            let ratings = ratings_by_recipe.remove(&recipe.id).unwrap_or_default();
            RecipeWithTags {
                recipe,
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
pub struct RecipeForm {
    title: String,
    instructions: String,
    ingredients_text: String,
    tags_text: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    overview: String,
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
        "oz" | "ounce" | "ounces" => "oz".to_string(),
        "lb" | "lbs" | "pound" | "pounds" => "lb".to_string(),
        "g" | "gram" | "grams" => "g".to_string(),
        "kg" | "kilogram" | "kilograms" => "kg".to_string(),
        "ml" | "milliliter" | "milliliters" => "ml".to_string(),
        "l" | "liter" | "liters" => "l".to_string(),
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

fn parse_ingredient_line(line: &str) -> Option<(Option<f64>, Option<String>, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let (quantity, rest_parts) = match parse_quantity(parts[0]) {
        Some(q) => (Some(q), &parts[1..]),
        None => (None, &parts[0..]),
    };

    if rest_parts.is_empty() {
        if quantity.is_some() {
            return Some((quantity, None, "Ingredient".to_string()));
        }
        return None;
    }

    let potential_unit = rest_parts[0];
    let normalized = normalize_unit(potential_unit);
    // basic check: name changed or in common unit list
    let is_unit = normalized != potential_unit
        || [
            "cup", "cups", "oz", "lb", "lbs", "g", "kg", "ml", "l", "tsp", "tbsp",
        ]
        .contains(&normalized.as_str());

    let (unit, name_parts) = if rest_parts.len() > 1 && is_unit {
        (Some(normalized), &rest_parts[1..])
    } else {
        (None, &rest_parts[0..])
    };

    let name = name_parts.join(" ");
    Some((quantity, unit, name))
}

pub async fn create_recipe_form(
    State(pool): State<SqlitePool>,
    session: Session,
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
        all_tags,
    })
    .into_response())
}

pub async fn create_recipe(
    State(pool): State<SqlitePool>,
    session: Session,
    Form(form): Form<RecipeForm>,
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
                .bind(&form.title)
                .bind(if form.instructions.trim().is_empty() { None } else { Some(&form.instructions) })
                .bind(if form.url.is_empty() { None } else { Some(&form.url) })
                .bind(if form.overview.is_empty() { None } else { Some(&form.overview) })
                .execute(&mut *tx)
                .await;

            if let Ok(rev_record) = rev_result {
                let revision_id = rev_record.last_insert_rowid();

                // Parse and insert ingredients linked to revision
                for line in form.ingredients_text.lines() {
                    if let Some((quantity, unit, name)) = parse_ingredient_line(line) {
                        let _ = sqlx::query("INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)")
                             .bind(revision_id)
                             .bind(name)
                             .bind(quantity)
                             .bind(unit)
                             .execute(&mut *tx)
                             .await;
                    }
                }

                // Parse and insert tags linked to recipe (identity)
                for tag_name in form.tags_text.split(',') {
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
                ingredients,
                tags,
                user: user.map(|u| u.email),
                all_tags,
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
    Form(form): Form<RecipeForm>,
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
    .bind(&form.title)
    .bind(if form.instructions.trim().is_empty() {
        None
    } else {
        Some(&form.instructions)
    })
    .bind(if form.url.is_empty() {
        None
    } else {
        Some(&form.url)
    })
    .bind(if form.overview.is_empty() {
        None
    } else {
        Some(&form.overview)
    })
    .execute(&mut *tx)
    .await;

    match result {
        Ok(record) => {
            let revision_id = record.last_insert_rowid();

            // Re-insert ingredients linked to new revision
            for line in form.ingredients_text.lines() {
                if let Some((quantity, unit, name)) = parse_ingredient_line(line) {
                    let _ = sqlx::query("INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)")
                        .bind(revision_id)
                        .bind(name)
                        .bind(quantity)
                        .bind(unit)
                        .execute(&mut *tx)
                        .await;
                }
            }

            // Update tags (still linked to recipe_id, so wipe and replace)
            let _ = sqlx::query("DELETE FROM recipe_tags WHERE recipe_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await;

            for tag_name in form.tags_text.split(',') {
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
