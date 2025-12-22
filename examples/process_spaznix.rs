use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::env;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Serialize, Deserialize)]
struct GeminiResponse {
    candidates: Option<Vec<Candidate>>,
    error: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Candidate {
    content: Content,
}

#[derive(Debug, Serialize, Deserialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ParsedRecipe {
    title: Option<String>,
    url: Option<String>,
    ingredients: Vec<ParsedIngredient>,
    instructions: Option<Vec<String>>,
    overview: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ParsedIngredient {
    quantity: Option<f64>,
    unit: Option<String>,
    name: String,
}

#[derive(Debug)]
enum GeminiError {
    QuotaExceeded(Duration),
    Other(String),
}

impl std::fmt::Display for GeminiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeminiError::QuotaExceeded(d) => write!(f, "Quota exceeded, retry after {:?}", d),
            GeminiError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for GeminiError {}

async fn call_gemini(
    client: &Client,
    api_key: &str,
    text: &str,
) -> Result<ParsedRecipe, GeminiError> {
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key={}",
        api_key
    );

    let prompt = format!(
        "Extract the recipe details from the text below.\n\
        - Parse instructions into a list of strings.\n\
        - Put any information that wasn't parsed into title, url, ingredients, or instructions into the 'overview' field.\n\
        Text:\n{}",
        text
    );

    let schema = serde_json::json!({
        "type": "OBJECT",
        "properties": {
            "title": { "type": "STRING", "nullable": true },
            "url": { "type": "STRING", "nullable": true },
            "overview": { "type": "STRING", "nullable": true },
            "instructions": {
                "type": "ARRAY",
                "items": { "type": "STRING" },
                "nullable": true
            },
            "ingredients": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "quantity": { "type": "NUMBER", "nullable": true },
                        "unit": { "type": "STRING", "nullable": true },
                        "name": { "type": "STRING" }
                    },
                    "required": ["name"]
                }
            }
        },
        "required": ["ingredients"]
    });

    let body = serde_json::json!({
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": schema
        }
    });

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| GeminiError::Other(e.to_string()))?;

    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = resp
            .headers()
            .get("Retry-After")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(60)); // Default to 60s if not specified
        return Err(GeminiError::QuotaExceeded(retry_after));
    }

    if !resp.status().is_success() {
        let err_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(GeminiError::Other(format!(
            "Gemini API error: {}",
            err_text
        )));
    }

    let gemini_resp: GeminiResponse = resp
        .json()
        .await
        .map_err(|e| GeminiError::Other(e.to_string()))?;

    if let Some(err) = gemini_resp.error {
        return Err(GeminiError::Other(format!(
            "Gemini API returned error: {:?}",
            err
        )));
    }

    let raw_text = gemini_resp
        .candidates
        .as_ref()
        .and_then(|c| c.first())
        .and_then(|c| c.content.parts.first())
        .map(|p| p.text.clone())
        .ok_or_else(|| GeminiError::Other("No content in Gemini response".to_string()))?;

    let parsed: ParsedRecipe =
        serde_json::from_str(&raw_text).map_err(|e| GeminiError::Other(e.to_string()))?;
    Ok(parsed)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let api_key = env::var("GEMINI_API_KEY").expect("GEMINI_API_KEY must be set");
    let client = Client::new();

    // Setup DB connection
    let opts = SqliteConnectOptions::new()
        .filename("recipes.db")
        .create_if_missing(false);
    let pool = SqlitePool::connect_with(opts).await?;

    // Fetch candidate recipes
    let rows: Vec<(i64, String)> = sqlx::query_as(
        r#"
        SELECT r.id, rev.overview
        FROM recipes r
        JOIN revisions rev ON r.id = rev.recipe_id
        JOIN recipe_tags rt ON r.id = rt.recipe_id
        JOIN tags t ON rt.tag_id = t.id
        WHERE t.name = 'spaznix'
        AND r.id NOT IN (
            SELECT r2.id FROM recipes r2
            JOIN recipe_tags rt2 ON r2.id = rt2.recipe_id
            JOIN tags t2 ON rt2.tag_id = t2.id
            WHERE t2.name = 'gemini'
        )
        AND rev.revision_number = (
            SELECT MAX(revision_number) FROM revisions WHERE recipe_id = r.id
        )
        LIMIT 100
        "#,
    )
    .fetch_all(&pool)
    .await?;

    println!("Found {} recipes to process.", rows.len());

    for (recipe_id, overview) in rows {
        if overview.trim().is_empty() {
            println!("Skipping recipe {} due to empty overview", recipe_id);
            continue;
        }

        println!("Processing recipe {}...", recipe_id);

        loop {
            match call_gemini(&client, &api_key, &overview).await {
                Ok(parsed) => {
                    let mut tx = pool.begin().await?;

                    // Get current max revision
                    let (max_rev,): (i64,) = sqlx::query_as(
                        "SELECT MAX(revision_number) FROM revisions WHERE recipe_id = ?",
                    )
                    .bind(recipe_id)
                    .fetch_one(&mut *tx)
                    .await?;

                    let new_rev = max_rev + 1;

                    // Join instructions list into a single string with newlines
                    let instructions_text = parsed.instructions.map(|lines| lines.join("\n"));

                    // Use Gemini's overview if present, otherwise fallback to original
                    let overview_content = parsed.overview.unwrap_or("".to_string());
                    let new_overview = format!("{}\n\nParsed by Gemini", overview_content);

                    // Insert Revision
                    let rev_res = sqlx::query(
                        r#"
                    INSERT INTO revisions (recipe_id, revision_number, title, instructions, url, overview)
                    VALUES (?, ?, ?, ?, ?, ?)
                    "#,
                    )
                    .bind(recipe_id)
                    .bind(new_rev)
                    .bind(parsed.title.unwrap_or_else(|| "Untitled".to_string()))
                    .bind(instructions_text)
                    .bind(parsed.url)
                    .bind(new_overview)
                    .execute(&mut *tx)
                    .await?;

                    let revision_id = rev_res.last_insert_rowid();

                    // Insert Ingredients
                    for ing in parsed.ingredients {
                        sqlx::query(
                        "INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)"
                    )
                    .bind(revision_id)
                    .bind(ing.name)
                    .bind(ing.quantity)
                    .bind(ing.unit)
                    .execute(&mut *tx)
                    .await?;
                    }

                    // Add 'gemini' tag
                    sqlx::query("INSERT OR IGNORE INTO tags (name) VALUES ('gemini')")
                        .execute(&mut *tx)
                        .await?;

                    let (tag_id,): (i64,) =
                        sqlx::query_as("SELECT id FROM tags WHERE name = 'gemini'")
                            .fetch_one(&mut *tx)
                            .await?;

                    sqlx::query(
                        "INSERT OR IGNORE INTO recipe_tags (recipe_id, tag_id) VALUES (?, ?)",
                    )
                    .bind(recipe_id)
                    .bind(tag_id)
                    .execute(&mut *tx)
                    .await?;

                    tx.commit().await?;
                    println!(
                        "Successfully processed recipe {} -> Rev {}",
                        recipe_id, new_rev
                    );
                    break;
                }
                Err(GeminiError::QuotaExceeded(duration)) => {
                    println!(
                        "Quota exceeded. Sleeping for {:?} before retrying...",
                        duration
                    );
                    sleep(duration).await;
                }
                Err(GeminiError::Other(e)) => {
                    eprintln!("Failed to process recipe {}: {}", recipe_id, e);
                    return Err(e.into());
                }
            }
        }

        // Safety sleep between success calls
        sleep(Duration::from_millis(1000)).await;
    }

    Ok(())
}
