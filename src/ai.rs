use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

pub const GEMINI_MODEL: &str = "gemini-2.5-flash-lite";

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct GeminiResponse {
    candidates: Option<Vec<Candidate>>,
    error: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct Candidate {
    content: Content,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParsedRecipe {
    pub title: Option<String>,
    pub url: Option<String>,
    pub ingredients: Vec<ParsedIngredient>,
    pub instructions: Option<Vec<String>>,
    pub overview: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParsedIngredient {
    pub quantity: Option<f64>,
    pub unit: Option<String>,
    pub name: String,
}

#[derive(Debug)]
pub enum GeminiError {
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

pub async fn extract_recipe_from_text(
    client: &Client,
    api_key: &str,
    text: &str,
) -> Result<ParsedRecipe, GeminiError> {
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        GEMINI_MODEL, api_key
    );

    let prompt = format!(
        "Extract the recipe details from the text below.\n\
        Text:\n{}",
        text
    );

    let schema = serde_json::json!({
        "type": "OBJECT",
        "properties": {
            "title": { "type": "STRING", "nullable": true },
            "overview": { "type": "STRING", "nullable": true },
            "tags": {
                "type": "ARRAY",
                "items": { "type": "STRING" },
                "nullable": true
            },
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
        "required": ["ingredients", "instructions", "title"]
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
