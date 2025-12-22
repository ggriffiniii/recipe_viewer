use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::collections::{HashSet, VecDeque};
use tokio::task::JoinSet;
use url::Url;

const BASE_URL: &str = "http://spaznix.com/recipe/";

#[derive(Debug, Serialize, Deserialize)]
struct Recipe {
    title: String,
    ingredients: Vec<Ingredient>,
    instructions: Option<String>,
    url: Option<String>,
    overview: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ingredient {
    name: String,
    quantity: f64,
    unit: Option<String>,
}

async fn fetch_url(client: &Client, url: &Url) -> Result<String, String> {
    let resp = client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Failed to fetch {}: {}", url, resp.status()));
    }
    resp.text().await.map_err(|e| e.to_string())
}

fn extract_recipe_simple(url: &Url, text: &str, mut tags: Vec<String>) -> Recipe {
    let filename = url
        .path_segments()
        .and_then(|segments| segments.last())
        .unwrap_or("unknown_recipe");

    let title_encoded = filename.strip_suffix(".txt").unwrap_or(filename);
    let title = urlencoding::decode(title_encoded)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| title_encoded.to_string())
        .replace('_', " ")
        .replace('-', " ");

    tags.push("spaznix".to_string());

    Recipe {
        title,
        ingredients: vec![],
        instructions: None,
        url: Some(url.to_string()),
        overview: Some(text.to_string()),
        tags,
    }
}

async fn insert_recipes_batch(
    pool: &SqlitePool,
    recipes: &[Recipe],
) -> Result<(), Box<dyn std::error::Error>> {
    if recipes.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;

    for recipe in recipes {
        let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM recipes r JOIN revisions rev ON r.id = rev.recipe_id WHERE rev.title = ?")
            .bind(&recipe.title)
            .fetch_one(&mut *tx)
            .await?;

        if exists.0 > 0 {
            println!("Skipping duplicate: {}", recipe.title);
            continue;
        }

        let recipe_result =
            sqlx::query("INSERT INTO recipes (created_at) VALUES (CURRENT_TIMESTAMP)")
                .execute(&mut *tx)
                .await?;

        let recipe_id = recipe_result.last_insert_rowid();

        let rev_result = sqlx::query(
            "INSERT INTO revisions (recipe_id, revision_number, title, instructions, url, overview) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(recipe_id)
        .bind(1)
        .bind(&recipe.title)
        .bind(&recipe.instructions)
        .bind(&recipe.url)
        .bind(&recipe.overview)
        .execute(&mut *tx)
        .await?;

        let revision_id = rev_result.last_insert_rowid();

        for ingredient in &recipe.ingredients {
            sqlx::query(
                "INSERT INTO ingredients (revision_id, name, quantity, unit) VALUES (?, ?, ?, ?)",
            )
            .bind(revision_id)
            .bind(&ingredient.name)
            .bind(ingredient.quantity)
            .bind(ingredient.unit.clone())
            .execute(&mut *tx)
            .await?;
        }

        for tag_name in &recipe.tags {
            let decoded_tag = urlencoding::decode(tag_name)
                .unwrap_or_else(|_| tag_name.clone().into())
                .to_string();

            sqlx::query("INSERT OR IGNORE INTO tags (name) VALUES (?)")
                .bind(&decoded_tag)
                .execute(&mut *tx)
                .await?;

            let tag_id_row: (i64,) = sqlx::query_as("SELECT id FROM tags WHERE name = ?")
                .bind(&decoded_tag)
                .fetch_one(&mut *tx)
                .await?;

            sqlx::query("INSERT INTO recipe_tags (recipe_id, tag_id) VALUES (?, ?)")
                .bind(recipe_id)
                .bind(tag_id_row.0)
                .execute(&mut *tx)
                .await?;
        }
        println!("Staged for commit: {}", recipe.title);
    }

    tx.commit().await?;
    println!("Committed batch of recipes.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let mut visited = HashSet::new();
    let mut imported_count = 0;

    let base = Url::parse(BASE_URL)?;
    let mut queue = VecDeque::from(vec![(base.clone(), vec![])]);

    // Setup DB connection
    let opts = SqliteConnectOptions::new()
        .filename("recipes.db")
        .create_if_missing(true);
    let pool = SqlitePool::connect_with(opts).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let mut recipe_buffer: Vec<Recipe> = Vec::new();
    let mut join_set = JoinSet::new();

    loop {
        while join_set.len() < 10 {
            if let Some((current_url, current_tags)) = queue.pop_front() {
                let url_str = current_url.to_string();
                if visited.contains(&url_str) {
                    continue;
                }
                // Skip TO-TRY directory
                if url_str.contains("TO-TRY") {
                    continue;
                }
                visited.insert(url_str.clone());
                println!("Visiting: {}", url_str);

                let client = client.clone();
                join_set.spawn(async move {
                    let res = fetch_url(&client, &current_url).await;
                    (current_url, current_tags, res)
                });
            } else {
                break;
            }
        }

        if join_set.is_empty() {
            break;
        }

        if let Some(res) = join_set.join_next().await {
            match res {
                Ok((current_url, current_tags, fetch_res)) => {
                    let url_str = current_url.to_string();
                    match fetch_res {
                        Ok(html) => {
                            if url_str.ends_with(".txt") {
                                println!("Found recipe: {}", url_str);
                                let recipe =
                                    extract_recipe_simple(&current_url, &html, current_tags);
                                recipe_buffer.push(recipe);
                                imported_count += 1;

                                if recipe_buffer.len() >= 100 {
                                    insert_recipes_batch(&pool, &recipe_buffer).await?;
                                    recipe_buffer.clear();
                                }
                            } else {
                                let document = Html::parse_document(&html);
                                let link_selector = Selector::parse("a").unwrap();

                                for element in document.select(&link_selector) {
                                    if let Some(href) = element.value().attr("href") {
                                        if href.contains("?")
                                            || href == "../"
                                            || href == "./"
                                            || href == "/"
                                        {
                                            continue;
                                        }

                                        match current_url.join(href) {
                                            Ok(absolute_url) => {
                                                if !absolute_url.as_str().starts_with(BASE_URL) {
                                                    continue;
                                                }

                                                let abs_str = absolute_url.as_str();

                                                if abs_str.ends_with(".txt") {
                                                    if !visited.contains(abs_str) {
                                                        queue.push_back((
                                                            absolute_url,
                                                            current_tags.clone(),
                                                        ));
                                                    }
                                                } else if abs_str.ends_with("/") {
                                                    let tag_name = href.trim_end_matches('/');
                                                    let mut new_tags = current_tags.clone();
                                                    if !tag_name.is_empty()
                                                        && !tag_name.contains("..")
                                                    {
                                                        new_tags.push(tag_name.to_string());
                                                    }
                                                    queue.push_back((absolute_url, new_tags));
                                                }
                                            }
                                            Err(e) => eprintln!("Error joining URL: {}", e),
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => eprintln!("Error fetching {}: {}", url_str, e),
                    }
                }
                Err(e) => eprintln!("Task join error: {}", e),
            }
        }
    }

    // Insert remaining recipes
    if !recipe_buffer.is_empty() {
        insert_recipes_batch(&pool, &recipe_buffer).await?;
    }

    println!("Finished. Imported {} recipes.", imported_count);
    Ok(())
}
