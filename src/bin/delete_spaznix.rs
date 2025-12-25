use dotenvy::dotenv;
use sqlx::{Row, sqlite::SqlitePoolOptions};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Connect to database
    let pool = SqlitePoolOptions::new().connect(&database_url).await?;

    println!("Connected to database.");

    // 1. Find the 'spaznix' tag ID
    let tag_name = "spaznix";
    let tag_row = sqlx::query("SELECT id FROM tags WHERE name = ?")
        .bind(tag_name)
        .fetch_optional(&pool)
        .await?;

    let tag_id: i64 = match tag_row {
        Some(row) => row.get("id"),
        None => {
            println!("Tag '{}' not found. No recipes to delete.", tag_name);
            return Ok(());
        }
    };

    println!("Found tag '{}' with ID: {}", tag_name, tag_id);

    // 2. Find all recipes associated with this tag
    let recipe_rows = sqlx::query("SELECT recipe_id FROM recipe_tags WHERE tag_id = ?")
        .bind(tag_id)
        .fetch_all(&pool)
        .await?;

    let recipe_ids: Vec<i64> = recipe_rows.iter().map(|r| r.get("recipe_id")).collect();

    if recipe_ids.is_empty() {
        println!("No recipes found with tag '{}'.", tag_name);
        return Ok(());
    }

    println!("Found {} recipes to delete.", recipe_ids.len());

    // 3. Perform cascading delete in a transaction
    let mut tx = pool.begin().await?;

    for recipe_id in &recipe_ids {
        println!("Deleting recipe ID: {}", recipe_id);

        // A. Delete Ratings
        sqlx::query("DELETE FROM ratings WHERE recipe_id = ?")
            .bind(recipe_id)
            .execute(&mut *tx)
            .await?;

        // B. Get all revisions to find ingredients
        let revision_rows = sqlx::query("SELECT id FROM revisions WHERE recipe_id = ?")
            .bind(recipe_id)
            .fetch_all(&mut *tx)
            .await?;

        // C. Delete Ingredients for each revision
        for rev_row in revision_rows {
            let rev_id: i64 = rev_row.get("id");
            sqlx::query("DELETE FROM ingredients WHERE revision_id = ?")
                .bind(rev_id)
                .execute(&mut *tx)
                .await?;
        }

        // D. Delete Revisions
        sqlx::query("DELETE FROM revisions WHERE recipe_id = ?")
            .bind(recipe_id)
            .execute(&mut *tx)
            .await?;

        // E. Delete Tag Links (all tags for this recipe)
        sqlx::query("DELETE FROM recipe_tags WHERE recipe_id = ?")
            .bind(recipe_id)
            .execute(&mut *tx)
            .await?;

        // F. Delete Recipe
        sqlx::query("DELETE FROM recipes WHERE id = ?")
            .bind(recipe_id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    println!("Successfully deleted {} recipes.", recipe_ids.len());

    Ok(())
}
