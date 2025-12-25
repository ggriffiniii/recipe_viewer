use dotenvy::dotenv;
use sqlx::sqlite::SqlitePoolOptions;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let args: Vec<String> = env::args().collect();
    let apply = args.contains(&"--apply".to_string());

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:recipes.db".to_string());

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;

    if !apply {
        println!("DRY RUN: Checking for unused tags in {}...", database_url);
    } else {
        println!("APPLY: Cleaning up unused tags in {}...", database_url);
    }

    // Find tags that are not referenced in the recipe_tags table
    let unused_tags: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM tags WHERE id NOT IN (SELECT DISTINCT tag_id FROM recipe_tags)",
    )
    .fetch_all(&pool)
    .await?;

    if unused_tags.is_empty() {
        println!("No unused tags found.");
        return Ok(());
    }

    println!("Found {} unused tags:", unused_tags.len());
    for (_, name) in &unused_tags {
        println!("  - {}", name);
    }

    if !apply {
        println!("\nThis was a dry run. To actually delete these tags, run with --apply");
        return Ok(());
    }

    let ids: Vec<i64> = unused_tags.iter().map(|(id, _)| *id).collect();

    // SQLx doesn't support Vec in IN clause directly like some other ORMs
    // without manual expansion or using placeholders.
    // Since this is a simple utility, we can just run the delete.

    let delete_query = format!(
        "DELETE FROM tags WHERE id IN ({})",
        ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    let result = sqlx::query(&delete_query).execute(&pool).await?;

    println!("Successfully deleted {} tags.", result.rows_affected());

    Ok(())
}
