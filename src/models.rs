use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(sqlx::FromRow, Debug, Clone)]
#[allow(dead_code)]
pub struct Recipe {
    pub id: i64,
    pub created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow, Debug, Clone)]
#[allow(dead_code)]
pub struct Revision {
    pub id: i64,
    pub recipe_id: i64,
    pub revision_number: i64,
    pub title: String,
    pub instructions: Option<String>,
    pub url: Option<String>,
    pub overview: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct RecipeWithRevision {
    pub id: i64,
    pub revision_id: i64,
    pub revision_number: i64,
    pub title: String,
    pub instructions: Option<String>,
    pub url: Option<String>,
    pub overview: Option<String>,
    #[allow(dead_code)]
    pub created_at: NaiveDateTime,
    #[allow(dead_code)]
    pub revision_created_at: NaiveDateTime,
}
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Ingredient {
    pub id: i64,
    pub revision_id: i64,
    pub name: String,
    pub quantity: Option<f64>,
    pub unit: Option<String>,
}

impl Ingredient {
    pub fn display_quantity(&self, scale: f64) -> Option<String> {
        self.quantity.map(|q| {
            let val = q * scale;
            format_fraction(val)
        })
    }
}

fn format_fraction(val: f64) -> String {
    let tolerance = 0.01;
    let int_part = val.trunc() as i64;
    let frac_part = val - val.trunc();

    if frac_part.abs() < tolerance {
        return format!("{}", int_part);
    }

    let fractions = [
        (1.0 / 8.0, "1/8"),
        (1.0 / 4.0, "1/4"),
        (1.0 / 3.0, "1/3"),
        (3.0 / 8.0, "3/8"),
        (1.0 / 2.0, "1/2"),
        (5.0 / 8.0, "5/8"),
        (2.0 / 3.0, "2/3"),
        (3.0 / 4.0, "3/4"),
        (7.0 / 8.0, "7/8"),
    ];

    for (dec, str_frac) in fractions {
        if (frac_part - dec).abs() < tolerance {
            if int_part > 0 {
                return format!("{} {}", int_part, str_frac);
            } else {
                return str_frac.to_string();
            }
        }
    }

    // If no match, return decimal formatted to 2 places, trimming zeros
    let formatted = format!("{:.2}", val);
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Tag {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Rating {
    pub id: i64,
    pub recipe_id: i64,
    pub rater_name: String,
    pub score: i64,
}
