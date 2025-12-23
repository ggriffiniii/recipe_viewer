use crate::models::RecipeWithRevision;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

#[derive(Template)]
#[template(path = "layout.html")]
#[allow(dead_code)]
pub struct LayoutTemplate<'a> {
    pub title: &'a str,
    pub user: Option<String>,
}

pub struct RecipeWithTags {
    pub recipe: RecipeWithRevision,
    pub tags: Vec<crate::models::Tag>,
    pub ratings: Vec<crate::models::Rating>,
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct RecipeListTemplate {
    pub recipes: Vec<RecipeWithTags>,
    pub user: Option<String>,
    pub q: Option<String>,
}

#[derive(Template)]
#[template(path = "detail.html")]
pub struct RecipeDetailTemplate {
    pub recipe: RecipeWithRevision,
    pub ingredients: Vec<crate::models::Ingredient>,
    pub tags: Vec<crate::models::Tag>,
    pub user: Option<String>,
    pub scale: f64,
    pub all_tags: Vec<String>,
    pub revisions: Vec<(i64, chrono::NaiveDateTime)>,
    pub ratings: Vec<crate::models::Rating>,
}

impl RecipeDetailTemplate {
    pub fn pluralize_unit(&self, unit: &str, qty: f64) -> String {
        if qty <= 1.0 {
            return unit.to_string();
        }

        match unit {
            "cup" => "cups",
            "lb" => "lbs",
            // "tsp" => "tsps", // Optional, often left as tsp
            // "tbsp" => "tbsps", // Optional
            // "oz" => "oz", // Usually invariant
            // "g" | "kg" | "ml" | "l" => unit, // Metric usually invariant in abbr
            _ => unit,
        }
        .to_string()
    }
}

#[derive(Template)]
#[template(path = "form.html")]
pub struct RecipeFormTemplate {
    pub is_edit: bool,
    pub recipe: Option<RecipeWithRevision>,
    pub ingredients: Vec<crate::models::Ingredient>,
    pub tags: Vec<crate::models::Tag>,
    pub user: Option<String>,
    pub all_tags: Vec<String>,
}

#[derive(Template)]
#[template(path = "convert.html")]
pub struct RecipeConvertTemplate {
    pub recipe: RecipeWithRevision,
    pub ingredients: Vec<(String, String, String, f64)>, // (key, name, unit, qty)
    pub user: Option<String>,
}

pub struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}
