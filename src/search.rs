use sqlx::{QueryBuilder, Sqlite};

#[derive(Debug, Clone, PartialEq)]
pub enum Query {
    Term(String),
    Title(String),
    Tag(String),
    Rating {
        rater: String,
        op: String,
        score: i64,
    },
    And(Box<Query>, Box<Query>),
    Or(Box<Query>, Box<Query>),
    Not(Box<Query>),
}

impl Query {
    pub fn to_sql(&self, query_builder: &mut QueryBuilder<'_, Sqlite>) {
        match self {
            Query::Term(term) => {
                query_builder.push(" (title LIKE ");
                let val = format!("%{}%", term);
                query_builder.push_bind(val);
                query_builder.push(") ");
            }
            Query::Title(pattern) => {
                query_builder.push(" (title REGEXP ");
                let val = format!("(?i){}", pattern);
                query_builder.push_bind(val);
                query_builder.push(") ");
            }
            Query::Tag(tag) => {
                query_builder.push(" (EXISTS (SELECT 1 FROM recipe_tags rt JOIN tags t ON rt.tag_id = t.id WHERE rt.recipe_id = r.id AND t.name LIKE ");
                let val = format!("%{}%", tag);
                query_builder.push_bind(val);
                query_builder.push(")) ");
            }
            Query::Rating { rater, op, score } => {
                // op is verified to be =, >, <, >=, <=
                query_builder.push(" (EXISTS (SELECT 1 FROM ratings ra WHERE ra.recipe_id = r.id AND ra.rater_name LIKE ");
                query_builder.push_bind(rater.clone()); // Exact match or case-insensitive via LIKE (collation NOCASE)
                query_builder.push(format!(" AND ra.score {} ", op));
                query_builder.push_bind(*score);
                query_builder.push(")) ");
            }
            Query::And(left, right) => {
                query_builder.push(" (");
                left.to_sql(query_builder);
                query_builder.push(" AND ");
                right.to_sql(query_builder);
                query_builder.push(") ");
            }
            Query::Or(left, right) => {
                query_builder.push(" (");
                left.to_sql(query_builder);
                query_builder.push(" OR ");
                right.to_sql(query_builder);
                query_builder.push(") ");
            }
            Query::Not(q) => {
                query_builder.push(" NOT (");
                q.to_sql(query_builder);
                query_builder.push(") ");
            }
        }
    }
}

// Simple recursive descent parser
// Tokens: (, ), AND, OR, NOT, TERM
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Str(String),
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            '(' => {
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RParen);
                chars.next();
            }
            ' ' | '\t' | '\r' | '\n' => {
                chars.next();
            }
            '"' => {
                chars.next(); // consume opening quote
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '"' {
                        chars.next(); // consume closing quote
                        break;
                    }
                    s.push(c);
                    chars.next();
                }
                tokens.push(Token::Str(s));
            }
            _ => {
                // Read word
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '(' || c == ')' || c == ' ' || c == '"' {
                        break;
                    }
                    s.push(c);
                    chars.next();
                }
                match s.to_lowercase().as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    "not" => tokens.push(Token::Not),
                    _ => tokens.push(Token::Str(s)),
                }
            }
        }
    }
    tokens
}

pub fn parse(input: &str) -> Option<Query> {
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return None;
    }
    let (query, _) = parse_expression(&tokens, 0);
    Some(query)
}

fn parse_expression(tokens: &[Token], mut pos: usize) -> (Query, usize) {
    // Parse OR terms
    let (mut left, new_pos) = parse_term(tokens, pos);
    pos = new_pos;

    while pos < tokens.len() {
        match &tokens[pos] {
            Token::Or => {
                pos += 1;
                let (right, next_pos) = parse_term(tokens, pos);
                left = Query::Or(Box::new(left), Box::new(right));
                pos = next_pos;
            }
            _ => break,
        }
    }
    (left, pos)
}

fn parse_term(tokens: &[Token], mut pos: usize) -> (Query, usize) {
    // Parse AND terms (explicit AND or implicit)
    let (mut left, new_pos) = parse_factor(tokens, pos);
    pos = new_pos;

    while pos < tokens.len() {
        match &tokens[pos] {
            Token::And => {
                pos += 1;
                let (right, next_pos) = parse_factor(tokens, pos);
                left = Query::And(Box::new(left), Box::new(right));
                pos = next_pos;
            }
            Token::Str(_) | Token::LParen | Token::Not => {
                // Implicit AND
                let (right, next_pos) = parse_factor(tokens, pos);
                left = Query::And(Box::new(left), Box::new(right));
                pos = next_pos;
            }
            _ => break,
        }
    }
    (left, pos)
}

fn parse_factor(tokens: &[Token], pos: usize) -> (Query, usize) {
    if pos >= tokens.len() {
        return (Query::Term("".to_string()), pos);
    }

    match &tokens[pos] {
        Token::Not => {
            let (q, next_pos) = parse_factor(tokens, pos + 1);
            (Query::Not(Box::new(q)), next_pos)
        }
        Token::LParen => {
            let (q, next_pos) = parse_expression(tokens, pos + 1);
            if next_pos < tokens.len() && tokens[next_pos] == Token::RParen {
                (q, next_pos + 1)
            } else {
                (q, next_pos) // Missing closing paren, just return what we have
            }
        }
        Token::Str(s) => {
            // Check for separated prefix
            if s == "title:" {
                if let Some(Token::Str(val)) = tokens.get(pos + 1) {
                    return (Query::Title(val.clone()), pos + 2);
                }
            } else if s == "tag:"
                && let Some(Token::Str(val)) = tokens.get(pos + 1)
            {
                return (Query::Tag(val.clone()), pos + 2);
            }

            let q = parse_field_string(s);
            (q, pos + 1)
        }
        _ => (Query::Term("".to_string()), pos + 1), // unexpected
    }
}

fn parse_field_string(s: &str) -> Query {
    if let Some(val) = s.strip_prefix("title:") {
        Query::Title(val.to_string())
    } else if let Some(val) = s.strip_prefix("tag:") {
        Query::Tag(val.to_string())
    } else {
        let s = s.strip_prefix("rating:").unwrap_or(s);
        // Try to parse rating: name=val, name>val, name<val
        // We look for operators =, >, <, >=, <=
        // Order matters: check longer operators first.
        let ops = [">=", "<=", "=", ">", "<"];
        for op in ops {
            if let Some(idx) = s.find(op) {
                let rater = s[..idx].trim();
                let val_str = s[idx + op.len()..].trim();
                if !rater.is_empty()
                    && let Ok(score) = val_str.parse::<i64>()
                {
                    return Query::Rating {
                        rater: rater.to_string(),
                        op: op.to_string(),
                        score,
                    };
                }
            }
        }

        Query::Term(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize() {
        let tokens = tokenize("title:pizza tag:easy rating:me>=4 (cheap OR fast)");
        assert_eq!(
            tokens,
            vec![
                Token::Str("title:pizza".to_string()),
                Token::Str("tag:easy".to_string()),
                Token::Str("rating:me>=4".to_string()),
                Token::LParen,
                Token::Str("cheap".to_string()),
                Token::Or,
                Token::Str("fast".to_string()),
                Token::RParen,
            ]
        );
    }

    #[test]
    fn test_parse_simple() {
        let query = parse("pizza").unwrap();
        assert_eq!(query, Query::Term("pizza".to_string()));

        let query = parse("title:pizza").unwrap();
        assert_eq!(query, Query::Title("pizza".to_string()));

        let query = parse("tag:dinner").unwrap();
        assert_eq!(query, Query::Tag("dinner".to_string()));
    }

    #[test]
    fn test_parse_rating() {
        let query = parse("rating:me=5").unwrap();
        assert_eq!(
            query,
            Query::Rating {
                rater: "me".to_string(),
                op: "=".to_string(),
                score: 5
            }
        );

        let query = parse("rating:user>=4").unwrap();
        assert_eq!(
            query,
            Query::Rating {
                rater: "user".to_string(),
                op: ">=".to_string(),
                score: 4
            }
        );
    }

    #[test]
    fn test_parse_logic() {
        let query = parse("pizza AND easy").unwrap();
        assert_eq!(
            query,
            Query::And(
                Box::new(Query::Term("pizza".to_string())),
                Box::new(Query::Term("easy".to_string()))
            )
        );

        let query = parse("pizza easy").unwrap();
        assert_eq!(
            query,
            Query::And(
                Box::new(Query::Term("pizza".to_string())),
                Box::new(Query::Term("easy".to_string()))
            )
        );

        let query = parse("fast OR cheap").unwrap();
        assert_eq!(
            query,
            Query::Or(
                Box::new(Query::Term("fast".to_string())),
                Box::new(Query::Term("cheap".to_string()))
            )
        );

        let query = parse("NOT spicy").unwrap();
        assert_eq!(
            query,
            Query::Not(Box::new(Query::Term("spicy".to_string())))
        );
    }

    #[test]
    fn test_parse_complex() {
        let query = parse("title:chicken (tag:easy OR tag:quick)").unwrap();
        assert_eq!(
            query,
            Query::And(
                Box::new(Query::Title("chicken".to_string())),
                Box::new(Query::Or(
                    Box::new(Query::Tag("easy".to_string())),
                    Box::new(Query::Tag("quick".to_string()))
                ))
            )
        );
    }
}
