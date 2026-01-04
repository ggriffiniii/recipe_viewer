-- Rename old table
ALTER TABLE ratings RENAME TO ratings_old;

-- Create new table with REAL score
CREATE TABLE ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id INTEGER NOT NULL,
    rater_name TEXT NOT NULL COLLATE NOCASE,
    score REAL NOT NULL CHECK (score >= 0.0 AND score <= 5.0),
    UNIQUE(recipe_id, rater_name),
    FOREIGN KEY(recipe_id) REFERENCES recipes(id)
);

-- Copy data
INSERT INTO ratings (id, recipe_id, rater_name, score)
SELECT id, recipe_id, rater_name, CAST(score AS REAL)
FROM ratings_old;

-- Drop old table
DROP TABLE ratings_old;
