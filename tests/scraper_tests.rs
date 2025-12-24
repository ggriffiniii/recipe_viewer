use recipe_viewer::scraper::scrape_url;

#[tokio::test]
async fn test_scrape_real_sites() {
    // Defines a list of (url, expected_text_fragment)
    // We use sites strictly for testing purposes.
    // Note: These tests depend on external connectivity and site structure.
    let test_cases = vec![
        (
            "https://www.notanothercookingshow.tv/post/spicy-red-pepper-pasta/",
            "Slice the onion and garlic thinly",
        ),
        (
            "https://www.seriouseats.com/new-york-style-pizza",
            "preheat oven to 500°F",
        ),
        (
            "https://www.skinnytaste.com/skillet-lasagna/",
            "stirring occasionally",
        ),
    ];

    for (url, expected) in test_cases {
        println!("Testing URL: {}", url);
        match scrape_url(url).await {
            Ok(text) => {
                if !text.contains(expected) {
                    panic!(
                        "Failed to find expected string '{}' in content from {}\nContent preview: {:.200}...",
                        expected, url, text
                    );
                }
            }
            Err(e) => {
                panic!("Failed to scrape {}: {}", url, e);
            }
        }
    }
}
