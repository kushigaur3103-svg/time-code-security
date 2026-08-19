use axum::{
    routing::post,
    Router,
    Json,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tree_sitter::{Parser, Query, QueryCursor};
use tokio::net::TcpListener;

// --- API Request / Response Structs ---

#[derive(Deserialize)]
pub struct ScanRequest {
    pub code: String,
    pub file_name: String,
}

#[derive(Debug, Serialize)]
pub struct SecurityHotspot {
    pub node_type: String,
    pub code_snippet: String,
    pub start_line: usize,
    pub end_line: usize,
    pub risk_level: String,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub status: String,
    pub file_name: String,
    pub hotspots: Vec<SecurityHotspot>,
}

// --- AST Parsing Logic ---

pub fn scan_code(source_code: &str, file_name: String) -> Result<ScanResult, Box<dyn Error>> {
    let mut parser = Parser::new();
    let language = tree_sitter_javascript::language();
    parser.set_language(language)?;

    let tree = parser.parse(source_code, None).ok_or("Failed to parse source code")?;
    let root_node = tree.root_node();

    let query_source = r#"
        (variable_declarator 
            name: (identifier) @var_name 
            value: (string) @var_value
        )
        
        (call_expression 
            function: (identifier) @func_name 
            arguments: (arguments)
            (#eq? @func_name "eval")
        )
    "#;

    let query = Query::new(language, query_source)?;
    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, root_node, source_code.as_bytes());

    let mut hotspots = Vec::new();

    for m in matches {
        for capture in m.captures {
            let capture_name = &query.capture_names()[capture.index as usize];
            let node = capture.node;
            
            if let Ok(text) = node.utf8_text(source_code.as_bytes()) {
                let text_lower = text.to_lowercase();
                
                // Hardcoded Secret Match logic
                if capture_name == "var_name" && (text_lower.contains("password") || text_lower.contains("secret")) {
                    if let Some(parent) = node.parent() {
                        if let Ok(full_snippet) = parent.utf8_text(source_code.as_bytes()) {
                            hotspots.push(SecurityHotspot {
                                node_type: "hardcoded_secret".to_string(),
                                code_snippet: full_snippet.to_string(),
                                start_line: parent.start_position().row + 1,
                                end_line: parent.end_position().row + 1,
                                risk_level: "High".to_string(),
                            });
                        }
                    }
                }
                
                // Insecure Eval Match logic
                if capture_name == "func_name" && text == "eval" {
                    if let Some(parent) = node.parent() {
                        if let Ok(full_snippet) = parent.utf8_text(source_code.as_bytes()) {
                            hotspots.push(SecurityHotspot {
                                node_type: "insecure_eval_call".to_string(),
                                code_snippet: full_snippet.to_string(),
                                start_line: parent.start_position().row + 1,
                                end_line: parent.end_position().row + 1,
                                risk_level: "Critical".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(ScanResult {
        status: "success".to_string(),
        file_name,
        hotspots,
    })
}

// --- Axum Handler ---

async fn scan_handler(Json(payload): Json<ScanRequest>) -> Json<serde_json::Value> {
    println!("Received code scan request for: {}", payload.file_name);

    // 1. Parse AST and find hotspots
    let scan_result = match scan_code(&payload.code, payload.file_name.clone()) {
        Ok(res) => res,
        Err(e) => {
            return Json(serde_json::json!({ "error": format!("AST Parsing failed: {}", e) }));
        }
    };

    println!("Found {} hotspots. Dispatching to AI Engine...", scan_result.hotspots.len());

    // 2. Dispatch to Python AI Engine
    let ai_engine_url = std::env::var("AI_ENGINE_URL").unwrap_or_else(|_| "http://localhost:8000/analyze".to_string());
    
    let client = reqwest::Client::new();
    let res = client.post(&ai_engine_url)
        .json(&scan_result)
        .send()
        .await;

    // 3. Return AI Engine Response
    match res {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(json_body) = response.json::<serde_json::Value>().await {
                    return Json(json_body);
                }
            }
            // Graceful fallback for non-200 responses
            Json(serde_json::json!({ 
                "original_hotspots": scan_result.hotspots,
                "suggested_patches": [],
                "status": "AI Engine returned invalid response - Safely Skipped"
            }))
        },
        Err(e) => {
            println!("Network Error reaching AI Engine: {}", e);
            // Graceful fallback when AI engine is completely offline/timeout
            Json(serde_json::json!({ 
                "original_hotspots": scan_result.hotspots,
                "suggested_patches": [],
                "status": "AI Engine Offline - Safely Skipped"
            }))
        }
    }
}

// --- Server Bootstrapper ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let app = Router::new().route("/scan", post(scan_handler));

    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    println!("Rust AST Scanner (Axum) listening on http://127.0.0.1:3000");
    
    axum::serve(listener, app).await?;

    Ok(())
}
