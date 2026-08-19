#!/bin/bash

echo "Starting Python AI Engine (FastAPI) on Port 8000..."
cd apps/ai-engine
source venv/bin/activate
uvicorn app.main:app --port 8000 &
cd ../..

echo "Starting Rust AST Scanner (Axum) on Port 3000..."
cd apps/scanner-core
cargo run &
cd ../..

echo "==========================================================="
echo "All microservices are up and running!"
echo "VS Code Extension can now POST code to http://localhost:3000/scan"
echo "Press Ctrl+C to terminate the services."
echo "==========================================================="
wait
