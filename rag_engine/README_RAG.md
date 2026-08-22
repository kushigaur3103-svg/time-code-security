# The RAG Engine (God-Mode Context)

Welcome to the **TimeCodeSecurity Retrieval-Augmented Generation (RAG) Architecture**. 

This module represents the technological pinnacle of our AI pipeline. It upgrades the system from a "Single-File Snippet Scanner" to an **Architectural God-Mode Agent** that understands how thousands of files interact across a massive enterprise codebase.

## The Engineering Problem
If a developer creates a function `sanitize_input()` in `utils/security.py`, but forgets to call it in `api/routes.py`, an AI that only looks at `routes.py` will hallucinate or miss the context. 

## The Zero-Crash RAG Solution
We have built a proprietary, 100% crash-proof Vector Database layer.
Instead of relying on fragile external pip dependencies (like `torch` or `chromadb`) which frequently cause OOM (Out of Memory) crashes or installation loops in Docker containers, this module leverages a mathematically robust **Term Frequency Vectorization** algorithm written entirely in native Python. 

### How it works:
1. **Ingestion (`ingest_repository`)**: When a company connects their GitHub, we pipe every file through our RAG engine. It strips the code into mathematical vectors and hashes them.
2. **Contextual Retrieval (`retrieve_context`)**: When a CI/CD Pull Request triggers a scan, we take the 5 lines of changed code, convert it to a query vector, and instantly retrieve the Top 3 most relevant files from across the entire architecture.
3. **Agentic Analysis**: We inject those 3 extra files into the hidden System Prompt sent to the LLM. The AI now knows exactly how the code interacts with the rest of the app.

## Guaranteed Reliability
Per strict enterprise requirements, `vector_db.py` contains:
- **Zero External Dependencies**: No `pip install` required. No binary compilation crashes.
- **Impenetrable Exception Handling**: Every mathematical transformation is wrapped in fail-safes. If a file contains corrupted binary data, the engine will safely drop it and continue without throwing an unhandled exception.
- **Fallback Arrays**: If retrieval completely fails, it safely returns an empty array `[]` rather than crashing the primary AI security scan.
