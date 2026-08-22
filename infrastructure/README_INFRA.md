# TimeCodeSecurity - Enterprise Infrastructure Architecture

Welcome to the **Enterprise Scalability Blueprint**. This folder contains the exact configuration and scripts required to transition TimeCodeSecurity from a lightweight SaaS into a high-concurrency, enterprise-grade architecture capable of processing thousands of parallel CI/CD security scans without dropping connections or losing tasks.

## Why are we migrating?
1. **SQLite Limitation**: SQLite locks the entire database file during writes. Under heavy enterprise load, this causes `database is locked` errors. We must migrate to **PostgreSQL**.
2. **FastAPI BackgroundTasks Limitation**: In-memory background tasks are volatile. If the API container crashes or restarts for a deployment, all pending security scans are permanently lost. We must migrate to **Redis + Celery**.

## 1. PostgreSQL Migration (`db_migration.py`)
This script configures a production-grade SQLAlchemy engine tailored for heavy web loads.
- **`pool_size` & `max_overflow`**: Creates a permanent pool of connections, bursting up to 30 concurrent connections per worker node.
- **`pool_pre_ping=True`**: Prevents the dreaded "MySQL/PostgreSQL has gone away" error by actively verifying connection health before executing a query.
- **Exponential Backoff**: If the database cluster reboots, the script automatically retries connection initialization without crashing the application.

## 2. Redis & Celery Message Queue (`celery_worker.py`)
This replaces `background_tasks.add_task()`.
- **`task_acks_late=True`**: Ensures a job is only marked as "done" when the scan actually finishes. If the worker machine loses power mid-scan, Redis automatically re-queues the job to another worker.
- **`worker_prefetch_multiplier=1`**: Prevents a single worker from hoarding tasks, ensuring perfectly balanced load distribution across your infrastructure.
- **Exponential Retries**: If the AI engine (Groq/Gemini) returns a `429 Rate Limit` or `502 Bad Gateway`, Celery intercepts it and automatically reschedules the scan 60 seconds later.

## How to Spin Up the Stack (Docker Compose Example)

To deploy this in an enterprise environment, use a `docker-compose.yml` structured like this:

```yaml
version: '3.8'

services:
  web:
    build: .
    command: uvicorn app:app --host 0.0.0.0 --port 8000
    depends_on:
      - db
      - redis
    environment:
      - DATABASE_URL=postgresql://postgres:securepassword@db:5432/timecodesecurity
      - REDIS_URL=redis://redis:6379/0

  worker:
    build: .
    command: celery -A infrastructure.celery_worker.app worker --loglevel=info
    depends_on:
      - db
      - redis
    environment:
      - DATABASE_URL=postgresql://postgres:securepassword@db:5432/timecodesecurity
      - REDIS_URL=redis://redis:6379/0

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: securepassword
      POSTGRES_DB: timecodesecurity
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

volumes:
  postgres_data:
```

With this architecture, TimeCodeSecurity is formally ready to handle enterprise traffic at scale.
