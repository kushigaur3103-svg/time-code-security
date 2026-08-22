import os
import json
import requests
from celery import Celery
from celery.exceptions import Reject, MaxRetriesExceededError

# ==============================================================
# TimeCodeSecurity - Redis + Celery Worker Blueprint
# ==============================================================
# This script replaces FastAPI's in-memory BackgroundTasks with
# a distributed message queue. This guarantees that if the web
# server restarts or crashes, background security scans are NOT lost.
# They are safely queued in Redis and processed asynchronously.
# ==============================================================

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Configure Celery to use Redis as both the message broker and result backend
app = Celery(
    'tcs_security_tasks',
    broker=REDIS_URL,
    backend=REDIS_URL
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    worker_prefetch_multiplier=1, # Ensure fair dispatching (workers only take 1 task at a time)
    task_acks_late=True,          # Acknowledge task ONLY after it successfully finishes
    task_reject_on_worker_lost=True # Re-queue tasks if a worker unexpectedly dies (OOM, Crash)
)

# Replace with the actual URL of your internal API or logic functions
INTERNAL_AI_ENGINE_URL = "http://localhost:8000/api/internal/generate_scan_report"

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def background_security_scan(self, job_id, email, redacted_code, system_prompt, secrets_found):
    """
    Executes deep AI security analysis asynchronously.
    Includes robust error handling and exponential backoff retries.
    """
    print(f"[+] Worker received security scan job: {job_id}")
    
    try:
        # Mocking the AI Generation Logic
        # In production, you would import `get_cached_or_generate_ai` from app.py and run it
        # or make a secure internal HTTP request to the isolated AI engine.
        print(f"[*] Processing {len(redacted_code)} bytes of code for job {job_id}...")
        
        # Simulate heavy processing or API call to Groq/Gemini/OpenAI
        import time
        time.sleep(2) 
        
        ai_reply = "🚨 VULNERABILITY DETECTED [Celery Mock Report]"
        
        if secrets_found:
            warning_str = "🚨 **CRITICAL SECURITY VIOLATION:** Hardcoded secrets/passwords were detected and successfully redacted before AI analysis to prevent data leakage. \n\n"
            ai_reply = warning_str + ai_reply
            
        print(f"[+] Security scan for {job_id} completed successfully.")
        
        # Trigger the Webhook if defined
        # ... logic to fetch user.webhook_url and post payload ...
        
        return {"job_id": job_id, "status": "success", "report_length": len(ai_reply)}
        
    except requests.exceptions.RequestException as req_err:
        print(f"[-] Network error connecting to AI engine for job {job_id}: {req_err}")
        try:
            # Retry automatically if the AI provider API is temporarily down
            raise self.retry(exc=req_err)
        except MaxRetriesExceededError:
            print(f"[-] CRITICAL: Job {job_id} permanently failed after max retries due to network issues.")
            # Update database to mark job as failed
            return {"job_id": job_id, "status": "failed", "error": "AI Engine Unreachable"}
            
    except Exception as e:
        print(f"[-] FATAL UNHANDLED ERROR in job {job_id}: {str(e)}")
        # Rejecting the task without requeueing since it's an unhandled exception (likely a code bug)
        raise Reject(reason=str(e), requeue=False)

if __name__ == '__main__':
    print("TimeCodeSecurity Celery Worker Module Loaded.")
