import os
import json
import requests
from flask import Flask, request, jsonify

# ==========================================
# TimeCodeSecurity - Self-Healing PR Bot
# Prototype GitHub App Webhook Receiver
# ==========================================

app = Flask(__name__)

# In production, this would be your production URL
API_BASE_URL = "https://time-code-security.onrender.com/api"
API_KEY = os.getenv("TCS_API_KEY", "tcs_demo_key_123")
JWT_TOKEN = os.getenv("TCS_JWT_TOKEN", "dummy_jwt_token")

@app.route("/webhook/github", methods=["POST"])
def github_webhook():
    """
    Receives standard GitHub 'pull_request' webhook payloads.
    """
    payload = request.json
    
    # We only care about PRs that are opened or synchronized (new commits)
    action = payload.get("action")
    if action not in ["opened", "synchronize"]:
        return jsonify({"status": "ignored", "reason": f"Action '{action}' is not relevant."})

    pull_request = payload.get("pull_request", {})
    pr_number = pull_request.get("number")
    repo_full_name = payload.get("repository", {}).get("full_name")
    
    print(f"[+] Received PR #{pr_number} for {repo_full_name}")

    # 1. Fetch the actual diff of the PR (Mocked here)
    # In production: requests.get(pull_request['diff_url'], headers={"Accept": "application/vnd.github.v3.diff"})
    mock_diff = """
    @@ -10,3 +10,4 @@
    -    user_id = request.args.get('id')
    +    user_id = request.args.get('user_id')
    +    query = "SELECT * FROM users WHERE id = " + user_id
    +    cursor.execute(query)
    """

    print("[+] Extracted Code Diff. Initiating TimeCodeSecurity Scan...")

    # 2. Send the diff to our TimeCodeSecurity CI/CD engine
    try:
        scan_response = requests.post(
            f"{API_BASE_URL}/cicd/scan",
            json={"code": mock_diff, "filename": "pr_diff.py"},
            headers={"X-API-Key": API_KEY},
            timeout=10
        )
        scan_data = scan_response.json()
    except Exception as e:
        print(f"[-] Failed to reach TimeCodeSecurity API: {e}")
        return jsonify({"status": "error", "message": "API timeout"}), 500

    if not scan_data.get("vulnerabilities_found"):
        print("[+] Code is secure. Approving PR.")
        return jsonify({"status": "success", "message": "No vulnerabilities found."})

    print(f"[!] Vulnerabilities detected! Severity: {scan_data.get('severity_level')}")
    print("[+] Generating Secure Auto-Remediation Code...")

    # 3. Generate the self-healing fix
    try:
        fix_response = requests.post(
            f"{API_BASE_URL}/fix-code",
            json={"code": mock_diff},
            headers={"Authorization": f"Bearer {JWT_TOKEN}"},
            timeout=10
        )
        fix_data = fix_response.json()
        secure_code = fix_data.get("fixed_code", "Error generating fix.")
    except Exception as e:
        secure_code = "Could not generate automated fix due to engine overload."

    # 4. Post the fix back to the GitHub PR as a comment (Mocked)
    github_comment = f"""
🚨 **TimeCodeSecurity Automated Review** 🚨

We detected a **{scan_data.get('severity_level')}** severity vulnerability in this Pull Request.

**Vulnerability Analysis:**
{scan_data.get('report', 'Analysis unavailable.')[:500]}...

✅ **Self-Healing Code Fix Generated:**
```python
{secure_code}
```

*Please review the generated secure code above and commit the changes to proceed.*
    """

    print("[+] Constructing GitHub API Comment Payload:")
    github_api_payload = {
        "body": github_comment
    }
    
    # In production:
    # requests.post(f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments", json=github_api_payload, headers={"Authorization": "Bearer GITHUB_TOKEN"})

    print(github_api_payload["body"])
    
    return jsonify({
        "status": "success", 
        "action_taken": "commented_on_pr", 
        "fix_generated": True
    })

if __name__ == "__main__":
    print("Starting TimeCodeSecurity PR Bot Prototype on port 5001...")
    app.run(port=5001)
