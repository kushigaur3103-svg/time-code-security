# TimeCodeSecurity - Self-Healing PR Bot

Welcome to the **Self-Healing GitHub PR Integration Prototype**.

Currently, the TimeCodeSecurity CI/CD Action simply *blocks* vulnerable code from being deployed by failing the build. While highly secure, this slows down developer velocity because they have to figure out how to fix the vulnerability manually.

This prototype demonstrates how to convert our SaaS from a "Blocker" into an **Autonomous Security Engineer**.

## How the Architecture Works

1. **The Webhook Trigger**: This Flask app acts as a GitHub App Webhook receiver. Whenever a developer pushes code and opens a Pull Request, GitHub fires a JSON payload to this server.
2. **Diff Extraction**: The bot extracts the raw patch diff of exactly what code the developer added.
3. **AI Security Analysis**: It sends the diff to our production `POST /api/cicd/scan` endpoint.
4. **Auto-Remediation**: If vulnerabilities are found, instead of just screaming "ERROR", the bot automatically routes the vulnerable code to our `POST /api/fix-code` endpoint to generate a secure drop-in replacement.
5. **The Self-Healing Comment**: The bot securely calls the GitHub REST API and injects a comment directly onto the Pull Request. The comment contains the detailed vulnerability report AND the exact copy-pasteable secure code fix.

In a fully mature version, this bot wouldn't even leave a comment—it would create a dedicated "Security Fix" commit on the developer's branch autonomously, achieving true **Self-Healing Infrastructure**.

## How to Test Locally

1. Install dependencies:
```bash
pip install flask requests
```

2. Run the bot server:
```bash
python pr_bot.py
```

3. Open a new terminal and fire a mock GitHub webhook payload to test the flow:
```bash
curl -X POST http://localhost:5001/webhook/github \
     -H "Content-Type: application/json" \
     -d '{
       "action": "opened",
       "pull_request": {
         "number": 42
       },
       "repository": {
         "full_name": "acme-corp/financial-api"
       }
     }'
```

Watch the terminal logs as the bot automatically extracts the mock SQL Injection diff, scans it, generates the fix, and structures the GitHub response!
