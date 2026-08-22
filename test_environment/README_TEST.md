# TimeCodeSecurity CI/CD Stress Test

This directory contains everything you need to execute a live, production-grade stress test of the TimeCodeSecurity API inside a real CI/CD pipeline.

## What is this?
We are going to prove that your SaaS platform can autonomously detect vulnerabilities and block a deployment on GitHub. 

Included in this folder:
- `vulnerable_test.py`: A Python file containing a blatant SQL injection and a hardcoded AWS key (`AKIA...`).
- `github_actions_test.yml`: A fully weaponized GitHub Actions pipeline script that sends the code to your production backend and parses the security response.

## Instructions: How to Trigger the Stress Test

### 1. Generate Your API Key
1. Go to your live dashboard at `http://localhost:8000/dashboard` (or your live Render URL).
2. Upgrade your account to PRO using the secret license key if you haven't already.
3. Click the **Developer API** button at the top.
4. Copy the newly generated API Key (`tcs_...`).

### 2. Create a Dummy Repository
1. Log into your GitHub account.
2. Create a brand new, empty repository named `tcs-stress-test`.

### 3. Add the Secret to GitHub
1. In your new repository on GitHub, go to **Settings** > **Secrets and variables** > **Actions**.
2. Click **New repository secret**.
3. **Name**: `TCS_API_KEY`
4. **Secret**: (Paste the `tcs_...` key you generated in Step 1).
5. Click **Add secret**.

### 4. Upload the Files
1. Create a folder named `.github/workflows` in your repository.
2. Upload `github_actions_test.yml` into that `.github/workflows` folder.
3. Upload `vulnerable_test.py` into the root of your repository.
4. Commit the changes.

### 5. Watch the Pipeline Fail (Success!)
1. Go to the **Actions** tab in your GitHub repository.
2. You will see the "DevSecOps Code Scan" workflow running automatically.
3. Click on the workflow run, then click on the "DevSecOps Code Scan" job to view the console logs.
4. You will see TimeCodeSecurity intercept the code, automatically redact the AWS key, detect the SQL injection, return the vulnerability report, and explicitly throw an exit code 1 to block the vulnerable code from being deployed!
