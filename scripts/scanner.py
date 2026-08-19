import os
import sys
import requests

def scan_code():
    print("--- TimeCodeSecurity: Enterprise Deep Scan Initiated ---")
    api_key = os.getenv("GROQ_API_KEY")
    
    if not api_key:
        print("[-] FATAL ERROR: GROQ_API_KEY not found in environment. Did you save it in GitHub Secrets?")
        sys.exit(1)
        
    print("[+] Connected to Enterprise Master Control.")
    print("[+] Groq AI Engine Online. Initializing security analysis...")
    
    # Target endpoint for Groq
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # We send a test vulnerable code snippet to the AI to prove it works
    payload = {
        "model": "llama3-70b-8192", 
        "messages": [
            {"role": "system", "content": "You are TimeCodeSecurity, an elite enterprise code security AI. Analyze the given code for vulnerabilities. Keep your response brief, professional, and point out the exact security flaw."},
            {"role": "user", "content": "Review this code for security issues: const db_password = 'admin_super_secret_123'; console.log(db_password);"}
        ],
        "temperature": 0.1
    }
    
    try:
        print("[+] Transmitting data to Groq 120B-Class Model...")
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
        result = response.json()
        ai_reply = result['choices'][0]['message']['content']
        
        print("\n================ AI ANALYSIS REPORT ================")
        print(ai_reply)
        print("====================================================")
        print("\n[+] SUCCESS: Live AI Integration Verified.")
        sys.exit(0)
        
    except Exception as e:
        print(f"[-] SECURITY SCAN FAILED: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    scan_code()
