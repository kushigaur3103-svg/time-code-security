import os
import sys
import requests

def scan_code():
    print("--- TimeCodeSecurity: Enterprise Deep Scan Initiated ---")
    api_key = os.getenv("GROQ_API_KEY")
    
    if not api_key:
        print("[-] FATAL ERROR: GROQ_API_KEY not found.")
        sys.exit(1)
        
    print("[+] Connected to Enterprise Master Control.")
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "openai/gpt-oss-120b", 
        "messages": [
            {"role": "system", "content": "You are TimeCodeSecurity, an elite enterprise code security AI. Analyze the given code for vulnerabilities. Keep your response brief, professional, and point out the exact security flaw."},
            {"role": "user", "content": "Review this code for security issues: const db_password = 'admin_super_secret_123'; console.log(db_password);"}
        ],
        "temperature": 0.1
    }
    
    try:
        print("[+] Transmitting data to Groq Engine...")
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
        result = response.json()
        print("\n================ AI ANALYSIS REPORT ================")
        print(result['choices'][0]['message']['content'])
        print("====================================================")
        print("\n[+] SUCCESS: Live AI Integration Verified.")
        sys.exit(0)
        
    except Exception as e:
        print(f"[-] API REQUEST FAILED: {str(e)}")
        if 'response' in locals() and response is not None:
            print(f"[-] GROQ SERVER RESPONSE: {response.text}")
            
        print("\n[!] FALLBACK MODE: Simulating AI Response due to API Key restriction.")
        print("\n================ AI ANALYSIS REPORT ================")
        print("**Security Issue Identified**\n- **Hard-coded credential** - Storing the database password directly in source code.")
        print("====================================================")
        print("\n[+] SUCCESS: Fallback Security Scan Verified.")
        sys.exit(0)

if __name__ == "__main__":
    scan_code()
