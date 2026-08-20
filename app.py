import os
import requests
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv

# Load the .env file containing API keys
load_dotenv()

app = FastAPI(title="TimeCodeSecurity Enterprise API")
templates = Jinja2Templates(directory="templates")

class CodePayload(BaseModel):
    code: str

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/scan")
async def scan_code(payload: CodePayload):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        api_keys_str = os.getenv("GROQ_API_KEYS")
        if api_keys_str:
            api_key = api_keys_str.split(",")[0].strip()
            
    if not api_key:
        return {"error": "GROQ_API_KEY not found in .env file. Please ensure it is set."}
        
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json"
    }
    
    prompt = f"Analyze this code for security vulnerabilities. Keep your response professional, brief, and actionable. Point out exact flaws.\n\nCode to analyze:\n{payload.code}"
    
    groq_payload = {
        "model": "openai/gpt-oss-120b", 
        "messages": [
            {"role": "system", "content": "You are TimeCodeSecurity, an elite enterprise code security AI."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }
    
    try:
        response = requests.post(url, headers=headers, json=groq_payload)
        response.raise_for_status()
        result = response.json()
        ai_reply = result['choices'][0]['message']['content']
        return {"result": ai_reply}
    except Exception as e:
        error_msg = f"API Error: {str(e)}"
        if 'response' in locals() and response is not None:
            try:
                error_msg += f" - Details: {response.json().get('error', {}).get('message', response.text)}"
            except:
                error_msg += f" - Details: {response.text}"
        return {"error": error_msg}

if __name__ == "__main__":
    print("--- Starting TimeCodeSecurity Web Server ---")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
