import os
import sqlite3
import requests
import jwt
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv
from passlib.context import CryptContext
from datetime import datetime, timedelta

# Load the .env file containing API keys
load_dotenv()

app = FastAPI(title="TimeCodeSecurity Enterprise API")
templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "super_secret_enterprise_key_change_me_in_prod"

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class AuthPayload(BaseModel):
    email: str
    password: str

class CodePayload(BaseModel):
    code: str

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/api/signup")
async def signup(payload: AuthPayload):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT email FROM users WHERE email = ?", (payload.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Operator ID already registered.")
        
    password_hash = pwd_context.hash(payload.password)
    cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (payload.email, password_hash))
    conn.commit()
    conn.close()
    return {"message": "Signup successful. Clearance granted."}

@app.post("/api/login")
async def login(payload: AuthPayload):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE email = ?", (payload.email,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or not pwd_context.verify(payload.password, row[0]):
        raise HTTPException(status_code=401, detail="Invalid credentials. Access Denied.")
        
    token = jwt.encode(
        {"sub": payload.email, "exp": datetime.utcnow() + timedelta(hours=2)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"message": "Login successful", "token": token}

class UpgradePayload(BaseModel):
    license_key: str

async def get_current_user_email(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/api/me")
async def get_me(authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT is_premium, scan_count FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {"email": email, "is_premium": bool(row[0]), "scan_count": row[1]}

@app.post("/api/upgrade")
async def upgrade_plan(payload: UpgradePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    expected_key = os.getenv("PREMIUM_LICENSE_KEY")
    if not expected_key or payload.license_key != expected_key:
        raise HTTPException(status_code=400, detail="Invalid License Key")
        
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_premium = 1 WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    return {"message": "License accepted. Premium unlocked."}

@app.post("/scan")
async def scan_code(payload: CodePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT is_premium, scan_count FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
        
    is_premium, scan_count = bool(row[0]), row[1]
    
    if not is_premium and scan_count >= 5:
        conn.close()
        raise HTTPException(status_code=403, detail="Free plan limit reached. Please upgrade to Premium.")
        
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        api_keys_str = os.getenv("GROQ_API_KEYS")
        if api_keys_str:
            api_key = api_keys_str.split(",")[0].strip()
            
    if not api_key:
        conn.close()
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
        
        # Increment scan_count on success
        cursor.execute("UPDATE users SET scan_count = scan_count + 1 WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        
        return {"result": ai_reply}
    except Exception as e:
        conn.close()
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
