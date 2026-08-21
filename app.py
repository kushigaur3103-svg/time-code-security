import os
import requests
import jwt
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fpdf import FPDF

from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import hashlib
import google.generativeai as genai
import openai
import cohere
import secrets
import re

SECRET_PATTERNS = {
    "AWS Access Keys": re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
    "Stripe Secrets": re.compile(r"(?i)sk_live_[0-9a-zA-Z]{24,}"),
    "Generic Tokens": re.compile(r"(?i)(?:password|secret|api_key|token|auth)[\s=:]+['\"]([^'\"]+)['\"]")
}

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("CRITICAL ERROR: DATABASE_URL is not set.")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_premium = Column(Boolean, default=False)
    scan_count = Column(Integer, default=0)
    api_key = Column(String, unique=True, index=True, nullable=True)

class ScanCache(Base):
    __tablename__ = "scan_cache"
    
    id = Column(Integer, primary_key=True, index=True)
    code_hash = Column(String, unique=True, index=True, nullable=False)
    report_text = Column(Text, nullable=False)
    is_fix = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="TimeCodeSecurity Enterprise API")
templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "super_secret_enterprise_key_change_me_in_prod"

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
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == payload.email).first():
            raise HTTPException(status_code=400, detail="Operator ID already registered.")
            
        safe_password = payload.password[:72]
        password_hash = pwd_context.hash(safe_password)
        
        new_user = User(email=payload.email, password_hash=password_hash)
        db.add(new_user)
        db.commit()
    finally:
        db.close()
        
    token = jwt.encode(
        {"sub": payload.email, "exp": datetime.utcnow() + timedelta(hours=2)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"message": "User created", "token": token}

@app.post("/api/login")
async def login(payload: AuthPayload):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == payload.email).first()
        if not user:
            raise HTTPException(status_code=401, detail="Please create account first")
        if not pwd_context.verify(payload.password[:72], user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid password")
    finally:
        db.close()
        
    token = jwt.encode(
        {"sub": payload.email, "exp": datetime.utcnow() + timedelta(hours=2)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"message": "Login successful", "token": token}

class UpgradePayload(BaseModel):
    key: str

class ReportPayload(BaseModel):
    report_text: str

async def get_current_user_email(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    
    if token.startswith("tcs_"):
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.api_key == token).first()
            if not user:
                raise HTTPException(status_code=401, detail="Invalid API Key")
            return user.email
        finally:
            db.close()
            
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/api/me")
async def get_me(authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"email": user.email, "is_premium": user.is_premium, "scan_count": user.scan_count, "api_key": user.api_key, "webhook_url": user.webhook_url}
    finally:
        db.close()

class SettingsPayload(BaseModel):
    webhook_url: str

@app.post("/api/settings")
async def update_settings(payload: SettingsPayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.webhook_url = payload.webhook_url
        db.commit()
        return {"message": "Settings updated"}
    finally:
        db.close()

@app.post("/api/developer-key")
async def generate_api_key(authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.is_premium:
            raise HTTPException(status_code=403, detail="Developer API access is for PRO users only.")
        
        new_key = "tcs_" + secrets.token_hex(20)
        user.api_key = new_key
        db.commit()
        return {"api_key": new_key}
    finally:
        db.close()

@app.post("/api/upgrade")
async def upgrade_plan(payload: UpgradePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    expected_key = os.getenv("PREMIUM_LICENSE_KEY")
    if not expected_key or payload.key != expected_key:
        raise HTTPException(status_code=400, detail="Invalid license key")
        
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.is_premium = True
            db.commit()
            return {"message": "Success"}
    finally:
        db.close()

@app.post("/api/generate-pdf")
async def generate_pdf(payload: ReportPayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.is_premium:
            raise HTTPException(status_code=403, detail="Premium feature only")
    finally:
        db.close()
        
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="TimeCodeSecurity Enterprise Audit Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True, align='C')
    pdf.ln(10)
    
    sanitized_text = payload.report_text.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 10, txt=sanitized_text)
    
    pdf_output = pdf.output(dest='S')
    if isinstance(pdf_output, str):
        pdf_output = pdf_output.encode('latin-1')
    
    return Response(content=pdf_output, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=report.pdf"})

def get_cached_or_generate_ai(payload_code: str, system_prompt: str, is_fix: bool, db):
    code_hash = hashlib.sha256(f"{payload_code}_{is_fix}".encode('utf-8')).hexdigest()
    cached = db.query(ScanCache).filter(ScanCache.code_hash == code_hash, ScanCache.is_fix == is_fix).first()
    if cached:
        return cached.report_text
        
    prompt = f"Code to {'fix' if is_fix else 'analyze'}:\n{payload_code}"
    
    groq_keys_str = os.getenv("GROQ_API_KEYS", "")
    if not groq_keys_str:
        single = os.getenv("GROQ_API_KEY", "")
        groq_keys = [single] if single else []
    else:
        groq_keys = [k.strip() for k in groq_keys_str.split(",") if k.strip()]
        
    url = "https://api.groq.com/openai/v1/chat/completions"
    groq_payload = {
        "model": "openai/gpt-oss-120b", 
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }
    
    ai_reply = None
    last_error = None
    
    for key in groq_keys:
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(url, headers=headers, json=groq_payload)
            if response.status_code == 429:
                last_error = "Rate Limit 429"
                continue
            response.raise_for_status()
            ai_reply = response.json()['choices'][0]['message']['content']
            break
        except Exception as e:
            last_error = str(e)
            continue
            
    if ai_reply is None:
        gemini_keys_str = os.getenv("GEMINI_API_KEYS", "")
        gemini_keys = [k.strip() for k in gemini_keys_str.split(",") if k.strip()]
        for key in gemini_keys:
            try:
                genai.configure(api_key=key)
                model = genai.GenerativeModel('gemini-1.5-flash')
                full_prompt = f"{system_prompt}\n\n{prompt}"
                gemini_response = model.generate_content(full_prompt)
                ai_reply = gemini_response.text
                break
            except Exception as e:
                continue
                
    if ai_reply is None:
        or_keys_str = os.getenv("OPENROUTER_API_KEYS", "")
        or_keys = [k.strip() for k in or_keys_str.split(",") if k.strip()]
        for key in or_keys:
            try:
                client = openai.OpenAI(base_url="https://openrouter.ai/api/v1", api_key=key)
                response = client.chat.completions.create(
                    model="meta-llama/llama-3-8b-instruct",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ]
                )
                ai_reply = response.choices[0].message.content
                break
            except Exception as e:
                continue

    if ai_reply is None:
        cohere_keys_str = os.getenv("COHERE_API_KEYS", "")
        cohere_keys = [k.strip() for k in cohere_keys_str.split(",") if k.strip()]
        for key in cohere_keys:
            try:
                co = cohere.Client(key)
                response = co.chat(
                    message=prompt,
                    preamble=system_prompt,
                    model="command-r"
                )
                ai_reply = response.text
                break
            except Exception as e:
                continue
                
    if ai_reply is None:
        raise HTTPException(status_code=500, detail="All AI core systems are currently overloaded. Please try again in a few minutes.")
            
    new_cache = ScanCache(code_hash=code_hash, report_text=ai_reply, is_fix=is_fix)
    db.add(new_cache)
    db.commit()
    
    return ai_reply

@app.post("/scan")
async def scan_code(payload: CodePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        is_premium = user.is_premium
        scan_count = user.scan_count
        
        if not is_premium and scan_count >= 5:
            raise HTTPException(status_code=403, detail="Free plan limit reached. Please upgrade to Premium.")
            
        if is_premium:
            system_prompt = (
                "You are a highly advanced cybersecurity expert. "
                "You must analyze the provided code for Zero-Day vulnerabilities, "
                "SQL/NoSQL injections, XSS, memory leaks, and architectural flaws. "
                "You must categorize the vulnerabilities by regulatory compliance frameworks (SOC 2, HIPAA, GDPR). "
                "Explicitly state which laws are violated. Also, assign a Severity Level (CRITICAL, HIGH, MEDIUM, LOW). "
                "Provide strict remediation code and a severity score."
            )
        else:
            system_prompt = (
                "You are a basic code analyzer. Identify only simple syntax errors or basic bugs. "
                "You must explicitly state at the end of the response: 'Upgrade to PRO for deep vulnerability analysis and remediation code.'"
            )
    
        try:
            secrets_found = False
            redacted_code = payload.code
            
            if SECRET_PATTERNS["AWS Access Keys"].search(redacted_code):
                secrets_found = True
                redacted_code = SECRET_PATTERNS["AWS Access Keys"].sub("***REDACTED_BY_TIMECODESECURITY***", redacted_code)
                
            if SECRET_PATTERNS["Stripe Secrets"].search(redacted_code):
                secrets_found = True
                redacted_code = SECRET_PATTERNS["Stripe Secrets"].sub("***REDACTED_BY_TIMECODESECURITY***", redacted_code)
                
            def replace_generic(match):
                full_match = match.group(0)
                secret_val = match.group(1)
                return full_match.replace(secret_val, "***REDACTED_BY_TIMECODESECURITY***")
                
            if SECRET_PATTERNS["Generic Tokens"].search(redacted_code):
                secrets_found = True
                redacted_code = SECRET_PATTERNS["Generic Tokens"].sub(replace_generic, redacted_code)

            ai_reply = get_cached_or_generate_ai(redacted_code, system_prompt, is_fix=False, db=db)
            
            if secrets_found:
                ai_reply = "🚨 **CRITICAL SECURITY VIOLATION:** Hardcoded secrets/passwords were detected and successfully redacted before AI analysis to prevent data leakage. \n\n" + ai_reply

            user.scan_count += 1
            
            if user.webhook_url:
                import threading
                def send_webhook(url, text):
                    try:
                        import requests
                        payload = {"content": "🚨 **TimeCodeSecurity Alert** 🚨\n\n**Vulnerability Detected!**\n" + text[:1500]}
                        requests.post(url, json=payload, timeout=5)
                    except:
                        pass
                threading.Thread(target=send_webhook, args=(user.webhook_url, ai_reply)).start()
                
            db.commit()
            return {"result": ai_reply}
        except HTTPException as he:
            raise he
        except Exception as e:
            return {"error": f"API Error: {str(e)}"}
    finally:
        db.close()

@app.post("/api/fix-code")
async def fix_code(payload: CodePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.is_premium:
            raise HTTPException(status_code=403, detail="Premium feature only")
            
        system_prompt = (
            "You are a senior cybersecurity engineer. Fix the provided vulnerable code. "
            "Return ONLY the secure, remediated code inside a markdown code block. Do not include any explanations."
        )
        
        try:
            ai_reply = get_cached_or_generate_ai(payload.code, system_prompt, is_fix=True, db=db)
            return {"fixed_code": ai_reply}
        except HTTPException as he:
            raise he
        except Exception as e:
            return {"error": f"API Error: {str(e)}"}
    finally:
        db.close()

if __name__ == "__main__":
    print("--- Starting TimeCodeSecurity Web Server ---")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
