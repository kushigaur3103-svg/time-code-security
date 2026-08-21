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

from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

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
        if not user or not pwd_context.verify(payload.password[:72], user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials. Access Denied.")
    finally:
        db.close()
        
    token = jwt.encode(
        {"sub": payload.email, "exp": datetime.utcnow() + timedelta(hours=2)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"message": "Login successful", "token": token}

class UpgradePayload(BaseModel):
    license_key: str

class ReportPayload(BaseModel):
    report_text: str

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
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"email": user.email, "is_premium": user.is_premium, "scan_count": user.scan_count}
    finally:
        db.close()

@app.post("/api/upgrade")
async def upgrade_plan(payload: UpgradePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    expected_key = os.getenv("PREMIUM_LICENSE_KEY")
    if not expected_key or payload.license_key != expected_key:
        raise HTTPException(status_code=400, detail="Invalid License Key")
        
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.is_premium = True
            db.commit()
    finally:
        db.close()
    return {"message": "License accepted. Premium unlocked."}

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
        
        if is_premium:
            system_prompt = (
                "You are a highly advanced cybersecurity expert. "
                "You must analyze the provided code for Zero-Day vulnerabilities, "
                "SQL/NoSQL injections, XSS, memory leaks, and architectural flaws, "
                "providing strict remediation code and a severity score."
            )
        else:
            system_prompt = (
                "You are a basic code analyzer. Identify only simple syntax errors or basic bugs. "
                "You must explicitly state at the end of the response: 'Upgrade to PRO for deep vulnerability analysis and remediation code.'"
            )
    
        prompt = f"Code to analyze:\n{payload.code}"
        
        groq_payload = {
            "model": "openai/gpt-oss-120b", 
            "messages": [
                {"role": "system", "content": system_prompt},
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
            user.scan_count += 1
            db.commit()
            
            return {"result": ai_reply}
        except Exception as e:
            error_msg = f"API Error: {str(e)}"
            if 'response' in locals() and response is not None:
                try:
                    error_msg += f" - Details: {response.json().get('error', {}).get('message', response.text)}"
                except:
                    error_msg += f" - Details: {response.text}"
            return {"error": error_msg}
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
        
        system_prompt = (
            "You are a senior cybersecurity engineer. Fix the provided vulnerable code. "
            "Return ONLY the secure, remediated code inside a markdown code block. Do not include any explanations."
        )
        prompt = f"Code to fix:\n{payload.code}"
        
        groq_payload = {
            "model": "openai/gpt-oss-120b", 
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1
        }
        
        try:
            response = requests.post(url, headers=headers, json=groq_payload)
            response.raise_for_status()
            result = response.json()
            ai_reply = result['choices'][0]['message']['content']
            return {"fixed_code": ai_reply}
        except Exception as e:
            error_msg = f"API Error: {str(e)}"
            if 'response' in locals() and response is not None:
                try:
                    error_msg += f" - Details: {response.json().get('error', {}).get('message', response.text)}"
                except:
                    error_msg += f" - Details: {response.text}"
            return {"error": error_msg}
    finally:
        db.close()

if __name__ == "__main__":
    print("--- Starting TimeCodeSecurity Web Server ---")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
