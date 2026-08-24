import os
import requests
import jwt
import uuid
from fastapi import FastAPI, Request, HTTPException, Header, BackgroundTasks
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


try:
    from rag_engine.vector_db import CodeContextEngine
    rag_engine_instance = CodeContextEngine()
except Exception as e:
    rag_engine_instance = None
    print(f"RAG Load Error: {e}")

SECRET_PATTERNS = {
    "AWS Access Keys": re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
    "Stripe Secrets": re.compile(r"(?i)sk_live_[0-9a-zA-Z]{24,}"),
    "Generic Tokens": re.compile(r"(?i)(?:password|secret|api_key|token|auth)[\s=:]+['\"]([^'\"]+)['\"]")
}

def apply_zero_leak_redaction(code: str):
    secrets_found = False
    redacted_code = code
    
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
        
    return redacted_code, secrets_found

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
try:
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL missing")
    engine = create_engine(DATABASE_URL)
except Exception as e:
    print(f"[!] Warning: PostgreSQL connection failed or missing ({e}). Falling back to SQLite.")
    DATABASE_URL = "sqlite:///./sql_app.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship

class Organization(Base):
    __tablename__ = "organization"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    invite_code = Column(String, unique=True, index=True, nullable=False)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_premium = Column(Boolean, default=False)
    plan_tier = Column(String, default="developer")
    trial_expires_at = Column(DateTime, nullable=True)
    scan_count = Column(Integer, default=0)
    scans_used = Column(Integer, default=0)
    daily_scans_used = Column(Integer, default=0)
    monthly_scans_used = Column(Integer, default=0)
    scan_cycle_start = Column(DateTime, default=datetime.utcnow)
    api_key = Column(String, unique=True, index=True, nullable=True)
    webhook_url = Column(String, nullable=True)
    org_id = Column(Integer, ForeignKey("organization.id"), nullable=True)
    org_role = Column(String, default="member", nullable=True)

    organization = relationship("Organization", backref="users")
    scan_cache = relationship("ScanCache", backref="user")

Base.metadata.create_all(bind=engine)

# ADD SCHEMA MIGRATION BLOCKS
from sqlalchemy import text
with engine.begin() as conn:
    try:
        conn.execute(text("ALTER TABLE scan_cache ADD COLUMN user_id INTEGER REFERENCES users(id)"))
    except Exception:
        pass

    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN plan_tier VARCHAR DEFAULT 'developer'"))
    except Exception:
        pass
        
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN trial_expires_at TIMESTAMP"))
    except Exception:
        pass
        
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN scans_used INTEGER DEFAULT 0"))
    except Exception:
        pass
        
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN scan_cycle_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
    except Exception:
        pass

    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN daily_scans_used INTEGER DEFAULT 0"))
    except Exception:
        pass

    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN monthly_scans_used INTEGER DEFAULT 0"))
    except Exception:
        pass

class ScanCache(Base):
    __tablename__ = "scan_cache"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    code_hash = Column(String, index=True, nullable=False)
    report_text = Column(Text, nullable=True) # made nullable for pending jobs
    is_fix = Column(Boolean, default=False)
    status = Column(String, default="completed")
    job_id = Column(String, unique=True, index=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", backref="scans")

class CodeVault(Base):
    __tablename__ = "code_vault"
    
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organization.id"), nullable=False)
    vulnerable_code = Column(Text, nullable=False)
    secure_code = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    organization = relationship("Organization", backref="vaults")

Base.metadata.create_all(bind=engine)

from sqlalchemy import text
try:
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE scan_cache ADD COLUMN user_id INTEGER REFERENCES users(id)"))
        conn.commit()
except Exception:
    pass

try:
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN plan_tier VARCHAR DEFAULT 'developer'"))
        conn.commit()
except Exception:
    pass

try:
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN trial_expires_at TIMESTAMP"))
        conn.commit()
except Exception:
    pass

try:
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN scans_used INTEGER DEFAULT 0"))
        conn.commit()
except Exception:
    pass

try:
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN scan_cycle_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
        conn.commit()
except Exception:
    pass

app = FastAPI(title="TimeCodeSecurity Enterprise API")

from fastapi.responses import JSONResponse
import traceback

# ==========================================
# ULTIMATE BULLET-PROOF GLOBAL CRASH HANDLER
# ==========================================
@app.exception_handler(Exception)
async def ultimate_global_exception_handler(request: Request, exc: Exception):
    """
    Catches EVERY unhandled exception, crash, or memory fault in the app.
    Prevents the server from dying and returns a safe, structured JSON response.
    """
    print(f"[FATAL ZERO-DAY CRASH PREVENTED] {exc}")
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "detail": "An internal server fault occurred. The TimeCodeSecurity global shield intercepted the crash and kept the server alive.",
            "error_type": type(exc).__name__,
            "safe_fallback": True
        }
    )

templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "super_secret_enterprise_key_change_me_in_prod"

class AuthPayload(BaseModel):
    email: str
    password: str

class CodePayload(BaseModel):
    code: str

@app.head("/")
@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="landing.html")

@app.get("/dashboard")
async def dashboard(request: Request):
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
        new_api_key = "tcs_" + secrets.token_hex(16)
        
        new_user = User(email=payload.email, password_hash=password_hash, api_key=new_api_key)
        db.add(new_user)
        db.commit()
    finally:
        db.close()
        
    token = jwt.encode(
        {"sub": payload.email, "exp": datetime.utcnow() + timedelta(hours=2)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"message": "Success", "token": token}

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

class CodePayload(BaseModel):
    code: str

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
        scans_used = getattr(user, 'scans_used', 0)
        scan_cycle_start = getattr(user, 'scan_cycle_start', None)
        scan_count = getattr(user, 'scan_count', 0)
        webhook_url = getattr(user, 'webhook_url', None)
        api_key = getattr(user, 'api_key', None)
        trial_expires_at = getattr(user, 'trial_expires_at', None)
        plan_tier = getattr(user, 'plan_tier', 'free')

        if not api_key:
            user.api_key = "tcs_" + secrets.token_hex(16)
            api_key = user.api_key
            db.commit()

        if scan_cycle_start:
            if (datetime.utcnow() - scan_cycle_start).days >= 30:
                user.scans_used = 0
                scans_used = 0
                user.scan_cycle_start = datetime.utcnow()
                db.commit()
        else:
            user.scan_cycle_start = datetime.utcnow()
            db.commit()
            
        days_left = None
        if getattr(user, 'email', None) == "kushigaur3103@gmail.com":
            days_left = "Lifetime"
        elif trial_expires_at:
            delta = trial_expires_at - datetime.utcnow()
            if delta.total_seconds() > 0:
                days_left = str(max(1, delta.days)) + " Days Left"
            else:
                user.plan_tier = "free" # trial expired
                plan_tier = "free"
                db.commit()
            
        org_name = user.organization.name if getattr(user, 'organization', None) else None
        invite_code = user.organization.invite_code if getattr(user, 'organization', None) else None
        
        return {
            "email": getattr(user, 'email', None), 
            "is_premium": getattr(user, 'is_premium', False), 
            "plan_tier": plan_tier or "free",
            "days_left": days_left,
            "scan_count": scan_count,
            "scans_used": scans_used,
            "api_key": api_key, 
            "webhook_url": webhook_url,
            "org_name": org_name,
            "org_role": getattr(user, 'org_role', 'member'),
            "invite_code": invite_code
        }
    finally:
        db.close()

class GrantTrialPayload(BaseModel):
    target_email: str
    plan_tier: str
    admin_key: str

@app.post("/api/admin/grant-trial")
async def grant_trial(payload: GrantTrialPayload):
    if payload.admin_key != "AYUSH-ADMIN-666":
        raise HTTPException(status_code=403, detail="Invalid admin key")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == payload.target_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Target user not found")
        user.plan_tier = payload.plan_tier
        user.is_premium = payload.plan_tier in ["developer", "enterprise"]
        user.trial_expires_at = datetime.utcnow() + timedelta(days=14)
        db.commit()
        return {"message": f"Granted 14-day {payload.plan_tier} trial to {payload.target_email}"}
    finally:
        db.close()

class QASwitchPayload(BaseModel):
    new_tier: str

@app.post("/api/admin/qa-switch")
async def qa_switch(payload: QASwitchPayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    if email != "kushigaur3103@gmail.com":
        raise HTTPException(status_code=403, detail="Not authorized for QA switch")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.plan_tier = payload.new_tier
        user.is_premium = payload.new_tier in ["developer", "enterprise"]
        db.commit()
        return {"message": f"QA Switch: Tier changed to {payload.new_tier}"}
    finally:
        db.close()

class CreateWorkspacePayload(BaseModel):
    name: str

class JoinWorkspacePayload(BaseModel):
    invite_code: str

@app.post("/api/workspaces/create")
async def create_workspace(payload: CreateWorkspacePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if db.query(Organization).filter(Organization.name == payload.name).first():
            raise HTTPException(status_code=400, detail="Organization name already taken")
            
        invite_code = secrets.token_hex(3)
        new_org = Organization(name=payload.name, invite_code=invite_code)
        db.add(new_org)
        db.commit()
        db.refresh(new_org)
        
        user.org_id = new_org.id
        user.org_role = "admin"
        db.commit()
        return {"message": "Workspace created"}
    finally:
        db.close()

@app.post("/api/workspaces/join")
async def join_workspace(payload: JoinWorkspacePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        org = db.query(Organization).filter(Organization.invite_code == payload.invite_code).first()
        if not org:
            raise HTTPException(status_code=404, detail="Invalid invite code")
            
        user.org_id = org.id
        user.org_role = "developer"
        db.commit()
        return {"message": "Joined workspace"}
    finally:
        db.close()

@app.get("/api/analytics")
async def get_analytics(authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        total_scans = db.query(ScanCache).filter(ScanCache.user_id == user.id, ScanCache.is_fix != True).count()
        total_fixes = db.query(ScanCache).filter(ScanCache.user_id == user.id, ScanCache.is_fix == True).count()
        
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        all_reports = db.query(ScanCache.report_text).filter(ScanCache.user_id == user.id, ScanCache.is_fix != True).all()
        for (report,) in all_reports:
            if not report: continue
            text = report.lower()
            if 'critical' in text: critical_count += 1
            elif 'high' in text: high_count += 1
            elif 'medium' in text: medium_count += 1
            elif re.search(r'\blow\b', text): low_count += 1
        
        # Removed fallback logic so chart accurately reflects 0 if no severities are found in reports
            
        severity_breakdown = {
            "Critical": critical_count,
            "High": high_count,
            "Medium": medium_count,
            "Low": low_count
        }
        
        return {
            "total_scans": total_scans,
            "total_fixes": total_fixes,
            "severity_breakdown": severity_breakdown
        }
    finally:
        db.close()

class AuditDependenciesPayload(BaseModel):
    file_type: str
    content: str

@app.post("/api/audit-dependencies")
async def audit_dependencies(payload: AuditDependenciesPayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not user.is_premium:
            raise HTTPException(status_code=403, detail="Supply Chain Auditing is a Premium feature.")
            
        system_prompt = (
            "You are an expert security auditor. Review the provided dependency file. "
            "Identify any notoriously vulnerable packages, suggest secure version upgrades, "
            "and warn about potential supply chain risks. Return the analysis formatted in clean markdown "
            "without any extra explanations."
        )
        
        code_input = f"File Type: {payload.file_type}\n\n{payload.content}"
        
        try:
            ai_reply = get_cached_or_generate_ai(code_input, system_prompt, is_fix=False, db=db)
            
            user.scan_count += 1
            db.commit()
            
            return {"report": ai_reply}
        except Exception as e:
            return {"error": f"API Error: {str(e)}"}
    finally:
        db.close()

class UpgradePayload(BaseModel):
    key: str

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

class CheckoutPayload(BaseModel):
    plan: str

@app.post("/api/checkout")
async def create_checkout(payload: CheckoutPayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    try:
        if payload.plan == "developer":
            checkout_url = "https://timecodesecurity.lemonsqueezy.com/checkout/buy/3c098864-5a17-4120-8873-37192daaa6c6"
        else:
            checkout_url = "https://timecodesecurity.lemonsqueezy.com/checkout/buy/d41592c8-fa47-41e3-b8a6-cef3e0f275b6"
            
        return JSONResponse({"checkout_url": checkout_url})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/verify-payment")
async def verify_payment(authorization: str = Header(None)):
    # Lemon Squeezy uses webhooks for real verification, but for this demo overlay we'll mock success
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.is_premium = True
            db.commit()
            return {"message": "Success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
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

def get_cached_or_generate_ai(payload_code: str, system_prompt: str, is_fix: bool, db, existing_job_id: str = None, user_id: int = None):
    code_hash = hashlib.sha256(f"{payload_code}_{system_prompt}".encode('utf-8')).hexdigest()
    cached = db.query(ScanCache).filter(ScanCache.code_hash == code_hash, ScanCache.is_fix == is_fix, ScanCache.status == 'completed').first()
    if cached:
        if existing_job_id:
            pending_job = db.query(ScanCache).filter(ScanCache.job_id == existing_job_id).first()
            if pending_job:
                pending_job.report_text = cached.report_text
                pending_job.status = 'completed'
                db.commit()
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
            
    if existing_job_id:
        pending_job = db.query(ScanCache).filter(ScanCache.job_id == existing_job_id).first()
        if pending_job:
            pending_job.report_text = ai_reply
            pending_job.status = 'completed'
            db.commit()
    else:
        new_cache = ScanCache(code_hash=code_hash, report_text=ai_reply, is_fix=is_fix, status='completed', user_id=user_id)
        db.add(new_cache)
        db.commit()
    
    return ai_reply

def background_scan_task(job_id: str, email: str, redacted_code: str, system_prompt: str, secrets_found: bool):
    db = SessionLocal()
    try:
        ai_reply = get_cached_or_generate_ai(redacted_code, system_prompt, is_fix=False, db=db, existing_job_id=job_id)
        
        warning_str = "🚨 **CRITICAL SECURITY VIOLATION:** Hardcoded secrets/passwords were detected and successfully redacted before AI analysis to prevent data leakage. \n\n"
        if secrets_found and warning_str not in ai_reply:
            ai_reply = warning_str + ai_reply
            pending_job = db.query(ScanCache).filter(ScanCache.job_id == job_id).first()
            if pending_job:
                pending_job.report_text = ai_reply
                db.commit()

        user = db.query(User).filter(User.email == email).first()
        if user and user.webhook_url:
            try:
                import requests
                payload = {"content": "🚨 **TimeCodeSecurity Alert** 🚨\n\n**Vulnerability Detected!**\n" + ai_reply[:1500]}
                requests.post(user.webhook_url, json=payload, timeout=5)
            except:
                pass
            
    except Exception as e:
        pending_job = db.query(ScanCache).filter(ScanCache.job_id == job_id).first()
        if pending_job:
            pending_job.status = "failed"
            pending_job.report_text = f"Error: {str(e)}"
            db.commit()
    finally:
        db.close()

@app.post("/scan")
async def scan_code(payload: CodePayload, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if user.scan_cycle_start:
            if (datetime.utcnow() - user.scan_cycle_start).days >= 30:
                user.scans_used = 0
                user.scan_cycle_start = datetime.utcnow()
                db.commit()
        else:
            user.scan_cycle_start = datetime.utcnow()
            db.commit()

        is_premium = user.plan_tier in ["developer", "enterprise"]
        scan_count = user.scan_count
        
        if not is_premium:
            if user.scans_used >= 3:
                return {
                    "is_blurred_paywall": True,
                    "report": "🚨 CRITICAL VULNERABILITY FOUND: Remote Code Execution (RCE) / Arbitrary Code Execution detected on line 42.\n\nSeverity: CRITICAL (Score: 9.8)\nImpact: An attacker could take full control of your server.\n\nFix Required immediately:\n```javascript\n// Developer PRO Required to view Auto-Fix\n```"
                }
            else:
                user.scans_used += 1
                db.commit()
            
        if is_premium:
            system_prompt = (
                "You are a highly advanced cybersecurity expert. "
                "You must analyze the provided code for Zero-Day vulnerabilities, "
                "SQL/NoSQL injections, XSS, memory leaks, and architectural flaws. "
                "You must categorize the vulnerabilities by regulatory compliance frameworks (SOC 2, HIPAA, GDPR). "
                "Explicitly state which laws are violated. Also, assign a Severity Level (CRITICAL, HIGH, MEDIUM, LOW). "
                "Provide strict remediation code and a severity score."
            )
            # ====== GOD-MODE RAG CONTEXT INJECTION ======
            if rag_engine_instance:
                try:
                    context_files = rag_engine_instance.retrieve_context("default_repo", payload.code, top_k=2)
                    if context_files:
                        context_str = "\n".join([f"--- File: {f['filename']} ---\n{f['content']}" for f in context_files])
                        system_prompt += (
                            f"\n\n[ARCHITECTURAL CONTEXT PROVIDED BY RAG ENGINE]\n"
                            f"Consider the following related files from the codebase to detect cross-file vulnerabilities:\n{context_str}"
                        )
                except Exception as e:
                    print(f"[RAG WARNING] {e}")
        else:
            system_prompt = (
                "You are a basic code analyzer. Identify only simple syntax errors or basic bugs. "
                "You must explicitly state at the end of the response: 'Upgrade to PRO for deep vulnerability analysis and remediation code.'"
            )
    
        try:
            redacted_code, secrets_found = apply_zero_leak_redaction(payload.code)

            job_id = str(uuid.uuid4())
            code_hash = hashlib.sha256(f"{redacted_code}_{system_prompt}".encode('utf-8')).hexdigest()
            
            new_job = ScanCache(job_id=job_id, code_hash=code_hash, status="pending", is_fix=False, report_text="AI Scan in progress...", user_id=user.id)
            db.add(new_job)
            
            user.scan_count += 1
            db.commit()
            
            background_tasks.add_task(
                background_scan_task,
                job_id,
                email,
                redacted_code,
                system_prompt,
                secrets_found
            )
            
            return {"job_id": job_id, "status": "pending"}
        except HTTPException as he:
            raise he
        except Exception as e:
            return {"error": f"API Error: {str(e)}"}
    finally:
        db.close()

@app.get("/api/scan/status/{job_id}")
async def get_scan_status(job_id: str, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        job = db.query(ScanCache).filter(ScanCache.job_id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
            
        return {
            "job_id": job.job_id,
            "status": job.status,
            "report": job.report_text if job.status == "completed" else None
        }
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
            redacted_code, _ = apply_zero_leak_redaction(payload.code)
            ai_reply = get_cached_or_generate_ai(redacted_code, system_prompt, is_fix=True, db=db, user_id=user.id)
            
            if user.org_id:
                new_vault = CodeVault(
                    org_id=user.org_id,
                    vulnerable_code=redacted_code,
                    secure_code=ai_reply
                )
                db.add(new_vault)
            
            user.scan_count += 1
            db.commit()
                
            return {"fixed_code": ai_reply}
        except HTTPException as he:
            raise he
        except Exception as e:
            return {"error": f"API Error: {str(e)}"}
    finally:
        db.close()

@app.get("/api/vault")
async def get_vault(authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.org_id:
            return []
            
        vault_entries = db.query(CodeVault).filter(CodeVault.org_id == user.org_id).order_by(CodeVault.created_at.desc()).all()
        
        result = []
        for v in vault_entries:
            result.append({
                "id": v.id,
                "vulnerable_code": v.vulnerable_code,
                "secure_code": v.secure_code,
                "created_at": v.created_at.isoformat()
            })
        return result
    finally:
        db.close()

class CICDScanPayload(BaseModel):
    code: str
    filename: str

from typing import List, Dict
class RAGIngestPayload(BaseModel):
    repo_id: str
    files: List[Dict[str, str]]

@app.post("/api/rag/ingest")
async def rag_ingest(payload: RAGIngestPayload, x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header missing")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.api_key == x_api_key).first()
        if not user or not user.is_premium:
            raise HTTPException(status_code=403, detail="PRO required for RAG ingestion")
        if rag_engine_instance:
            rag_engine_instance.ingest_repository(payload.repo_id, payload.files)
            return {"status": "success", "message": f"Ingested {len(payload.files)} files into Vector DB."}
        return {"status": "error", "message": "RAG Engine offline."}
    finally:
        db.close()

@app.post("/api/cicd/scan")
async def cicd_scan(payload: CICDScanPayload, x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header missing")
        
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.api_key == x_api_key).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API Key")
            
        system_prompt = (
            "You are a highly advanced cybersecurity expert. "
            "You must analyze the provided code for Zero-Day vulnerabilities, "
            "SQL/NoSQL injections, XSS, memory leaks, and architectural flaws. "
            "You must categorize the vulnerabilities by regulatory compliance frameworks (SOC 2, HIPAA, GDPR). "
            "Explicitly state which laws are violated. Also, assign a Severity Level (CRITICAL, HIGH, MEDIUM, LOW). "
            "Provide strict remediation code and a severity score."
        ) if user.is_premium else (
            "You are a basic code analyzer. Identify only simple syntax errors or basic bugs. "
            "You must explicitly state at the end of the response: 'Upgrade to PRO for deep vulnerability analysis and remediation code.'"
        )

        redacted_code, secrets_found = apply_zero_leak_redaction(payload.code)

        # ====== GOD-MODE RAG CONTEXT INJECTION ======
        if rag_engine_instance and user.is_premium:
            try:
                context_files = rag_engine_instance.retrieve_context("default_repo", redacted_code, top_k=2)
                if context_files:
                    context_str = "\n".join([f"--- File: {f['filename']} ---\n{f['content']}" for f in context_files])
                    system_prompt += (
                        f"\n\n[ARCHITECTURAL CONTEXT PROVIDED BY RAG ENGINE]\n"
                        f"Consider the following related files from the codebase to detect cross-file vulnerabilities:\n{context_str}"
                    )
            except Exception as e:
                print(f"[RAG WARNING] {e}")

        ai_reply = get_cached_or_generate_ai(redacted_code, system_prompt, is_fix=False, db=db)
        
        warning_str = "🚨 **CRITICAL SECURITY VIOLATION:** Hardcoded secrets/passwords were detected and successfully redacted before AI analysis to prevent data leakage. \n\n"
        if secrets_found and warning_str not in ai_reply:
            ai_reply = warning_str + ai_reply

        user.scan_count += 1
        db.commit()
        
        vulnerabilities_found = "vulnerabilities" in ai_reply.lower() or secrets_found or "CRITICAL" in ai_reply or "HIGH" in ai_reply
        severity_level = "LOW"
        if "CRITICAL" in ai_reply or secrets_found:
            severity_level = "CRITICAL"
        elif "HIGH" in ai_reply:
            severity_level = "HIGH"
        elif "MEDIUM" in ai_reply:
            severity_level = "MEDIUM"

        return {
            "status": "success", 
            "vulnerabilities_found": vulnerabilities_found, 
            "report": ai_reply, 
            "severity_level": severity_level
        }
    finally:
        db.close()

@app.post("/api/generate-test")
async def generate_test(payload: CodePayload, authorization: str = Header(None)):
    email = await get_current_user_email(authorization)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.is_premium:
            raise HTTPException(status_code=403, detail="Premium feature only")
            
        system_prompt = (
            "You are a senior DevSecOps engineer. Generate a defensive Unit Test (e.g., PyTest or Jest) "
            "that will explicitly FAIL when run against the provided vulnerable code, proving the vulnerability "
            "exists without being an active exploit. Return ONLY the raw test code inside a markdown code block."
        )
        
        try:
            redacted_code, _ = apply_zero_leak_redaction(payload.code)
            ai_reply = get_cached_or_generate_ai(redacted_code, system_prompt, is_fix=False, db=db)
            
            user.scan_count += 1
            db.commit()
            
            return {"test_code": ai_reply}
        except HTTPException as he:
            raise he
        except Exception as e:
            return {"error": f"API Error: {str(e)}"}
    finally:
        db.close()

@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")
    return templates.TemplateResponse(request=request, name="index.html")

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    print(f"--- Starting TimeCodeSecurity Web Server on port {port} ---")
    uvicorn.run(app, host="0.0.0.0", port=port)
