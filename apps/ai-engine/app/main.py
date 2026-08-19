from fastapi import FastAPI, Depends
from pydantic import BaseModel
from typing import List
from sqlalchemy.orm import Session
import os
import logging
import asyncio
import itertools
from dotenv import load_dotenv

from langchain_groq import ChatGroq
from langchain.prompts import PromptTemplate

from . import models
from .database import engine, get_db

# Load environment variables
load_dotenv()
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI-Powered Self-Healing Engine")
logging.basicConfig(level=logging.INFO)

# --- LangChain & LLM Setup ---
llm_rotator = None

try:
    groq_keys_str = os.getenv("GROQ_API_KEYS", "")
    if groq_keys_str:
        keys = [k.strip() for k in groq_keys_str.split(",") if k.strip()]
        llms = []
        for key in keys:
            llms.append(ChatGroq(model_name="openai/gpt-oss-120b", temperature=0.1, api_key=key))
        if llms:
            llm_rotator = itertools.cycle(llms)
            logging.info(f"Initialized Round-Robin LLM Rotator with {len(llms)} keys.")
        else:
            logging.error("GROQ_API_KEYS provided but no valid keys found.")
    else:
        # Fallback to single key if only GROQ_API_KEY is provided
        single_key = os.getenv("GROQ_API_KEY")
        if single_key:
            llms = [ChatGroq(model_name="openai/gpt-oss-120b", temperature=0.1, api_key=single_key)]
            llm_rotator = itertools.cycle(llms)
            logging.info("Initialized LLM with 1 key.")
except Exception as e:
    logging.error(f"Failed to initialize LLM rotator: {e}")
    llm_rotator = None

patch_prompt = PromptTemplate(
    input_variables=["vulnerability_type", "code_snippet"],
    template=(
        "You are an expert security engineer. "
        "The following JavaScript/TypeScript code has a vulnerability of type '{vulnerability_type}':\n"
        "{code_snippet}\n\n"
        "Please provide the corrected, secure version of this code.\n"
        "CRITICAL CONSTRAINT: Output ONLY the raw corrected code string. Do not include markdown formatting, "
        "do not use ```javascript blocks, and do not provide any explanations. Just the code."
    )
)

# --- Pydantic Models ---

class SecurityHotspot(BaseModel):
    node_type: str
    code_snippet: str
    start_line: int
    end_line: int
    risk_level: str

class ScanResult(BaseModel):
    status: str
    file_name: str
    hotspots: List[SecurityHotspot]

class SuggestedPatch(BaseModel):
    hotspot_index: int
    original_code: str
    suggested_code: str
    explanation: str

class AnalysisResponse(BaseModel):
    original_hotspots: List[SecurityHotspot]
    suggested_patches: List[SuggestedPatch]

class EnterpriseAnalyzeRequest(BaseModel):
    code_snippet: str
    vulnerability_type: str = "Unknown Vulnerability"
    zero_retention: bool = False

class EnterpriseAnalyzeResponse(BaseModel):
    original_code: str
    fixed_code: str | None
    status: str
    message: str

@app.get('/')
def read_root():
    return {'status': 'AI Engine Running'}

async def generate_patch_concurrently(index: int, hotspot: SecurityHotspot):
    if not llm_rotator:
        return None, index, hotspot, "LLM Engine is offline. Missing API Key.", "Pending"

    # Pick the next LLM in the rotation perfectly safely
    llm = next(llm_rotator)
    
    prompt_text = patch_prompt.format(
        vulnerability_type=hotspot.node_type,
        code_snippet=hotspot.code_snippet
    )
    
    try:
        response = await llm.ainvoke(prompt_text)
        fixed_code = response.content.strip()
        return fixed_code, index, hotspot, "AI Patch successfully generated.", "Auto-Healed"
    except Exception as e:
        error_msg = str(e)
        logging.error(f"LLM Generation failed for hotspot {index}: {error_msg}")
        
        # Check for Groq 429 rate limit
        if "429" in error_msg or "rate limit" in error_msg.lower():
            return None, index, hotspot, "Groq API Rate Limit Exceeded.", "Rate Limit Exceeded - Pending"
            
        return None, index, hotspot, "LLM Generation failed due to an API error.", "Pending"

@app.post('/analyze', response_model=AnalysisResponse)
async def analyze_code_hotspots(payload: ScanResult, db: Session = Depends(get_db)):
    patches = []

    # 1. Fan out LLM requests concurrently
    tasks = [generate_patch_concurrently(i, h) for i, h in enumerate(payload.hotspots)]
    results = await asyncio.gather(*tasks)

    # 2. Process results and synchronize to Postgres
    for fixed_code, index, hotspot, explanation, status in results:
        
        if fixed_code:
            patches.append(SuggestedPatch(
                hotspot_index=index,
                original_code=hotspot.code_snippet,
                suggested_code=fixed_code,
                explanation=explanation
            ))

        new_scan = models.Scan(
            fileName=payload.file_name,
            vulnerabilityType=hotspot.node_type,
            riskLevel=hotspot.risk_level,
            status=status
        )
        db.add(new_scan)
        
    try:
        db.commit()
    except Exception as e:
        logging.error(f"Database commit failed: {e}")
        db.rollback()

    return AnalysisResponse(
        original_hotspots=payload.hotspots,
        suggested_patches=patches
    )

@app.post('/enterprise/analyze', response_model=EnterpriseAnalyzeResponse)
async def enterprise_analyze(payload: EnterpriseAnalyzeRequest, db: Session = Depends(get_db)):
    if not llm_rotator:
        return EnterpriseAnalyzeResponse(
            original_code=payload.code_snippet,
            fixed_code=None,
            status="Error",
            message="LLM Engine is offline. Missing API Key."
        )

    llm = next(llm_rotator)
    prompt_text = patch_prompt.format(
        vulnerability_type=payload.vulnerability_type,
        code_snippet=payload.code_snippet
    )
    
    fixed_code = None
    status = "Pending"
    message = ""
    
    try:
        response = await llm.ainvoke(prompt_text)
        fixed_code = response.content.strip()
        status = "Auto-Healed"
        message = "AI Patch successfully generated in memory."
    except Exception as e:
        error_msg = str(e)
        logging.error(f"Enterprise LLM Generation failed: {error_msg}")
        if "429" in error_msg or "rate limit" in error_msg.lower():
            status = "Rate Limit Exceeded"
            message = "Groq API Rate Limit Exceeded."
        else:
            status = "Error"
            message = "LLM Generation failed due to an API error."

    # Zero Retention Logic for SOC2 Compliance
    if not payload.zero_retention:
        new_scan = models.Scan(
            fileName="Enterprise_API_Payload",
            vulnerabilityType=payload.vulnerability_type,
            riskLevel="Critical",
            status=status
        )
        db.add(new_scan)
        try:
            db.commit()
        except Exception as e:
            logging.error(f"Database commit failed: {e}")
            db.rollback()
    else:
        message += " (SOC2 Compliant: Zero Data Retention Enforced. No database records created.)"

    return EnterpriseAnalyzeResponse(
        original_code=payload.code_snippet,
        fixed_code=fixed_code,
        status=status,
        message=message
    )
