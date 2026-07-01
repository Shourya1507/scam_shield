import os
import hashlib
import hmac
import sys

# Ensure Vercel can find the modules in the root directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv

# Load environment variables (Vercel will inject these automatically in production, but good for testing)
load_dotenv()

from agents.guardian_agent import GuardianAgent

app = FastAPI(title="ScamShield API - Vercel Serverless")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

guardian = GuardianAgent(guardian_contact=os.getenv("GUARDIAN_DEFAULT_CONTACT", "+1-555-0100"))
secret = os.getenv("WEBHOOK_SECRET", "")

class ScanRequest(BaseModel):
    user_id: str = "webhook-anon"
    input_type: str = "email"
    text: str
    sender: Optional[str] = None

@app.get("/api/health")
@app.get("/health")
@app.get("/healthz")
async def health_check():
    return {"status": "healthy", "environment": "vercel"}

@app.post("/api/scan")
@app.post("/webhook")
async def scan(request: ScanRequest, req: Request):
    # Optional HMAC verification if WEBHOOK_SECRET is set (only for /webhook, not UI)
    if secret and req.url.path.endswith("/webhook"):
        body = await req.body()
        sig = req.headers.get("X-ScamShield-Signature", "")
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(status_code=403, detail="invalid_signature")

    valid_types = {"call", "email", "financial"}
    if request.input_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid input_type. Must be one of {valid_types}")

    try:
        return guardian.process(
            user_id=request.user_id,
            input_type=request.input_type,
            text=request.text,
            sender=request.sender
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
