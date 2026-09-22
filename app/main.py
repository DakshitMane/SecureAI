from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="SecureAI / VulnNet Gateway",
    description="L2 Deep Learning Pipeline for Smart Contract Vulnerability Detection",
    version="1.0.0"
)

class AuditRequest(BaseModel):
    contract_name: str
    source_code: str

class AuditResponse(BaseModel):
    contract_name: str
    vulnerability_score: float
    risk_level: str
    flagged: bool

@app.get("/")
def health_check():
    return {"status": "online", "system": "SecureAI-L2-Gateway"}

@app.post("/api/v1/audit", response_model=AuditResponse)
def audit_contract(payload: AuditRequest):
    if not payload.source_code.strip():
        raise HTTPException(status_code=400, detail="Source code cannot be empty.")
    
    # Placeholder inference logic (Walking Skeleton)
    # Will be replaced with GraphCodeBERT + Bi-LSTM + DBN fusion
    dummy_score = 42.5  
    risk = "MEDIUM" if dummy_score > 40 else "LOW"
    
    return AuditResponse(
        contract_name=payload.contract_name,
        vulnerability_score=dummy_score,
        risk_level=risk,
        flagged=dummy_score >= 80.0
    )