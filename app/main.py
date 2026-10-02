from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import hashlib
import torch
import os
from l2_ai_engine.ingestion.ast_parser import parse_solidity_code
from l2_ai_engine.models.dual_modal_net import DualModalVulnNet

app = FastAPI(
    title="SecureAI / VulnNet Gateway",
    description="EVM Smart Contract Vulnerability Detection API",
    version="1.0.0"
)

# Load PyTorch Model Instance
model = DualModalVulnNet(use_bert_backbone=False)
checkpoint_path = "l2_ai_engine/models/checkpoints/vulnnet_dbn.pt"

if os.path.exists(checkpoint_path):
    model.load_state_dict(torch.load(checkpoint_path, map_location=torch.device('cpu')))
    print("✅ PyTorch Dual-Modal Model Weights Loaded.")
else:
    print("⚠️️ Checkpoint not found. Run train_quick.py first.")

model.eval()

# Vocabulary mapping for standard EVM OpCodes to Token IDs
OPCODE_VOCAB = {"PUSH1": 1, "PUSH2": 2, "MSTORE": 3, "CALL": 4, "CALLVALUE": 5, "SSTORE": 6, "SLOAD": 7, "JUMPDEST": 8, "REVERT": 9}

class AuditRequest(BaseModel):
    contract_name: str
    source_code: str

class AuditResponse(BaseModel):
    status: str
    contract_name: str
    contract_hash: str
    opcode_count: int
    risk_score: float
    risk_level: str
    is_flagged: bool

@app.post("/api/v1/audit", response_model=AuditResponse)
def run_audit(payload: AuditRequest):
    # 1. Extract AST and OpCodes
    parsed_data = parse_solidity_code(payload.source_code, payload.contract_name)
    if parsed_data["status"] == "error":
        raise HTTPException(status_code=400, detail=parsed_data["message"])

    opcodes = parsed_data.get("opcodes", [])
    
    # 2. Tokenize OpCodes into Tensor sequence
    token_ids = [OPCODE_VOCAB.get(op, 10) for op in opcodes[:64]] # Pad/Truncate to 64 tokens
    while len(token_ids) < 64:
        token_ids.append(0)
    
    input_tensor = torch.tensor([token_ids], dtype=torch.long)

    # 3. Perform PyTorch Model Inference
    with torch.no_grad():
        predicted_prob = model(input_tensor).item()

    risk_score = round(predicted_prob * 100.0, 2)
    risk_level = "HIGH" if risk_score >= 80.0 else ("MEDIUM" if risk_score >= 50.0 else "LOW")
    is_flagged = risk_score >= 80.0

    contract_hash = "0x" + hashlib.sha256(payload.source_code.encode()).hexdigest()

    return AuditResponse(
        status="success",
        contract_name=payload.contract_name,
        contract_hash=contract_hash,
        opcode_count=len(opcodes),
        risk_score=risk_score,
        risk_level=risk_level,
        is_flagged=is_flagged
    )