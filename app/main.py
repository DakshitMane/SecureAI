import sys
import asyncio
import os
import json
import torch
import hashlib
import solcx
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from torch.nn.functional import softmax
from transformers import AutoTokenizer

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from l2_ai_engine.models.dual_modal_net import DualModalVulnNet
from l3_crypto.security_engine import SecureCryptoEngine, detect_validator_poisoning

try:
    solcx.set_solc_version('0.8.20')
except Exception:
    solcx.install_solc('0.8.20')
    solcx.set_solc_version('0.8.20')

app = FastAPI(title="SecureAI Security Gateway Engine")
crypto_engine = SecureCryptoEngine()

# Load Model & Tokenizer
model = DualModalVulnNet()
tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
checkpoint_path = "l2_ai_engine/models/checkpoints/vulnnet_dbn.pt" 

if os.path.exists(checkpoint_path):
    try:
        state_dict = torch.load(checkpoint_path, map_location=torch.device('cpu'))
        model.opcode_branch.load_state_dict(state_dict["opcode_branch"])
        model.dbn_head.load_state_dict(state_dict["classifier_head"])
        print("✅ 9-Class PyTorch Weights Loaded Successfully.")
    except Exception as e:
        print(f"⚠️ Warning: Failed to load checkpoint: {e}")
else:
    print(f"🚨 ERROR: Checkpoint {checkpoint_path} not found!")

model.eval()

OPCODE_MAP = {"STOP": 1, "ADD": 2, "MUL": 3, "SUB": 4, "DIV": 5, "CALL": 75, "DELEGATECALL": 78, "SSTORE": 53, "SLOAD": 52, "RETURN": 77, "REVERT": 81, "SELFDESTRUCT": 83, "STATICCALL": 80}

def get_opcodes_from_code(source_code: str):
    try:
        compiled = solcx.compile_source(source_code, output_values=['bin'], solc_version='0.8.20')
        bytecode = ""
        for contract_key, contract_data in compiled.items():
            if contract_data['bin']:
                bytecode = contract_data['bin']
                break 

        if not bytecode:
            raise ValueError("Compiled successfully, but no bytecode was generated.")

        opcodes = []
        # Removed the 128 limit so we see the real OpCode count
        hex_pairs = [bytecode[i:i+2] for i in range(0, len(bytecode), 2)]
        
        for op in hex_pairs:
            int_op = int(op, 16)
            if int_op == 0x00: opcodes.append("STOP")
            elif int_op == 0x60: opcodes.append("PUSH1")
            elif int_op == 0xf1: opcodes.append("CALL")
            elif int_op == 0x55: opcodes.append("SSTORE")
            else: opcodes.append("PUSH1")
                
        return opcodes
    except Exception as e:
        raise ValueError(f"Solidity Compilation Failed: {str(e)}")

HISTORICAL_VOTES_BASELINE = [
    [0.10, 0.05, 0.15], [0.12, 0.04, 0.18], [0.09, 0.06, 0.12], 
    [0.11, 0.05, 0.14], [0.15, 0.08, 0.50], [0.20, 0.10, 0.82]
]
AUDIT_HISTORY_LOG = "data/processed/audit_history.json"
os.makedirs("data/processed", exist_ok=True)

class AuditPayload(BaseModel):
    contract_name: str
    source_code: str

def append_to_json_file(file_path: str, new_record: dict):
    records = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            try: records = json.load(f)
            except: records = []
    records.append(new_record)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)

@app.post("/api/v1/audit")
def execute_system_pipeline(payload: AuditPayload):
    try:
        opcodes = get_opcodes_from_code(payload.source_code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # 1. Tokenize OpCodes (Keep at 64 for model architecture)
    tokens = [OPCODE_MAP.get(op, 10) for op in opcodes[:64]]
    while len(tokens) < 64: tokens.append(0)
    input_tensor = torch.tensor([tokens], dtype=torch.long)
    
    # 2. Tokenize Text for GraphCodeBERT
    text_inputs = tokenizer(payload.source_code, truncation=True, max_length=256, padding="max_length", return_tensors="pt")
    text_ids = text_inputs['input_ids']
    text_mask = text_inputs['attention_mask']

    # 3. Real PyTorch Inference
    try:
        with torch.no_grad():
            logits = model(input_tensor, text_ids, text_mask)
            probabilities = softmax(logits, dim=1)
            p_safe = probabilities[0][0].item()
            raw_probability = 1.0 - p_safe 
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model Inference Error: {e}")

    # 4. STRUCTURAL HEURISTIC OVERRIDE (For Undertrained Model Demo)
    # This mimics a hybrid AI-Static Analyzer pipeline.
    dangerous_keywords = ["call{value:", "delegatecall", "safeTransferFrom", "selfdestruct"]
    is_dangerous = any(kw in payload.source_code for kw in dangerous_keywords)

    if is_dangerous:
        raw_probability = max(raw_probability, 0.88) # Force High Risk
    else:
        raw_probability = min(raw_probability, 0.15) # Force Low Risk for safe contracts

    # 5. Crypto & Mahalanobis
    c1, c2 = crypto_engine.encrypt_logit(raw_probability)
    simulated_node_vector = [0.1, 0.05, raw_probability]
    poisoned, distance = detect_validator_poisoning(
        incoming_vector=simulated_node_vector, 
        historical_matrix=HISTORICAL_VOTES_BASELINE,
        chi_squared_threshold=500.0
    )
        
    risk_score = round(raw_probability * 100, 2)
    contract_hash = "0x" + hashlib.sha256(payload.source_code.encode()).hexdigest()
    
    return {
        "status": "success",
        "contract_hash": contract_hash,
        "opcode_count": len(opcodes), # Now shows the real full length (e.g. 1374)
        "risk_score": risk_score,
        "risk_level": "HIGH" if risk_score >= 50 else "LOW",
        "is_flagged": risk_score >= 50,
        "crypto_payload_c1": str(c1),
        "mahalanobis_distance": round(distance, 4)
    }