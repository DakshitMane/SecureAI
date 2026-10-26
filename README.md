# SecureAI: Dual-Modal Smart Contract Auditing Pipeline

SecureAI is a decoupled, 6-layer security framework for detecting vulnerabilities in Ethereum smart contracts. It combines **GraphCodeBERT** (semantic analysis) and **Bi-LSTM** (OpCode sequence analysis) with **EC-ElGamal** homomorphic encryption and **Mahalanobis** anomaly detection.

## 🏗️ Architecture
1. **Layer 1:** Solidity Ingestion (FastAPI + `solcx`)
2. **Layer 2:** Dual-Modal AI Inference (PyTorch, GraphCodeBERT, Bi-LSTM, DBN)
3. **Layer 3:** Homomorphic Cryptography & Anomaly Filtering
4. **Layer 4:** RBFT Consensus (Simulated)
5. **Layer 5:** Hardhat EVM Gating (Simulated)

## 📸 Screenshots
*(Insert your 3 best screenshots here: Counter (Low Risk), VulnerableVault (High Risk), and SolvVault)*

## 🚀 How to Run Locally
1. Clone the repo: `git clone https://github.com/yourusername/SecureAI.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Download the model weights (link to Google Drive/HuggingFace) and place in `l2_ai_engine/models/checkpoints/vulnnet_dbn.pt`
4. Start backend: `uvicorn app.main:app --reload --port 8001`
5. Start frontend: `streamlit run app/ui.py`

## 📊 Training Results
Trained on the SWC Registry dataset (3,000 sample subset, 5 epochs).
- **Loss:** 1.96 → 0.69
- **Test Accuracy:** 44.5% (9-class baseline)
- **F1-Score:** 0.33

## ⚠️ Current Status (40% Milestone)
- [x] AI Inference Pipeline (GraphCodeBERT + Bi-LSTM)
- [x] 9-Class Vulnerability Classification
- [x] Live Solidity Compilation & OpCode Extraction
- [x] FastAPI + Streamlit UI integration
- [ ] Full 47,000 dataset training (Phase 2)
- [ ] 5-Node RBFT Consensus Simulation (Phase 2)
- [ ] Live Sepolia Testnet Deployment (Phase 2)