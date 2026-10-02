import streamlit as st
import requests
import json

st.set_page_config(
    page_title="VulnNet Security Gateway",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ VulnNet: EVM Smart Contract Vulnerability Detection")
st.markdown("Dual-Modal AI Pipeline (GraphCodeBERT + Bi-LSTM) with Layer-1 Audit Verification Gate")

API_URL = "http://127.0.0.1:8000/api/v1/audit"

# Sidebar Configuration
st.sidebar.header("Configuration")
target_url = st.sidebar.text_input("Backend API Endpoint", API_URL)
st.sidebar.markdown("---")
st.sidebar.info("System Status: **API Online**")

# Sample Contracts
SAMPLE_REENTRANCY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}"""

tab1, tab2, tab3 = st.tabs(["🔍 Audit Center", "🧬 AST & OpCode Viewer", "⛓️ L1 Audit Gate"])

with tab1:
    st.subheader("Smart Contract Submission")
    col1, col2 = st.columns([1, 1])

    with col1:
        contract_name = st.text_input("Contract Name", "VulnerableVault")
        source_code = st.text_area("Solidity Source Code", SAMPLE_REENTRANCY, height=300)
        submit_btn = st.button("🚀 Run Dual-Modal Audit", type="primary")

    with col2:
        st.subheader("Audit Results")
        if submit_btn:
            with st.spinner("Analyzing semantics (GraphCodeBERT) and execution paths (Bi-LSTM)..."):
                try:
                    payload = {"contract_name": contract_name, "source_code": source_code}
                    response = requests.post(target_url, json=payload, timeout=10)

                    if response.status_code == 200:
                        data = response.json()
                        
                        # Risk Gauge Display
                        score = data.get("risk_score", 0)
                        level = data.get("risk_level", "LOW")
                        
                        if level == "HIGH":
                            st.error(f"⚠️ HIGH RISK DETECTED — Score: {score}/100")
                        elif level == "MEDIUM":
                            st.warning(f"⚡ MEDIUM RISK DETECTED — Score: {score}/100")
                        else:
                            st.success(f"✅ LOW RISK — Score: {score}/100")

                        # Metrics Display
                        m1, m2, m3 = st.columns(3)
                        m1.metric("Risk Score", f"{score}%")
                        m2.metric("OpCode Count", data.get("opcode_count", 0))
                        m3.metric("Flagged On-Chain", str(data.get("is_flagged", False)))

                        st.markdown("### Transaction Fingerprint")
                        st.code(data.get("contract_hash", ""), language="text")

                    else:
                        st.error(f"Error {response.status_code}: {response.text}")
                except Exception as e:
                    st.error(f"Failed to connect to backend API: {str(e)}")

with tab2:
    st.subheader("Extracted OpCode & AST Representation")
    if submit_btn and 'data' in locals() and response.status_code == 200:
        st.json(data)
    else:
        st.info("Run an audit in the Audit Center tab to view extracted structural representations.")

with tab3:
    st.subheader("Layer-1 On-Chain Verification Ledger")
    st.markdown("Audits passing consensus thresholds are committed to `AuditGate.sol` on local Hardhat testnet.")
    st.table([
        {"Contract Hash": "0x99ec2edd860c...", "Risk Score": "85.04%", "Flagged": "True", "Status": "Committed (Block #1042)"},
        {"Contract Hash": "0x3f1b20ac891d...", "Risk Score": "12.30%", "Flagged": "False", "Status": "Committed (Block #1041)"}
    ])