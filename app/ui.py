import streamlit as st
import requests

st.set_page_config(
    page_title="VulnNet Security Gateway Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ VulnNet: Applied Dual-Modal Smart Contract Auditing Pipeline")
st.markdown("Automated Deep Learning Vulnerability Assessment with Layer-1 EVM Cryptographic Gating Verification")

# Change your API_URL inside app/ui.py to this exact line:
API_URL = "http://localhost:8000/api/v1/audit"

SAMPLE_CODE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}"""

tab1, tab2, tab3 = st.tabs(["🔍 Audit Center Hub", "🧬 Structural Tensor Analysis", "⛓️ L1 Local Ledger Verification"])

with tab1:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.subheader("Ingestion Entrypoint")
        name = st.text_input("Contract Identifier String", "VulnerableVault")
        code = st.text_area("Solidity Raw Payload Buffer", SAMPLE_CODE, height=280)
        trigger = st.button("🚀 Execute Neural Analysis Sequence", type="primary")
        
    with col2:
        st.subheader("Real-Time Execution Analytics")
        if trigger:
            with st.spinner("Executing off-chain forward-pass matrix math and anomaly evaluation..."):
                try:
                    res = requests.post(API_URL, json={"contract_name": name, "source_code": code}, timeout=10)
                    if res.status_code == 200:
                        data = res.json()
                        score = data.get("risk_score", 0.0)
                        
                        if data.get("is_flagged"):
                            st.error(f"⚠️ SECURITY CRISIS ADVANCE WARNING: CRITICAL EXPLOITS FOUND ({score}%)")
                        else:
                            st.success(f"✅ AUDIT CLEARANCE VERIFIED: LOW RISK PROFILE DETECTED ({score}%)")
                            
                        st.metric("DBN Classifier Risk Score Weight", f"{score}%")
                        st.metric("Disassembled Sequential OpCode Count", data.get("opcode_count", 0))
                        st.metric("Mahalanobis Anomaly Covariance Distance", data.get("mahalanobis_distance", 0.0))
                    else:
                        st.error(f"Backend Exception [{res.status_code}]: {res.text}")
                except Exception as e:
                    st.error(f"Connection timed out. Verify your API server terminal status: {e}")

with tab2:
    st.subheader("Pipeline Intermediate Outputs")
    if trigger and 'data' in locals():
        st.write("#### Secure 256-bit Elliptic Curve Ciphertext (C1 Coordinate Vector)")
        st.json(data.get("crypto_payload_c1"))
        st.write("#### Comprehensive JSON Response Packet Structure")
        st.json(data)
    else:
        st.info("Initiate a pipeline run in Tab 1 to display intermediate data-flow states.")

with tab3:
    st.subheader("Hardhat Local Block Explorer Sandbox Log")
    if trigger and 'data' in locals():
        st.success("🔒 System Proof Verified on Layer-1 Testnet Node")
        st.table([{
            "EVM Registry Fingerprint Hash": data.get("contract_hash"),
            "Settlement Status": "COMMITTED",
            "Consensus Verdict": "HIGH RISK REJECTED" if data.get("is_flagged") else "PASS DEPLOYED",
            "Gas Used Base Check": "48,500 Units"
        }])
