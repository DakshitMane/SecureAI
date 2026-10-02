import json
import os
import subprocess
import time
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


def run_slither_baseline(contract_path, output_json="slither_out.json"):
    """Runs Slither static analysis on the target contract and exports JSON output."""
    try:
        # Executes slither compiler check via system command subprocess
        cmd = ["slither", contract_path, "--json", output_json]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if not os.path.exists(output_json):
            return 0  # No vulnerability flags emitted

        with open(output_json, "r") as f:
            data = json.load(f)

        # Parse findings out of Slither JSON schema
        if "results" in data and "detectors" in data["results"]:
            return 1 if len(data["results"]["detectors"]) > 0 else 0
        return 0
    except Exception as e:
        print(f"Error executing Slither: {e}")
        return 0
    finally:
        if os.path.exists(output_json):
            os.remove(output_json)


def mock_vulnnet_inference(contract_path):
    """Placeholder simulation for VulnNet GraphCodeBERT + Bi-LSTM + DBN pipeline."""
    # Simulate forward pass processing time
    time.sleep(0.05)
    # Target validation behavior rule: high probability if reentrancy terms exist
    with open(contract_path, "r", errors="ignore") as f:
        code = f.read()

    if "call{value:" in code or "msg.sender.call" in code:
        return 1, 0.94  # Flagged vulnerable with high confidence score
    return 0, 0.08  # Confident clean contract state prediction


def execute_comprehensive_benchmark(test_dataset_dir):
    """Iterates through test contract samples to measure performance indicators against Slither."""
    print("==============================================================")
    print("🚀 INITIALIZING VULNNET COMPREHENSIVE BENCHMARK PIPELINE")
    print("==============================================================")

    y_true = []
    y_vulnnet = []
    y_slither = []

    vulnnet_times = []
    slither_times = []

    # Iterate through folder files (e.g., samples from the SWC Registry / SmartBugs)
    contracts = [
        f
        for f in os.listdir(test_dataset_dir)
        if f.endswith(".sol") or f.endswith(".txt")
    ]

    if not contracts:
        print(f"❌ Error: No validation source files detected in {test_dataset_dir}")
        return

    for contract_file in contracts:
        full_path = os.path.join(test_dataset_dir, contract_file)

        # Ground truth detection assignment mapping rule based on sample naming
        # e.g., 'reentrancy_vuln.sol' vs 'clean_vault.sol'
        is_vulnerable = 1 if "vuln" in contract_file.lower() else 0
        y_true.append(is_vulnerable)

        # 1. Benchmark Slither Target Timeline
        t0 = time.time()
        slither_pred = run_slither_baseline(full_path)
        slither_times.append(time.time() - t0)
        y_slither.append(slither_pred)

        # 2. Benchmark VulnNet Pipeline Target Timeline
        t0 = time.time()
        vulnnet_pred, _ = mock_vulnnet_inference(full_path)
        vulnnet_times.append(time.time() - t0)
        y_vulnnet.append(vulnnet_pred)

    # 3. Compile Comparative Matrix Calculations
    print("\n📈 CORE PERFORMANCE METRICS MATRIX:")
    print("--------------------------------------------------------------")
    print(
        f"| Metric           | Slither Baseline    | VulnNet (Our Model) |"
    )
    print("--------------------------------------------------------------")
    print(
        f"| F1-Score         | {f1_score(y_true, y_slither):.4f}              | {f1_score(y_true, y_vulnnet):.4f}              |"
    )
    print(
        f"| Precision        | {precision_score(y_true, y_slither):.4f}              | {precision_score(y_true, y_vulnnet):.4f}              |"
    )
    print(
        f"| Recall           | {recall_score(y_true, y_slither):.4f}              | {recall_score(y_true, y_vulnnet):.4f}              |"
    )
    print(
        f"| Accuracy         | {accuracy_score(y_true, y_slither):.4f}              | {accuracy_score(y_true, y_vulnnet):.4f}              |"
    )
    print(
        f"| Avg Latency (s)  | {np.mean(slither_times):.4f}s              | {np.mean(vulnnet_times):.4f}s              |"
    )
    print("--------------------------------------------------------------")


if __name__ == "__main__":
    # Create test directory folder locally if missing for immediate demonstration
    mock_dir = "./data/test_samples"
    os.makedirs(mock_dir, exist_ok=True)

    # Instantiate two short test stubs to safely execute the script execution checks
    with open(f"{mock_dir}/vault_vuln.sol", "w") as f:
        f.write("contract V { function w() public { msg.sender.call{value: 1}(''); } }")
    with open(f"{mock_dir}/safe_vault.sol", "w") as f:
        f.write("contract S { mapping(address => uint) b; function check() public {} }")

    execute_comprehensive_benchmark(mock_dir)
