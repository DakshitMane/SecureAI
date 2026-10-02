import solcx
import json
from typing import Dict, Any

# Ensure solc 0.8.20 is installed and active
try:
    solcx.set_solc_version('0.8.20')
except Exception:
    solcx.install_solc('0.8.20')
    solcx.set_solc_version('0.8.20')


def parse_solidity_code(source_code: str, contract_name: str = "TargetContract") -> Dict[str, Any]:
    """
    Compiles Solidity source code and returns AST, Bytecode, and OpCodes.
    """
    try:
        # Wrap source in basic pragma if missing
        if "pragma solidity" not in source_code:
            source_code = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + source_code

        compiled_sol = solcx.compile_source(
            source_code,
            output_values=["ast", "bin", "opcodes"],
            solc_version="0.8.20"
        )

        # Find compiled contract key
        key = f"<stdin>:{contract_name}"
        if key not in compiled_sol:
            key = list(compiled_sol.keys())[0]

        contract_data = compiled_sol[key]

        return {
            "status": "success",
            "ast": contract_data.get("ast", {}),
            "bytecode": contract_data.get("bin", ""),
            "opcodes": contract_data.get("opcodes", "").split()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


if __name__ == "__main__":
    sample_code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract SimpleVault {
        mapping(address => uint256) public balances;

        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
    }
    """
    result = parse_solidity_code(sample_code, "SimpleVault")
    print(f"Parser Status: {result['status']}")
    print(f"Extracted {len(result.get('opcodes', []))} OpCodes.")