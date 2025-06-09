"""
Generate Python ABI stubs for main-layer smart contracts.

This script reads all non‐debug JSON artifacts under
`artifacts/contracts/main/` and writes flat stub modules
into `src/blocka2a/contracts/`, each exposing:

  - ABI constant (ABI)
  - get_contract(w3, address) -> Contract

Usage:
  python3 scripts/generate_abi.py
"""

import json
import re
from pathlib import Path
from pprint import pformat

# —— 1. Paths ——————————————————————————————
BASE_DIR       = Path(__file__).resolve().parent.parent
ARTIFACTS_MAIN = BASE_DIR / "artifacts" / "contracts" / "main"
OUTPUT_DIR     = BASE_DIR / "src" / "blocka2a" / "contracts"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# —— 2. CamelCase → snake_case (handles acronyms) ——————————
def camel_to_snake(name: str) -> str:
    # FooBar → Foo_Bar
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    # fooBarXYZ → foo_Bar_XYZ
    s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()

# —— 3. Process only the three contracts in main —————————
# If you ever add more under main/, they'll be picked up automatically
for artifact_file in ARTIFACTS_MAIN.rglob("*.json"):
    # Skip non-contract JSON (no "abi") or debug files
    data = json.loads(artifact_file.read_text(encoding="utf-8"))
    abi = data.get("abi")
    if not abi:
        continue

    # Extract contract name
    contract_name = data.get("contractName") or artifact_file.stem
    module_name = camel_to_snake(contract_name)
    stub_path = OUTPUT_DIR / f"{module_name}.py"

    # Write stub
    with stub_path.open("w", encoding="utf-8") as f:
        f.write("from web3 import Web3\n")
        f.write("from web3.types import Address, ChecksumAddress, ENS\n")
        f.write("from web3.contract import Contract\n")
        f.write("from typing import Union\n\n")
        f.write(f"ABI = {pformat(abi, width=80)}\n\n")
        f.write("def get_contract(\n")
        f.write("    w3: Web3,\n")
        f.write("    address: Union[Address, ChecksumAddress, ENS],\n")
        f.write(") -> Contract:\n")
        f.write('    """\n')
        f.write(f"    Returns a Web3.py Contract instance for `{contract_name}`.\n")
        f.write("    \"\"\"\n")
        f.write("    return w3.eth.contract(address=address, abi=ABI)\n")

    print(f"Generated stub: {stub_path.relative_to(BASE_DIR)}")

print("✅ ABI stub generation complete.")
