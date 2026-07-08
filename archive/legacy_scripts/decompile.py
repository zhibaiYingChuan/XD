import subprocess
import sys

result = subprocess.run(
    [sys.executable, '-m', 'decompyle3',
     r'e:\smallloong\XuanDun\src\daoti_xuandun\__pycache__\reject_gate.cpython-311.pyc'],
    capture_output=True, text=True, timeout=60
)

with open(r'e:\smallloong\XuanDun\reject_gate_decompiled.py', 'w', encoding='utf-8') as f:
    f.write(result.stdout)

print(f"Return code: {result.returncode}")
print(f"Stderr: {result.stderr[:500]}")
print(f"Output length: {len(result.stdout)} chars")
