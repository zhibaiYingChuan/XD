from decompyle3 import decompile
import sys

try:
    with open(r'e:\smallloong\XuanDun\reject_gate_decompiled.py', 'w', encoding='utf-8') as f:
        decompile(
            3.11,
            r'e:\smallloong\XuanDun\src\daoti_xuandun\__pycache__\reject_gate.cpython-311.pyc',
            f
        )
    print("Decompilation successful")
except Exception as e:
    print(f"Error: {e}")
