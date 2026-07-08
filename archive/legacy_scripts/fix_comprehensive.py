import re

path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

fixed_lines = []
for i, line in enumerate(lines):
    original = line

    if "startswith('" in line and ')' not in line.split("startswith('")[-1]:
        if "startswith('?" in line:
            line = line.replace("startswith('?", "startswith(chr(0xFF1F)")
            if ')' not in line:
                line = line.rstrip() + "))\n"
        elif "startswith('!" in line:
            line = line.replace("startswith('!", "startswith(chr(0xFF01)")
            if ')' not in line:
                line = line.rstrip() + "))\n"
        elif "startswith(':" in line:
            line = line.replace("startswith(':", "startswith(chr(0xFF1A)")
            if ')' not in line:
                line = line.rstrip() + "))\n"

    if "'.startswith(" in line and ')' not in line.split("'.startswith(")[-1]:
        pass

    line = line.replace("'\uff1a'", "chr(0xFF1A)")
    line = line.replace("'\uff01'", "chr(0xFF01)")
    line = line.replace("'\uff1f'", "chr(0xFF1F)")
    line = line.replace("'\u3002'", "chr(0x3002)")
    line = line.replace("'？'", "chr(0xFF1F)")
    line = line.replace("'！'", "chr(0xFF01)")
    line = line.replace("'：'", "chr(0xFF1A)")
    line = line.replace("'。'", "chr(0x3002)")

    fixed_lines.append(line)

content = ''.join(fixed_lines)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixed all broken Chinese characters")
