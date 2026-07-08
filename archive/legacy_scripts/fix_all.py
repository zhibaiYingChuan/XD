path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

import re

content = content.replace("text.count('\\uff1a')", "text.count(chr(0xFF1A))")
content = content.replace("text.count('\\uff01')", "text.count(chr(0xFF01))")

broken_patterns = [
    (r"text\.count\('\uff1a'\)", "text.count(chr(0xFF1A))"),
    (r"text\.count\('\uff01'\)", "text.count(chr(0xFF01))"),
    (r"'？' in text", "chr(0xFF1F) in text"),
    (r"'？' in text", "chr(0xFF1F) in text"),
]

lines = content.split('\n')
fixed_lines = []
for line in lines:
    if "text.count('" in line:
        if line.strip().endswith(')') and not line.strip().endswith("')"):
            pass
        if "'\uff1a'" in line or "'\uff01'" in line or "'\uff1f'" in line or "'\u3002'" in line:
            line = line.replace("'\uff1a'", "chr(0xFF1A)")
            line = line.replace("'\uff01'", "chr(0xFF01)")
            line = line.replace("'\uff1f'", "chr(0xFF1F)")
            line = line.replace("'\u3002'", "chr(0x3002)")

    if "'？" in line and " in text" in line:
        line = line.replace("'？", "chr(0xFF1F)")
        if " in text" in line and "chr(0xFF1F)" in line:
            line = line.replace("chr(0xFF1F) in text", "chr(0xFF1F) in text")

    if "text.count('!" in line and ')' not in line.split("text.count('!")[-1]:
        line = line.rstrip() + "chr(0xFF01))"

    if "text.count('?" in line and ')' not in line.split("text.count('?")[-1]:
        line = line.rstrip() + "chr(0xFF1F))"

    if "text.count(':" in line and ')' not in line.split("text.count(':")[-1]:
        line = line.rstrip() + "chr(0xFF1A))"

    if "'？' in text" in line:
        line = line.replace("'？' in text", "chr(0xFF1F) in text")

    if "'？' in text" in line:
        line = line.replace("'？' in text", "chr(0xFF1F) in text")

    fixed_lines.append(line)

content = '\n'.join(fixed_lines)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixed all broken Chinese characters")
