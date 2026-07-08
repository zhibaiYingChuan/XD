path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

import re

lines = content.split('\n')

clean_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.strip()

    if 'has_q_particle' in line and 'any(p in text' in line:
        i += 1
        continue

    if stripped == 'Attributes:' and i > 0 and 'class EndogenousDomainAwareness' in lines[i-1]:
        i += 1
        continue

    if stripped.startswith('"""') and i > 0 and i < 5:
        i += 1
        continue

    if i < 4 and stripped == '':
        i += 1
        continue

    clean_lines.append(line)
    i += 1

content = '\n'.join(clean_lines)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print(f"Cleaned. Lines: {len(lines)} -> {len(clean_lines)}")
