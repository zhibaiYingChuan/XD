path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

replacements = {
    "text.count('\\uff1a')": "text.count('\\uff1a')",
    "text.count('\\uff01')": "text.count('\\uff01')",
    "text.count('\\uff1f')": "text.count('\\uff1f')",
    "text.count('\\u3002')": "text.count('\\u3002')",
}

import re
content = re.sub(r"text\.count\('\uff1a'\)", "text.count('\\uff1a')", content)
content = re.sub(r"text\.count\('\uff01'\)", "text.count('\\uff01')", content)
content = re.sub(r"text\.count\'\uff1f\'", "text.count('\\uff1f')", content)
content = re.sub(r"text\.count\('\u3002'\)", "text.count('\\u3002')", content)

lines = content.split('\n')
fixed_lines = []
for i, line in enumerate(lines):
    if "text.count('" in line and ')' not in line.split("text.count('")[-1]:
        next_line = lines[i+1] if i+1 < len(lines) else ''
        combined = line + next_line
        if "text.count('\\uff1a')" in combined or "text.count('\\uff01')" in combined:
            fixed_lines.append(line.rstrip() + "')")
            continue
        if "text.count('!" in line and ')' not in line:
            fixed_lines.append(line.rstrip() + "\\uff01')")
            continue
        if "text.count('?" in line and ')' not in line:
            fixed_lines.append(line.rstrip() + "\\uff1f')")
            continue
    fixed_lines.append(line)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(fixed_lines))

print("Fixed")
