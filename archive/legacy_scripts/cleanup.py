path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
skip_garbage = True
for i, line in enumerate(lines):
    stripped = line.strip()

    if skip_garbage and i < 3 and 'has_q_particle' in line:
        continue

    if skip_garbage and i >= 21 and i < 40 and 'has_q_particle' in line:
        continue

    if skip_garbage and stripped == '' and i < 3:
        continue

    if i == 3 and stripped.startswith('from'):
        skip_garbage = False

    if skip_garbage and 'has_q_particle' in line and 'any(p in text' in line:
        continue

    if skip_garbage and 'Attributes:' in line:
        continue

    if skip_garbage and i < 40 and stripped == '':
        continue

    if skip_garbage and i < 40 and stripped == '"""':
        skip_garbage = False

    new_lines.append(line)

content = ''.join(new_lines)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print(f"Removed garbage lines. Original: {len(lines)}, New: {len(new_lines)}")
