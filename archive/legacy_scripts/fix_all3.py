path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

lines = content.split('\n')
new_lines = []
for i, line in enumerate(lines):
    if '\ufffd' not in line:
        new_lines.append(line)
        continue

    stripped = line.strip()

    if stripped.startswith('#'):
        new_lines.append(line.replace('\ufffd', ''))
        continue

    if stripped.startswith('"""') or stripped.startswith("'''"):
        new_lines.append(line.replace('\ufffd', ''))
        continue

    if "has_question_mark = '?' in text" in line:
        new_lines.append("        has_question_mark = '?' in text or chr(0xFF1F) in text")
        continue

    if "has_q_particle = any(p in text for p in '" in line:
        new_lines.append("        has_q_particle = any(p in text for p in chr(0x5417)+chr(0x5462)+chr(0x5427))")
        continue

    if "is_very_short = n < 5 and not" in line:
        new_lines.append("            is_very_short = n < 5 and not ('?' in text or chr(0xFF1F) in text)")
        continue

    if "has_q = '?' in text" in line:
        new_lines.append("        has_q = '?' in text or chr(0xFF1F) in text or chr(0xFF01) in text or chr(0xFF1A) in text or chr(0x5417) in text")
        continue

    if "cn_learning = [" in line:
        new_lines.append("        cn_learning = [chr(0x6B63)+chr(0x5728)+chr(0x7814)+chr(0x7A76), chr(0x6B63)+chr(0x5728)+chr(0x5B66)+chr(0x4E60), chr(0x6B63)+chr(0x5728)+chr(0x5206)+chr(0x6790), chr(0x5E2E)+chr(0x6211)+chr(0x7406)+chr(0x89E3), chr(0x8BF7)+chr(0x89E3)+chr(0x91CA), chr(0x6211)+chr(0x60F3)+chr(0x4E86)+chr(0x89E3)]")
        continue

    if "is_question = (" in line:
        new_lines.append("        is_question = ('?' in text or chr(0xFF1F) in text or")
        continue

    if "any(p in text for p in '" in line and ')' in line:
        new_lines.append("                    any(p in text for p in chr(0x5417)+chr(0x5462)+chr(0x5427)))")
        continue

    if "text_stripped[-1] in '" in line:
        new_lines.append("            if text_stripped and text_stripped[-1] in chr(0x4E5F)+chr(0x77E3)+chr(0x7109)+chr(0x54C9)+chr(0x4E4E):")
        continue

    if "cn_classical_chars =" in line:
        new_lines.append("        cn_classical_chars = chr(0x66F0)+chr(0x4E4E)+chr(0x77E3)+chr(0x7109)+chr(0x54C9)+chr(0x5C14)+chr(0x6C5D)+chr(0x543E)+chr(0x4E43)+chr(0x4EA6)+chr(0x76D6)+chr(0x592B)+chr(0x4FF1)+chr(0x54B8)+chr(0x6089)+chr(0x5EB6)+chr(0x66F7)+chr(0x5950)+chr(0x7F37)+chr(0x96B9)+chr(0x96CE)+chr(0x9E20)")
        continue

    new_lines.append(line.replace('\ufffd', ''))

content = '\n'.join(new_lines)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixed all broken lines")
