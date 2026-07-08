path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

new_lines = []
in_docstring = False
docstring_delim = None

for i, line in enumerate(lines):
    stripped = line.strip()

    if in_docstring:
        if docstring_delim in stripped:
            in_docstring = False
        new_lines.append(line.replace('\ufffd', ''))
        continue

    if stripped.startswith('"""') or stripped.startswith("'''"):
        delim = stripped[:3]
        if stripped.count(delim) >= 2 and stripped.endswith(delim) and len(stripped) > 6:
            new_lines.append(line.replace('\ufffd', ''))
            continue
        in_docstring = True
        docstring_delim = delim
        new_lines.append(line.replace('\ufffd', ''))
        continue

    if '\ufffd' not in line:
        new_lines.append(line)
        continue

    if "has_question_mark = '?' in text" in line:
        new_lines.append("        has_question_mark = '?' in text or chr(0xFF1F) in text\n")
        continue
    if "has_q_particle = any(p in text for p in '" in line:
        new_lines.append("        has_q_particle = any(p in text for p in chr(0x5417)+chr(0x5462)+chr(0x5427))\n")
        continue
    if "is_very_short = n < 5 and not" in line:
        new_lines.append("            is_very_short = n < 5 and not ('?' in text or chr(0xFF1F) in text)\n")
        continue
    if "has_q = '?' in text" in line:
        new_lines.append("        has_q = '?' in text or chr(0xFF1F) in text or chr(0xFF01) in text or chr(0xFF1A) in text or chr(0x5417) in text\n")
        continue
    if "cn_learning = [" in line:
        new_lines.append("        cn_learning = ['\\u6b63\\u5728\\u7814\\u7a76', '\\u6b63\\u5728\\u5b66\\u4e60', '\\u6b63\\u5728\\u5206\\u6790', '\\u5e2e\\u6211\\u7406\\u89e3', '\\u8bf7\\u89e3\\u91ca', '\\u6211\\u60f3\\u4e86\\u89e3']\n")
        continue
    if "is_question = (" in line:
        new_lines.append("        is_question = ('?' in text or chr(0xFF1F) in text or\n")
        continue
    if "any(p in text for p in '" in line and ')' in line:
        new_lines.append("                    any(p in text for p in chr(0x5417)+chr(0x5462)+chr(0x5427)))\n")
        continue
    if "text_stripped[-1] in '" in line:
        new_lines.append("            if text_stripped and text_stripped[-1] in '\\u4e5f\\u77e3\\u7109\\u54c9\\u4e4e':\n")
        continue
    if "cn_classical_chars =" in line:
        new_lines.append("        cn_classical_chars = '\\u66f0\\u4e4e\\u77e3\\u7109\\u54c9\\u5c14\\u6c5d\\u543e\\u4e43\\u4ea6\\u76d6\\u592b\\u4ff1\\u54b8\\u6089\\u5eb6\\u66f7\\u5950\\u7f37\\u96b9\\u96ce\\u9e20'\n")
        continue

    new_lines.append(line.replace('\ufffd', ''))

content = ''.join(new_lines)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixed")
