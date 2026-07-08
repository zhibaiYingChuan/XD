path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

lines = content.split('\n')
new_lines = []
broken_count = 0
for i, line in enumerate(lines):
    if '\ufffd' in line:
        broken_count += 1
        print(f"  Line {i+1}: {repr(line.strip()[:100])}")
        if "text_stripped[-1] in '" in line:
            new_lines.append("            if text_stripped and text_stripped[-1] in '\u4e5f\u77e3\u7109\u54c9\u4e4e':")
            continue
        elif "any(p in text for p in '" in line and '吗' in line or '\u5417' in line or '\ufffd' in line:
            new_lines.append("        has_q_particle = any(p in text for p in '\u5417\u5462\u5427')")
            continue
        elif "cn_classical_chars =" in line:
            new_lines.append("        cn_classical_chars = '\u66f0\u4e4e\u77e3\u7109\u54c9\u5c14\u6c5d\u543e\u4e43\u4ea6\u76d6\u592b\u4ff1\u54b8\u6089\u5eb6\u66f7\u5950\u7f37\u96b9\u96ce\u9e20'")
            continue
        elif "cn_learning =" in line:
            new_lines.append("        cn_learning = ['\u6b63\u5728\u7814\u7a76', '\u6b63\u5728\u5b66\u4e60', '\u6b63\u5728\u5206\u6790', '\u5e2e\u6211\u7406\u89e3', '\u8bf7\u89e3\u91ca', '\u6211\u60f3\u4e86\u89e3']")
            continue
        elif "cn_marker" in line:
            new_lines.append("            if cn_marker in text_lower:")
            continue
        elif "learning_markers" in line:
            new_lines.append("            learning_markers = []")
            continue
        elif "'\u66f0" in line or "'\u4e4e" in line or "'\u77e3" in line or "'\u7109" in line or "'\u54c9" in line:
            new_lines.append(line.replace('\ufffd', ''))
            continue
        else:
            new_lines.append(line.replace('\ufffd', '?'))
            continue
    new_lines.append(line)

content = '\n'.join(new_lines)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print(f"\nTotal broken lines: {broken_count}")
