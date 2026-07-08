path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

fixed_count = 0
for i, line in enumerate(lines):
    if '\ufffd' in line:
        original = line
        if "text_stripped[-1] in '" in line:
            line = "            if text_stripped and text_stripped[-1] in '\u4e5f\u77e3\u7109\u54c9\u4e4e':\n"
        elif "any(p in text for p in '" in line:
            line = "        has_q_particle = any(p in text for p in '\u5417\u5462\u5427')\n"
        elif "cn_classical_chars =" in line:
            line = "        cn_classical_chars = '\u66f0\u4e4e\u77e3\u7109\u54c9\u5c14\u6c5d\u543e\u4e43\u4ea6\u76d6\u592b\u4ff1\u54b8\u6089\u5eb6\u66f7\u5950\u7f37\u96b9\u9e20\u9e20'\n"
        elif "cn_learning =" in line or "cn_marker" in line:
            line = line
        else:
            print(f"  Line {i+1}: {repr(original.strip()[:80])}")
        if line != original:
            fixed_count += 1
        lines[i] = line

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.writelines(lines)

print(f"Fixed {fixed_count} lines")
