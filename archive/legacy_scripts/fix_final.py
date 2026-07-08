path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

import re

content = re.sub(
    r"has_q = '\?' in text or '[^']*' in text or '[^']*' in text or '[^']*' in text",
    "has_q = '?' in text or chr(0xFF1F) in text or chr(0xFF01) in text or chr(0xFF1A) in text",
    content
)

content = re.sub(
    r"has_q = '\?' in text or '[^']*' in text or '[^']*' in text",
    "has_q = '?' in text or chr(0xFF1F) in text or chr(0xFF01) in text",
    content
)

content = re.sub(r"'？' in text", "chr(0xFF1F) in text", content)
content = re.sub(r"'！' in text", "chr(0xFF01) in text", content)
content = re.sub(r"'：' in text", "chr(0xFF1A) in text", content)
content = re.sub(r"'。' in text", "chr(0x3002) in text", content)

content = re.sub(r"text\.count\('？'\)", "text.count(chr(0xFF1F))", content)
content = re.sub(r"text\.count\('！'\)", "text.count(chr(0xFF01))", content)
content = re.sub(r"text\.count\('：'\)", "text.count(chr(0xFF1A))", content)
content = re.sub(r"text\.count\('。'\)", "text.count(chr(0x3002))", content)

content = re.sub(r"'\uff1a'", "chr(0xFF1A)", content)
content = re.sub(r"'\uff01'", "chr(0xFF01)", content)
content = re.sub(r"'\uff1f'", "chr(0xFF1F)", content)
content = re.sub(r"'\u3002'", "chr(0x3002)", content)

content = re.sub(r"'吗' in text", "chr(0x5417) in text", content)
content = re.sub(r"'呢' in text", "chr(0x5462) in text", content)
content = re.sub(r"'吧' in text", "chr(0x5427) in text", content)
content = re.sub(r"any\(p in text for p in '[^']*'\)", "any(p in text for p in chr(0x5417)+chr(0x5462)+chr(0x5427))", content)

broken = re.findall(r"'[\ufffd]+[^']*' in text", content)
for b in broken:
    print(f"Found broken pattern: {repr(b)}")

broken2 = re.findall(r"text\.count\('[\ufffd]+[^']*'\)", content)
for b in broken2:
    print(f"Found broken count: {repr(b)}")

broken3 = re.findall(r"startswith\('[\ufffd]+[^']*'\)", content)
for b in broken3:
    print(f"Found broken startswith: {repr(b)}")

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixed")
