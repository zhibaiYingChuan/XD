import re

path = r'e:\smallloong\XuanDun\src\daoti_xuandun\reject_gate.py'

try:
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
except UnicodeDecodeError:
    with open(path, 'rb') as f:
        raw = f.read()
    if raw[:2] == b'\xff\xfe':
        content = raw.decode('utf-16-le')
    elif raw[:3] == b'\xef\xbb\xbf':
        content = raw.decode('utf-8-sig')
    else:
        content = raw.decode('utf-8', errors='replace')

content = content.replace('time.time()', 'time.monotonic()')

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixed encoding and replaced time.time() -> time.monotonic()")
