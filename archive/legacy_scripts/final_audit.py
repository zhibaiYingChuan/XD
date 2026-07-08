import os
import re

SRC_DIR = "src/daoti_xuandun"
issues = []

for root, dirs, files in os.walk(SRC_DIR):
    for fname in files:
        if not fname.endswith(".py"):
            continue
        filepath = os.path.join(root, fname)
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if " / " in stripped or "/len(" in stripped or "/ n" in stripped or "/ n_" in stripped:
                if not any(s in stripped for s in ["1e-", "max(1", "max(0", "+ 1)", "+1)", "> 0", "!= 0", "eps", "//", "round(", "int(", ".0 /", "/ 1.", "/ 2.", "/ 3.", "/ 4.", "/ 10.", "/ 100.", "/ 1000.", "/ 255.", "/ 2**", "0.5 *", "0.3 *", "0.2 *", "0.1 *", "0.15 *"]):
                    if not any(s in stripped for s in ["# ", "docstring", "comment"]):
                        issues.append(("DIV", filepath, i, stripped[:100]))

            if "hash(" in stripped and "hashlib" not in stripped and "compute_integrity" not in stripped and "__hash__" not in stripped:
                issues.append(("HASH", filepath, i, stripped[:100]))

            if "time.time()" in stripped:
                issues.append(("TIME", filepath, i, stripped[:100]))

            if "np.random.randn(" in stripped:
                issues.append(("RNG", filepath, i, stripped[:100]))

            if ".fill(" in stripped and "len(" not in stripped and "size" not in stripped:
                prev = lines[i-2].strip() if i >= 2 else ""
                if "len(" not in prev and "size" not in prev and "hasattr(" not in prev:
                    issues.append(("FILL", filepath, i, stripped[:100]))

            if "astype(np.int32)" in stripped:
                issues.append(("INT32", filepath, i, stripped[:100]))

            if ".decision" in stripped and "Decision." not in stripped and "decision ==" not in stripped and "decision =" not in stripped and "decision:" not in stripped:
                issues.append(("ATTR", filepath, i, stripped[:100]))

if issues:
    print(f"REMAINING ISSUES: {len(issues)}\n")
    for cat, fp, ln, code in sorted(issues, key=lambda x: (x[0], x[1], x[2])):
        print(f"  [{cat}] {fp.replace(chr(92),'/')}:{ln}")
        print(f"    {code}\n")
else:
    print("NO REMAINING ISSUES FOUND - ALL CLEAR!")
