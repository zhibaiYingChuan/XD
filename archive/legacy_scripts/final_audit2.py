import os

SRC_DIR = "src/daoti_xuandun"
real_issues = []

for root, dirs, files in os.walk(SRC_DIR):
    for fname in files:
        if not fname.endswith(".py"):
            continue
        filepath = os.path.join(root, fname)
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or '"""' in stripped or "'''" in stripped:
                continue

            div_patterns = [
                (r"len\(\w+\)\s*\)", "len() result"),
                (r"/\s*n\b", "variable n"),
                (r"/\s*norm\b", "norm variable"),
                (r"/\s*total\b", "total variable"),
                (r"/\s*var_total\b", "var_total variable"),
                (r"/\s*total_var\b", "total_var variable"),
                (r"/\s*norms\b", "norms variable"),
                (r"/\s*proj_norms\b", "proj_norms variable"),
                (r"/\s*rare_count\b", "rare_count variable"),
                (r"/\s*rare_total\b", "rare_total variable"),
                (r"/\s*total_alpha_words\b", "total_alpha_words variable"),
                (r"/\s*total_alpha\b", "total_alpha variable"),
                (r"/\s*total_fg\b", "total_fg variable"),
                (r"/\s*total_tg\b", "total_tg variable"),
                (r"/\s*dist_range\b", "dist_range variable"),
                (r"/\s*dist_std\b", "dist_std variable"),
                (r"/\s*char_freq\b", "char_freq variable"),
            ]

            import re
            for pattern, desc in div_patterns:
                if re.search(pattern, stripped):
                    context = "".join(lines[max(0,i-3):i+1])
                    has_guard = any(g in context for g in [
                        "1e-", "max(1", "max(0", "> 0", "!= 0", "if len",
                        "if n", "if total", "if norm", "if rare", "if var",
                        "np.maximum", "eps", "> 1", "> 0"
                    ])
                    if not has_guard:
                        real_issues.append((filepath, i, desc, stripped[:100]))
                    break

if real_issues:
    print(f"REAL DIV_ZERO RISKS: {len(real_issues)}\n")
    for fp, ln, desc, code in sorted(real_issues, key=lambda x: (x[0], x[1])):
        print(f"  {fp.replace(chr(92),'/')}:{ln} [{desc}]")
        print(f"    {code}\n")
else:
    print("NO REAL DIV_ZERO RISKS FOUND!")
