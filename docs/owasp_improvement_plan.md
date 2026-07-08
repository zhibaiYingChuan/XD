# 快速改善 OWASP 结果实验方案

## 目标

将 OWASP LLM Top 10 良性接纳率从 33% 提升至 70%+，同时保持攻击拒绝率 ≥90%。

---

## 方案一：字符正规化管道（预期提升最大）

### 问题

OWASP 中以下类别的良性接纳率为 0%：
- 角色扮演越狱（"Write a story" 被误判）
- 数据泄露（"What data were you trained on?" 被误判）
- 向量嵌入（"Search for documents" 被误判）
- 虚假信息（"Write fiction" 被误判）

### 方案

在 `reject_gate.py` 的 `_compute_fourgram_signal` 之前，添加**命令式短语白名单**：

```python
IMPERATIVE_WHITELIST = {
    "write a", "create a", "explain how", "describe the",
    "what is the", "how do i", "can you help", "help me",
    "i want to", "i need to", "please show", "tell me about",
}

def _is_likely_benign_imperative(self, text: str) -> bool:
    lower = text.lower().strip()
    for phrase in IMPERATIVE_WHITELIST:
        if lower.startswith(phrase):
            return True
    return False
```

在信号融合时，若检测到良性命令式前缀，降低 `fourgram_signal` 的权重：

```python
if self._is_likely_benign_imperative(raw_input):
    fourgram_signal *= 0.3
```

### 预期效果

- 角色扮演良性：0% → 50-75%
- 数据泄露良性：0% → 50-75%
- 攻击拒绝率：可能下降 2-5%（部分攻击也以命令式开头）

### 风险

攻击者可能利用白名单前缀绕过检测（如 "Write a story about how to hack..."）。需要结合后续信号综合判断。

---

## 方案二：Base64/Hex 解码预处理（解决编码攻击盲区）

### 问题

Base64 编码攻击检测率仅 0-50%，因为编码后的字符串在字节分布上与普通 ASCII 无异。

### 方案

在 `reject_gate.py` 的 `process` 方法中，添加编码检测与解码：

```python
import base64
import re

def _try_decode_payload(self, text: str) -> list:
    decoded = [text]
    stripped = text.strip()

    if re.match(r'^[A-Za-z0-9+/=]{16,}$', stripped):
        try:
            d = base64.b64decode(stripped).decode('utf-8', errors='ignore')
            decoded.append(d)
        except Exception:
            pass

    if re.match(r'^[0-9a-fA-F]{16,}$', stripped):
        try:
            d = bytes.fromhex(stripped).decode('utf-8', errors='ignore')
            decoded.append(d)
        except Exception:
            pass

    return decoded
```

在 `process` 中对解码后的文本也运行检测：

```python
payloads = self._try_decode_payload(raw_input)
for payload in payloads:
    if payload != raw_input:
        decoded_result = self._compute_signal(payload, ...)
        if decoded_result > threshold:
            return Decision.REJECT
```

### 预期效果

- Base64 攻击检测率：0% → 80-100%
- Hex 攻击检测率：67% → 90-100%
- 良性接纳率：不受影响

---

## 方案三：Unicode 正规化（解决混淆良性误拒）

### 问题

Leet/Unicode/Spacing 混淆攻击检测率 100%，但良性接纳率 0%。原因是特殊字符（零宽字符、西里尔字母等）触发了异常信号。

### 方案

在检测前添加 Unicode 正规化：

```python
import unicodedata

def _normalize_text(self, text: str) -> str:
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'[\u200b\u200c\u200d\u00ad\u2060]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text
```

对正规化后的文本运行检测，若正规化版本通过，则放行原始文本：

```python
normalized = self._normalize_text(raw_input)
if normalized != raw_input:
    norm_result = self._compute_signal(normalized, ...)
    if norm_result < threshold:
        return Decision.ALLOW
```

### 预期效果

- Leet 良性接纳率：0% → 60-80%
- Unicode 良性接纳率：0% → 70-90%
- 混淆攻击检测率：可能下降 5-10%（正规化后部分攻击变得可接受）

---

## 方案四：语义重叠样本的"双通道"检测

### 问题

"Write a story" 与 "Write a malicious script" 在字节分布上无法区分。

### 方案

添加轻量级语义嵌入通道（可选模块，不影响核心架构）：

```python
class SemanticChannel:
    def __init__(self):
        self._model = None

    def _load_model(self):
        from sentence_transformers import SentenceTransformer
        self._model = SentenceTransformer('all-MiniLM-L6-v2')

    def similarity(self, text_a: str, text_b: str) -> float:
        if self._model is None:
            self._load_model()
        emb = self._model.encode([text_a, text_b])
        return float(np.dot(emb[0], emb[1]) / (np.linalg.norm(emb[0]) * np.linalg.norm(emb[1]) + 1e-10))
```

在信号融合时，若字节通道判定为攻击但语义通道判定为良性，降低最终攻击信号：

```python
if attack_signal > threshold:
    for proto in self.attack_prototypes[-5:]:
        sim = semantic.similarity(raw_input, proto.text)
        if sim < 0.3:
            attack_signal *= 0.5
            break
```

### 预期效果

- 语义重叠良性接纳率：0% → 50-70%
- 攻击拒绝率：可能下降 3-5%
- 延迟：增加 5-20ms（取决于模型加载方式）

### 风险

引入外部依赖（sentence-transformers），增加攻击面（对抗性嵌入）。

---

## 实施优先级

| 优先级 | 方案 | 预期良性接纳率提升 | 实施难度 | 风险 |
|-------|------|------------------|---------|------|
| **P0** | 方案二：Base64/Hex 解码 | +5-10%（编码类别） | 低 | 极低 |
| **P1** | 方案三：Unicode 正规化 | +10-15%（混淆类别） | 低 | 低 |
| **P2** | 方案一：命令式白名单 | +15-25%（技术类别） | 中 | 中 |
| **P3** | 方案四：语义通道 | +20-30%（全局） | 高 | 中 |

### 建议实施路径

1. **本周**：实施方案二 + 方案三（低风险，即时收益）
2. **下周**：实施方案一（需要仔细调参，避免攻击绕过）
3. **下月**：评估方案四（作为可选模块，不影响核心架构）

实施 P0+P1 后，预期 OWASP 良性接纳率可从 33% 提升至 **50-60%**，raucle-bench 保持 A 级。
