//! 洛书符号映射器 — Rust 加速实现

/// 判断字符是否为标点符号
fn is_punct(ch: char) -> bool {
    matches!(ch, '.' | ',' | '!' | '?' | ';' | ':' | '\'' | '"' | '-' | '(' | ')' | '[' | ']' | '{' | '}')
}

/// 洛书符号引擎 — 纯计算核心（无状态、无 PyO3 依赖）
///
/// 被 Python LuoshuSymbolMapper 调用以加速 encode() 计算。
pub struct LuoshuEngine {
    /// 原生维度（固定 176）
    native_dim: usize,
    /// 确定性种子（从 config 派生，保证可复现；预留字段，未来用于哈希盐值）
    #[allow(dead_code)]
    seed: u64,
}

impl LuoshuEngine {
    /// 创建洛书引擎实例
    pub fn new(native_dim: usize, seed: u64) -> Self {
        Self { native_dim, seed }
    }

    /// 将文本编码为 native_dim 维向量（核心编码管线）
    ///
    /// 算法：
    ///   1. 遍历每个 Unicode 码点，用三个不同哈希散列到向量索引
    ///   2. 位置权重（log 衰减）：位置越前的字符权重越大
    ///   3. 补 8 维统计特征：字节熵、可打印比、大写比、特殊字符密度、
    ///      平均词长、标点密度、数字密度、空白符比例
    ///   4. L2 归一化输出
    pub fn encode_native(&self, text: &str) -> Vec<f32> {
        let dim = self.native_dim;
        let mut vec = vec![0.0f32; dim];

        if text.is_empty() {
            return vec;
        }

        let text_len = text.chars().count();
        let data = text.as_bytes();
        let data_len = data.len() as f32;

        // ── 码点散列（dim - 8 维）──
        let hash_dim = dim - 8;
        for (i, ch) in text.chars().enumerate() {
            let cp = ch as u64;
            // 三个不同的乘法常量（黄金比例裂变），避免碰撞
            let idx1 = (cp.wrapping_mul(2654435761) as usize) % hash_dim;
            let idx2 = (cp.wrapping_mul(2246822519) as usize) % hash_dim;
            let idx3 = (cp.wrapping_mul(3266489917) as usize) % hash_dim;
            // 位置权重：log(1+i) 衰减，前面字符权重更大
            let pos_weight = 1.0 + 0.01 * (i as f32 + 1.0).ln();
            vec[idx1] += (cp & 0xFF) as f32 / 255.0 * pos_weight;
            vec[idx2] += ((cp >> 8) & 0xFF) as f32 / 255.0 * pos_weight;
            vec[idx3] += 0.1 * pos_weight;
        }

        // ── 统计特征（8 维）──
        let offset = hash_dim;

        // 1. 字节熵
        if data_len > 0.0 {
            let mut byte_counts = [0u64; 256];
            for &b in data {
                byte_counts[b as usize] += 1;
            }
            let mut entropy = 0.0f32;
            for &c in byte_counts.iter() {
                if c > 0 {
                    let p = c as f32 / data_len;
                    entropy -= p * p.log2();
                }
            }
            vec[offset] = (entropy / 8.0).min(1.0);
        }

        // 2. 可打印字符比
        let printable = text.chars().filter(|c| {
            c.is_alphanumeric() || c.is_whitespace()
                || matches!(*c, '\n' | '\r' | '\t')
        }).count();
        vec[offset + 1] = if text_len > 0 {
            printable as f32 / text_len as f32
        } else { 0.0 };

        // 3. 大写比例
        let upper = text.chars().filter(|c| c.is_uppercase()).count();
        vec[offset + 2] = if text_len > 0 {
            upper as f32 / text_len as f32
        } else { 0.0 };

        // 4. 特殊字符密度
        let special = text.chars().filter(|c| {
            !c.is_alphanumeric() && !c.is_whitespace() && !is_punct(*c)
        }).count();
        vec[offset + 3] = (special as f32 / text_len.max(1) as f32 * 3.0).min(1.0);

        // 5. 平均词长
        let words: Vec<&str> = text.split_whitespace().collect();
        let avg_word_len = if words.is_empty() { 0.0 } else {
            words.iter().map(|w| w.chars().count() as f32).sum::<f32>() / words.len() as f32
        };
        vec[offset + 4] = (avg_word_len / 15.0).min(1.0);

        // 6. 标点密度
        let punct = text.chars().filter(|c| is_punct(*c)).count();
        vec[offset + 5] = if text_len > 0 {
            punct as f32 / text_len as f32
        } else { 0.0 };

        // 7. 数字密度
        let digits = text.chars().filter(|c| c.is_ascii_digit()).count();
        vec[offset + 6] = if text_len > 0 {
            digits as f32 / text_len as f32
        } else { 0.0 };

        // 8. 空白符比例
        let spaces = text.chars().filter(|c| c.is_whitespace()).count();
        vec[offset + 7] = if text_len > 0 {
            spaces as f32 / text_len as f32
        } else { 0.0 };

        // L2 归一化
        let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 1e-8 {
            for v in vec.iter_mut() {
                *v /= norm;
            }
        }

        vec
    }

    /// 两个向量的余弦相似度
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        let (mut dot, mut norm_a, mut norm_b) = (0.0f32, 0.0f32, 0.0f32);
        for i in 0..a.len() {
            dot += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }
        let denom = norm_a.sqrt() * norm_b.sqrt();
        if denom < 1e-12 { 0.0 } else { dot / denom }
    }

    /// 计算香农字节熵（用于自然语言检测）
    pub fn shannon_entropy(text: &str) -> f32 {
        let data = text.as_bytes();
        if data.is_empty() { return 0.0; }
        let mut counts = [0u64; 256];
        for &b in data { counts[b as usize] += 1; }
        let n = data.len() as f32;
        let mut entropy = 0.0f32;
        for &c in counts.iter() {
            if c > 0 {
                let p = c as f32 / n;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty_text() {
        let engine = LuoshuEngine::new(176, 42);
        let v = engine.encode_native("");
        assert_eq!(v.len(), 176);
        assert!(v.iter().all(|&x| x == 0.0));
    }

    #[test]
    fn encode_chinese_text() {
        let engine = LuoshuEngine::new(176, 42);
        let v = engine.encode_native("你好世界");
        assert_eq!(v.len(), 176);
        // L2 归一化后范数应接近 1.0
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "norm = {}", norm);
    }

    #[test]
    fn encode_deterministic() {
        let engine = LuoshuEngine::new(176, 42);
        let v1 = engine.encode_native("测试文本");
        let v2 = engine.encode_native("测试文本");
        assert_eq!(v1, v2); // 相同种子+相同输入 → 相同输出
    }

    #[test]
    fn cosine_identical() {
        let v = vec![1.0f32, 0.0, 0.0];
        assert!((LuoshuEngine::cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal() {
        let a = vec![1.0f32, 0.0];
        let b = vec![0.0f32, 1.0];
        assert!((LuoshuEngine::cosine_similarity(&a, &b) - 0.0).abs() < 1e-6);
    }
}
