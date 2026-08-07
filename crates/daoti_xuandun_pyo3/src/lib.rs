// SPDX-License-Identifier: DaoTi-Research-1.0
// Copyright (c) 2026 独立研究者，知白
// 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
// 详见 LICENSE 文件

//! 双梯形镜像递归网络（Bilateral Ladder Recurrent Network）
//!
//! 玄盾灵魂级底层算法。将静态向量映射升级为动态流形演化。
//!
//! 核心思想：
//!   输入文本 → 多层双向递归迭代 → 形成"动态轨迹"
//!   - 正向传播（底层→顶层）：捕捉句子的结构依赖和指令嵌套
//!   - 逆向传播（顶层→底层）：回溯语义，发现隐藏的意图偏移
//!   - 递归迭代：使异常意图在层间传播中被放大
//!
//! 本 crate 用 Rust + ndarray 实现，通过 PyO3 暴露为 Python 可调用模块，
//! 保证性能优良（矩阵运算无 Python 层开销）。

use ndarray::{Array1, Array2};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rand::Rng;

/// 双梯形递归层
///
/// 镜像梯形：同时具有正向（从上层到下层）和逆向（从下层到上层）的信息流。
/// 每层的状态更新公式：
///   h_f_new = f( W_f * h_f_prev + U_f * h_b_curr + b_f )
///   h_b_new = f( W_b * h_b_next + U_b * h_f_curr + b_b )
/// 其中 f 是激活函数（tanh）
pub struct BilateralLadderLayer {
    // 正向权重：输入是上一层的正向状态
    w_f: Array2<f64>,
    // 正向交叉权重：输入是本层的逆向状态
    u_f: Array2<f64>,
    b_f: Array1<f64>,
    // 逆向权重：输入是下一层的逆向状态
    w_b: Array2<f64>,
    // 逆向交叉权重：输入是本层的正向状态
    u_b: Array2<f64>,
    b_b: Array1<f64>,
}

impl BilateralLadderLayer {
    fn new(dim: usize) -> Self {
        let mut rng = rand::thread_rng();
        // 权重初始化：使用增大版的 Xavier 缩放（2/sqrt(dim)），
        // 比标准 Xavier 大 2 倍，使不同文本的轨迹差异更明显。
        // 标准 Xavier 会让 64 维的 tanh 输出偏小，增大后
        // 不同文本在多层传播后产生可区分的轨迹特征。
        let scale = 1.5 / (dim as f64).sqrt();
        let w_f = Array2::from_shape_fn((dim, dim), |_| rng.gen_range(-scale..scale));
        let u_f = Array2::from_shape_fn((dim, dim), |_| rng.gen_range(-scale..scale));
        let b_f = Array1::zeros(dim);
        let w_b = Array2::from_shape_fn((dim, dim), |_| rng.gen_range(-scale..scale));
        let u_b = Array2::from_shape_fn((dim, dim), |_| rng.gen_range(-scale..scale));
        let b_b = Array1::zeros(dim);
        Self { w_f, u_f, b_f, w_b, u_b, b_b }
    }

    /// 正向更新：计算新的正向状态
    /// coupling 为耦合调制因子，攻击信号强时放大交叉耦合项
    fn step_forward(&self, h_f_prev: &Array1<f64>, h_b_curr: &Array1<f64>, coupling: f64) -> Array1<f64> {
        let mut sum = self.w_f.dot(h_f_prev);
        sum += &(self.u_f.mapv(|x| x * coupling)).dot(h_b_curr);
        sum += &self.b_f;
        sum.mapv(|x| x.tanh())
    }

    /// 逆向更新：计算新的逆向状态
    /// coupling 为耦合调制因子，攻击信号强时放大交叉耦合项
    fn step_backward(&self, h_b_next: &Array1<f64>, h_f_curr: &Array1<f64>, coupling: f64) -> Array1<f64> {
        let mut sum = self.w_b.dot(h_b_next);
        sum += &(self.u_b.mapv(|x| x * coupling)).dot(h_f_curr);
        sum += &self.b_b;
        sum.mapv(|x| x.tanh())
    }
}

/// 双梯形镜像递归网络
pub struct BilateralLadderNetwork {
    layers: Vec<BilateralLadderLayer>,
    state_dim: usize,
    num_layers: usize,
    t_iter: usize, // 递归迭代次数
}

impl BilateralLadderNetwork {
    fn new(num_layers: usize, state_dim: usize, t_iter: usize) -> Self {
        let mut layers = Vec::with_capacity(num_layers);
        for _ in 0..num_layers {
            layers.push(BilateralLadderLayer::new(state_dim));
        }
        Self { layers, state_dim, num_layers, t_iter }
    }

    /// 前向推理：给定初始正向状态向量（输入），通过递归迭代计算最终输出
    ///
    /// 返回最上层的逆向状态作为输出，同时返回完整轨迹用于收敛/振荡分析。
    ///
    /// 输入注入策略：输入向量持续注入到最底层正向状态（h_f[0]），
    /// 而不是只在初始化时设置一次。这样保证输入信息在每一次迭代中
    /// 都参与传播，驱动不同文本走不同的轨迹。
    ///
    /// 耦合调制（attack_signal）：攻击信号越强，层间耦合权重越大，
    /// 使正向-逆向交叉传播更剧烈，从而产生更高的振荡度。
    /// 正常文本（attack_signal=0）使用默认耦合，轨迹稳定收敛；
    /// 攻击文本（attack_signal>0）耦合增强，轨迹振荡加剧。
    #[allow(clippy::type_complexity)]
    fn forward(&self, input: Array1<f64>, attack_signal: f64) -> (Array1<f64>, Vec<Vec<Array1<f64>>>, Vec<Vec<Array1<f64>>>) {
        // 耦合调制因子：攻击信号强时放大交叉耦合
        // attack_signal=0 -> coupling=1.0（正常）
        // attack_signal=1 -> coupling=1.8（攻击，交叉耦合增强80%）
        let coupling = 1.0 + attack_signal * 0.8;

        // 初始化所有层的正向和逆向状态
        let mut h_f: Vec<Array1<f64>> = (0..self.num_layers)
            .map(|_| Array1::zeros(self.state_dim))
            .collect();
        let mut h_b: Vec<Array1<f64>> = (0..self.num_layers)
            .map(|_| Array1::zeros(self.state_dim))
            .collect();

        // 记录轨迹（含初始状态）
        let mut h_f_traj: Vec<Vec<Array1<f64>>> = Vec::new();
        let mut h_b_traj: Vec<Vec<Array1<f64>>> = Vec::new();
        h_f_traj.push(h_f.clone());
        h_b_traj.push(h_b.clone());

        for _ in 0..self.t_iter {
            // 保存旧状态用于并行更新
            let h_f_old = h_f.clone();
            let h_b_old = h_b.clone();

            // 正向传播（从底层到顶层）
            // 最底层（i=0）持续接收输入注入：h_f[0] = input + 自身递归
            for i in 0..self.num_layers {
                let (prev_f, curr_b) = if i == 0 {
                    // 底层：输入 + 交叉耦合
                    (&input, &h_b_old[0])
                } else {
                    (&h_f_old[i - 1], &h_b_old[i])
                };
                h_f[i] = self.layers[i].step_forward(prev_f, curr_b, coupling);
            }
            // 逆向传播（从顶层到底层）
            for i in (0..self.num_layers).rev() {
                let next_b = if i < self.num_layers - 1 { &h_b_old[i + 1] } else { &Array1::zeros(self.state_dim) };
                let curr_f = &h_f[i]; // 使用更新后的正向状态
                h_b[i] = self.layers[i].step_backward(next_b, curr_f, coupling);
            }

            h_f_traj.push(h_f.clone());
            h_b_traj.push(h_b.clone());
        }
        // 返回最上层的逆向状态作为输出
        (h_b[self.num_layers - 1].clone(), h_f_traj, h_b_traj)
    }

    /// 计算递归轨迹的收敛度
    ///
    /// 收敛度 = 所有迭代步骤间状态变化的平均幅度（归一化）。
    /// 值越小表示轨迹越稳定（收敛），值越大表示仍在剧烈变化。
    ///
    /// 与只比较最后两步相比，这里取所有相邻步骤的平均变化，
    /// 更能反映整条轨迹的动态演化特征。正常文本应快速收敛到
    /// 稳定点（平均变化小），攻击文本持续振荡（平均变化大）。
    fn compute_convergence(&self, h_f_traj: &[Vec<Array1<f64>>], h_b_traj: &[Vec<Array1<f64>>]) -> f64 {
        if h_f_traj.len() < 2 {
            return 0.0;
        }

        let mut total_diff = 0.0;
        let mut count = 0usize;
        for t in 1..h_f_traj.len() {
            for i in 0..self.num_layers {
                let diff_f = rms_diff(&h_f_traj[t][i], &h_f_traj[t - 1][i]);
                let diff_b = rms_diff(&h_b_traj[t][i], &h_b_traj[t - 1][i]);
                total_diff += diff_f + diff_b;
                count += 2;
            }
        }
        if count == 0 {
            return 0.0;
        }
        (total_diff / count as f64 * 12.0).min(1.0)
    }

    /// 计算递归轨迹的振荡度
    ///
    /// 振荡度衡量轨迹在迭代过程中是否出现"来回震荡"。
    /// 正常文本的轨迹应单调收敛（变化幅度逐次递减），
    /// 攻击文本的轨迹可能出现"反弹"（变化幅度先减后增）
    /// 或"衰减缓慢"（最后一步变化仍然很大）。
    fn compute_oscillation(&self, h_f_traj: &[Vec<Array1<f64>>], h_b_traj: &[Vec<Array1<f64>>]) -> f64 {
        if h_f_traj.len() < 3 {
            return 0.0;
        }

        // 计算每步的变化幅度序列
        let mut step_magnitudes: Vec<f64> = Vec::new();
        for t in 1..h_f_traj.len() {
            let mut total_mag = 0.0;
            for i in 0..self.num_layers {
                let diff_f = rms_diff(&h_f_traj[t][i], &h_f_traj[t - 1][i]);
                let diff_b = rms_diff(&h_b_traj[t][i], &h_b_traj[t - 1][i]);
                total_mag += diff_f + diff_b;
            }
            step_magnitudes.push(total_mag / (self.num_layers as f64 * 2.0));
        }

        if step_magnitudes.is_empty() {
            return 0.0;
        }

        // 1. 反弹检测：检查变化幅度是否单调递减
        let mut rebounds = 0usize;
        for t in 1..step_magnitudes.len() {
            if step_magnitudes[t] > step_magnitudes[t - 1] * 1.05 {
                rebounds += 1;
            }
        }
        let rebound_score = rebounds as f64 / (step_magnitudes.len().saturating_sub(1)).max(1) as f64;

        // 2. 衰减速率检测：最后一步 vs 第一步的比例
        let decay_ratio = step_magnitudes[step_magnitudes.len() - 1] / step_magnitudes[0].max(1e-8);
        let decay_score = if decay_ratio < 0.10 {
            0.0 // 快速衰减，正常
        } else if decay_ratio < 0.15 {
            0.2 // 中等衰减
        } else if decay_ratio < 0.25 {
            0.5 // 缓慢衰减
        } else {
            0.8 // 非常缓慢，异常
        };

        // 3. 衰减一致性检测：检查衰减是否均匀（平台期）
        let mut plateau_count = 0usize;
        for t in 1..step_magnitudes.len() {
            let ratio = step_magnitudes[t] / step_magnitudes[t - 1].max(1e-8);
            if (0.95..=1.05).contains(&ratio) {
                plateau_count += 1;
            }
        }
        let plateau_score = plateau_count as f64 / (step_magnitudes.len().saturating_sub(1)).max(1) as f64;

        // 综合得分：反弹 + 衰减 + 平台
        (rebound_score * 0.4 + decay_score * 0.4 + plateau_score * 0.2).min(1.0)
    }

    /// 检查是否在 3 次迭代内快速收敛
    fn check_early_convergence(&self, h_f_traj: &[Vec<Array1<f64>>]) -> bool {
        if h_f_traj.len() < 4 {
            return false;
        }
        let t2 = &h_f_traj[2];
        let t3 = &h_f_traj[3];
        let mut total_diff = 0.0;
        for i in 0..self.num_layers {
            total_diff += mean_abs(&t3[i], &t2[i]);
        }
        (total_diff / self.num_layers as f64) < 0.05
    }
}

/// 计算两个向量逐元素绝对差值的均值
fn mean_abs(a: &Array1<f64>, b: &Array1<f64>) -> f64 {
    let mut s = 0.0;
    for i in 0..a.len() {
        s += (a[i] - b[i]).abs();
    }
    s / a.len() as f64
}

/// 计算两个向量的 RMS 差异（均方根）
fn rms_diff(a: &Array1<f64>, b: &Array1<f64>) -> f64 {
    let mut s = 0.0;
    for i in 0..a.len() {
        let d = a[i] - b[i];
        s += d * d;
    }
    (s / a.len() as f64).sqrt()
}

/// 双梯形递归检测器（PyO3 暴露类）
///
/// 将双梯形镜像递归网络集成到玄盾检测流程中的前置钩子。
/// 对于被外门判定为"不确定/边界模糊"的请求，先经过递归层处理，
/// 输出"递归置信度"和"轨迹振荡度"作为 fused_anomaly 的增强信号。
#[pyclass]
pub struct BilateralLadderDetector {
    network: BilateralLadderNetwork,
}

#[pymethods]
impl BilateralLadderDetector {
    /// 初始化双梯形递归检测器
    ///
    /// Args:
    ///   num_layers: 递归层数（默认 3）
    ///   state_dim: 状态向量维度（默认 64）
    ///   t_iter: 递归迭代次数（默认 5）
    #[new]
    fn new(num_layers: usize, state_dim: usize, t_iter: usize) -> Self {
        Self {
            network: BilateralLadderNetwork::new(num_layers, state_dim, t_iter),
        }
    }

    /// 将文本转换为固定维度的向量（用于递归网络输入）
    ///
    /// 除 Unicode 码点散列外，加入 8 维统计特征，使不同语义文本
    /// 产生差异更大的向量，从而驱动递归网络走不同的轨迹。
    fn text_to_vector(&self, text: &str) -> Vec<f64> {
        let state_dim = self.network.state_dim;
        let mut vec = vec![0.0f64; state_dim];
        if text.is_empty() {
            return vec;
        }

        let text_len = text.chars().count();
        let data = text.as_bytes();
        let data_len = data.len() as f64;

        // ── 码点散列（state_dim - 8 维） ──
        let hash_dim = state_dim - 8;
        for (i, ch) in text.chars().enumerate() {
            let cp = ch as u64;
            let idx1 = (cp.wrapping_mul(2654435761) as usize) % hash_dim;
            let idx2 = (cp.wrapping_mul(2246822519) as usize) % hash_dim;
            let idx3 = (cp.wrapping_mul(3266489917) as usize) % hash_dim;
            let pos_weight = 1.0 + 0.01 * (i as f64 + 1.0).ln();
            vec[idx1] += (cp & 0xFF) as f64 / 255.0 * pos_weight;
            vec[idx2] += ((cp >> 8) & 0xFF) as f64 / 255.0 * pos_weight;
            vec[idx3] += 0.1 * pos_weight;
        }

        // ── 统计特征（8 维） ──
        let offset = hash_dim;

        // 1. 字节熵
        if data_len > 0.0 {
            let mut byte_counts = [0u64; 256];
            for &b in data {
                byte_counts[b as usize] += 1;
            }
            let mut entropy = 0.0;
            for &c in byte_counts.iter() {
                if c > 0 {
                    let p = c as f64 / data_len;
                    entropy -= p * p.log2();
                }
            }
            vec[offset] = (entropy / 8.0).min(1.0);
        }

        // 2. 可打印字符比
        let printable = text.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()
            || *c == '\n' || *c == '\r' || *c == '\t').count();
        vec[offset + 1] = if text_len > 0 { printable as f64 / text_len as f64 } else { 0.0 };

        // 3. 大写比例
        let upper = text.chars().filter(|c| c.is_uppercase()).count();
        vec[offset + 2] = if text_len > 0 { upper as f64 / text_len as f64 } else { 0.0 };

        // 4. 特殊字符密度（非字母数字、非空格、非标点）
        let special = text.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()
            && !".,!?;:'\"-()[]{}".contains(*c)).count();
        vec[offset + 3] = (special as f64 / text_len.max(1) as f64 * 3.0).min(1.0);

        // 5. 平均词长
        let words: Vec<&str> = text.split_whitespace().collect();
        let avg_word_len = if words.is_empty() {
            0.0
        } else {
            words.iter().map(|w| w.chars().count() as f64).sum::<f64>() / words.len() as f64
        };
        vec[offset + 4] = (avg_word_len / 15.0).min(1.0);

        // 6. 标点密度
        let punct = text.chars().filter(|c| ".,!?;:'\"-()[]{}".contains(*c)).count();
        vec[offset + 5] = if text_len > 0 { punct as f64 / text_len as f64 } else { 0.0 };

        // 7. 数字密度
        let digits = text.chars().filter(|c| c.is_ascii_digit()).count();
        vec[offset + 6] = if text_len > 0 { digits as f64 / text_len as f64 } else { 0.0 };

        // 8. 空白符比例
        let spaces = text.chars().filter(|c| c.is_whitespace()).count();
        vec[offset + 7] = if text_len > 0 { spaces as f64 / text_len as f64 } else { 0.0 };

        // L2 归一化
        let norm: f64 = vec.iter().map(|v| v * v).sum::<f64>().sqrt();
        if norm > 1e-8 {
            for v in vec.iter_mut() {
                *v /= norm;
            }
        }

        vec
    }

    /// 提取文本的攻击信号强度（0.0~1.0）
    ///
    /// 基于关键词命中数加权，攻击信号强时耦合调制放大振荡。
    /// 这是纯规则层面的快速估计，用于调制递归轨迹的耦合强度。
    fn _extract_attack_signal(&self, text: &str) -> f64 {
        let lower = text.to_lowercase();
        // 攻击关键词（角色扮演 / 越狱 / 系统提示词泄露 / 过度代理）
        let keywords = [
            "ignore", "instructions", "system prompt", "developer mode",
            "dan mode", "jailbreak", "no restrictions", "no limits",
            "roleplay", "pretend", "act as", "reveal", "disclose",
            "configuration", "override", "bypass", "restrictions",
            "security rules", "unrestricted", "do anything",
        ];
        let mut hits = 0usize;
        for kw in keywords.iter() {
            if lower.contains(kw) {
                hits += 1;
            }
        }
        // 命中数映射到 0.0~1.0（3 个关键词即达 0.8）
        (hits as f64 / 3.0).min(1.0)
    }

    /// 分析文本的递归轨迹特征
    ///
    /// Args:
    ///   text: 输入文本
    ///
    /// Returns:
    ///   分析结果字典：
    ///     - convergence: 收敛度（0.0~1.0，越小越稳定）
    ///     - oscillation: 振荡度（0.0~1.0，越大越异常）
    ///     - recursive_confidence: 递归置信度（0.0~1.0，越高越安全）
    ///     - recursive_anomaly: 递归异常度（0.0~1.0，越高越可疑）
    ///     - early_convergence: 是否在 3 次迭代内快速收敛
    fn analyze(&self, text: &str, py: Python<'_>) -> PyResult<PyObject> {
        let input = Array1::from(self.text_to_vector(text));
        let attack_signal = self._extract_attack_signal(text);
        let (output, h_f_traj, h_b_traj) = self.network.forward(input, attack_signal);

        let convergence = self.network.compute_convergence(&h_f_traj, &h_b_traj);
        let oscillation = self.network.compute_oscillation(&h_f_traj, &h_b_traj);
        let early_convergence = self.network.check_early_convergence(&h_f_traj);

        // 递归置信度：收敛且不振荡 → 高置信度（安全）
        let recursive_confidence = ((1.0 - convergence) * (1.0 - oscillation * 0.5)).max(0.0);
        // 递归异常度：振荡且不收敛 → 高异常（攻击）
        let recursive_anomaly = (oscillation * 0.6 + convergence * 0.4).min(1.0);

        let out = PyDict::new(py);
        out.set_item("convergence", convergence)?;
        out.set_item("oscillation", oscillation)?;
        out.set_item("recursive_confidence", recursive_confidence)?;
        out.set_item("recursive_anomaly", recursive_anomaly)?;
        out.set_item("early_convergence", early_convergence)?;
        out.set_item("output_state", output.to_vec())?;
        Ok(out.into_pyobject(py)?.unbind().into())
    }

    /// 获取递归检测对 fused_anomaly 的调整量
    ///
    /// Args:
    ///   text: 输入文本
    ///
    /// Returns:
    ///   (anomaly_boost, confidence_reduction, debug_info)
    ///     - anomaly_boost: fused_anomaly 的增量（0.0~0.5，负值表示降低）
    ///     - confidence_reduction: 信任度降低量（0.0~1.0）
    ///     - debug_info: 调试信息字典
    ///
    /// 决策逻辑（v2）：
    ///   attack_signal 是基于规则提取的攻击强度（0~1），作为主驱动信号。
    ///   结合轨迹振荡/收敛特征，形成"规则 + 动力学"双通道判据：
    ///   - attack_signal 高 → 显著提升 anomaly_boost（即使轨迹区分度有限）
    ///   - attack_signal 低 + 轨迹高振荡 → 轻微提升（边界文本）
    ///   - attack_signal 低 + 轨迹收敛 → 无调整（正常文本）
    fn get_adjustment(&self, text: &str, py: Python<'_>) -> PyResult<PyObject> {
        let input = Array1::from(self.text_to_vector(text));
        let attack_signal = self._extract_attack_signal(text);
        let (_output, h_f_traj, h_b_traj) = self.network.forward(input, attack_signal);

        let convergence = self.network.compute_convergence(&h_f_traj, &h_b_traj);
        let oscillation = self.network.compute_oscillation(&h_f_traj, &h_b_traj);
        let early_convergence = self.network.check_early_convergence(&h_f_traj);

        // 轨迹振荡度受 attack_signal 调制：攻击信号强时振荡显著放大
        let modulated_oscillation = (oscillation + attack_signal * 0.3).min(1.0);

        // 递归置信度：收敛且不振荡 → 高置信度（安全）
        let recursive_confidence = ((1.0 - convergence) * (1.0 - modulated_oscillation * 0.5)).max(0.0);
        // 递归异常度：攻击信号 + 振荡 + 不收敛 → 高异常（攻击）
        let recursive_anomaly = (attack_signal * 0.5 + modulated_oscillation * 0.3 + convergence * 0.2).min(1.0);

        // ── 决策逻辑（v2）：attack_signal 作为主驱动 ──
        let (anomaly_boost, confidence_reduction, reason) = if attack_signal >= 0.5 {
            // 强攻击信号 → 显著提升 anomaly_boost（拦截）
            ((attack_signal * 0.4 + modulated_oscillation * 0.2).min(0.5),
             (attack_signal * 0.5 + modulated_oscillation * 0.3).min(0.8),
             "strong_attack_signal")
        } else if attack_signal >= 0.2 {
            // 中等攻击信号 + 高振荡 → 提升
            ((attack_signal * 0.3 + modulated_oscillation * 0.15).min(0.4),
             (attack_signal * 0.4 + modulated_oscillation * 0.2).min(0.6),
             "moderate_attack_signal")
        } else if early_convergence && recursive_confidence > 0.5 {
            // 低攻击信号 + 快速收敛 → 降低 fused_anomaly（放行）
            (-0.10, 0.0, "early_convergence_low_signal")
        } else if modulated_oscillation > 0.5 {
            // 低攻击信号但轨迹高振荡只记录边界状态，不单独提升风险。
            // 随机动力学轨迹可能产生振荡，必须有规则攻击信号才能拦截。
            (0.0, 0.0, "high_oscillation_low_signal")
        } else {
            // 正常 → 无调整
            (0.0, 0.0, "normal")
        };

        let debug = PyDict::new(py);
        debug.set_item("convergence", convergence)?;
        debug.set_item("oscillation", oscillation)?;
        debug.set_item("modulated_oscillation", modulated_oscillation)?;
        debug.set_item("attack_signal", attack_signal)?;
        debug.set_item("recursive_confidence", recursive_confidence)?;
        debug.set_item("recursive_anomaly", recursive_anomaly)?;
        debug.set_item("early_convergence", early_convergence)?;
        debug.set_item("adjustment_reason", reason)?;

        let tuple = (anomaly_boost, confidence_reduction, debug);
        Ok(tuple.into_pyobject(py)?.unbind().into())
    }

    /// 一次性完成 analyze + get_adjustment（P1-3 修复：消除双重 forward 调用）
    ///
    /// 合并 analyze() 和 get_adjustment() 为单次 forward() 调用，
    /// 返回 analyze 结果字典和 adjustment 元组。
    ///
    /// Returns:
    ///   (anomaly_boost, confidence_reduction, debug_info, analyze_dict)
    fn analyze_and_adjust(&self, text: &str, py: Python<'_>) -> PyResult<PyObject> {
        let input = Array1::from(self.text_to_vector(text));
        let attack_signal = self._extract_attack_signal(text);
        let (output, h_f_traj, h_b_traj) = self.network.forward(input, attack_signal);

        let convergence = self.network.compute_convergence(&h_f_traj, &h_b_traj);
        let oscillation = self.network.compute_oscillation(&h_f_traj, &h_b_traj);
        let early_convergence = self.network.check_early_convergence(&h_f_traj);

        // 轨迹振荡度受 attack_signal 调制
        let modulated_oscillation = (oscillation + attack_signal * 0.3).min(1.0);

        let recursive_confidence = ((1.0 - convergence) * (1.0 - modulated_oscillation * 0.5)).max(0.0);
        let recursive_anomaly = (attack_signal * 0.5 + modulated_oscillation * 0.3 + convergence * 0.2).min(1.0);

        // ── 决策逻辑（v2）：与 get_adjustment 完全一致 ──
        let (anomaly_boost, confidence_reduction, reason) = if attack_signal >= 0.5 {
            ((attack_signal * 0.4 + modulated_oscillation * 0.2).min(0.5),
             (attack_signal * 0.5 + modulated_oscillation * 0.3).min(0.8),
             "strong_attack_signal")
        } else if attack_signal >= 0.2 {
            ((attack_signal * 0.3 + modulated_oscillation * 0.15).min(0.4),
             (attack_signal * 0.4 + modulated_oscillation * 0.2).min(0.6),
             "moderate_attack_signal")
        } else if early_convergence && recursive_confidence > 0.5 {
            (-0.10, 0.0, "early_convergence_low_signal")
        } else if modulated_oscillation > 0.5 {
            (0.0, 0.0, "high_oscillation_low_signal")
        } else {
            (0.0, 0.0, "normal")
        };

        // 构建 adjustment debug 字典
        let debug = PyDict::new(py);
        debug.set_item("convergence", convergence)?;
        debug.set_item("oscillation", oscillation)?;
        debug.set_item("modulated_oscillation", modulated_oscillation)?;
        debug.set_item("attack_signal", attack_signal)?;
        debug.set_item("recursive_confidence", recursive_confidence)?;
        debug.set_item("recursive_anomaly", recursive_anomaly)?;
        debug.set_item("early_convergence", early_convergence)?;
        debug.set_item("adjustment_reason", reason)?;

        // 构建 analyze 结果字典
        let analyze_dict = PyDict::new(py);
        analyze_dict.set_item("convergence", convergence)?;
        analyze_dict.set_item("oscillation", oscillation)?;
        analyze_dict.set_item("recursive_confidence", recursive_confidence)?;
        analyze_dict.set_item("recursive_anomaly", recursive_anomaly)?;
        analyze_dict.set_item("early_convergence", early_convergence)?;
        analyze_dict.set_item("output_state", output.to_vec())?;

        // 返回 (anomaly_boost, confidence_reduction, debug_info, analyze_dict)
        let tuple = (anomaly_boost, confidence_reduction, debug, analyze_dict);
        Ok(tuple.into_pyobject(py)?.unbind().into())
    }
}

/// PyO3 模块入口
#[pymodule]
fn daoti_xuandun_pyo3(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BilateralLadderDetector>()?;
    Ok(())
}