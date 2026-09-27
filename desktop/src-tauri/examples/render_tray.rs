// SPDX-License-Identifier: DaoTi-Research-1.0
// Copyright (c) 2026 独立研究者，知白

//! 托盘图标离线渲染器 —— 把四种状态的光栅化结果输出为 PNG。
//!
//! 用途：单元测试能证明「颜色值等于设计令牌」，
//! 但证明不了「盾牌在 16~24px 下看起来仍像盾牌」。
//! 本工具按托盘的真实显示尺寸（含 1× 与 2× DPI）渲染，肉眼可验。
//!
//! 用法：cargo run --example render_tray -- <输出目录>

use std::fs;

const SHIELD: [(f32, f32); 7] = [
    (4.0, 3.5),
    (28.0, 3.5),
    (28.0, 15.0),
    (24.0, 24.0),
    (16.0, 29.5),
    (8.0, 24.0),
    (4.0, 15.0),
];

const STATES: [(&str, (u8, u8, u8)); 4] = [
    ("safe", (0x00, 0xD4, 0xAA)),
    ("suspect", (0xF5, 0xA6, 0x23)),
    ("danger", (0xE5, 0x4D, 0x4D)),
    ("paused", (0x5A, 0x60, 0x68)),
];

fn point_in_poly(px: f32, py: f32) -> bool {
    let mut inside = false;
    let n = SHIELD.len();
    let mut j = n - 1;
    for i in 0..n {
        let (xi, yi) = SHIELD[i];
        let (xj, yj) = SHIELD[j];
        if (yi > py) != (yj > py) {
            let x_cross = (xj - xi) * (py - yi) / (yj - yi) + xi;
            if px < x_cross {
                inside = !inside;
            }
        }
        j = i;
    }
    inside
}

fn render(size: u32, rgb: (u8, u8, u8)) -> Vec<u8> {
    const SS: usize = 3;
    let mut buf = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let mut hits = 0u8;
            for sy in 0..SS {
                for sx in 0..SS {
                    let px = x as f32 + (sx as f32 + 0.5) / SS as f32;
                    let py = y as f32 + (sy as f32 + 0.5) / SS as f32;
                    if point_in_poly(px / size as f32 * 32.0, py / size as f32 * 32.0) {
                        hits += 1;
                    }
                }
            }
            buf.push(rgb.0);
            buf.push(rgb.1);
            buf.push(rgb.2);
            buf.push((hits as u16 * 255 / (SS * SS) as u16) as u8);
        }
    }
    buf
}

/// 极简 PNG 编码（RGBA8，无过滤）。
///
/// 不引第三方依赖：验证脚本不该给项目新增依赖树，
/// 且这段代码只服务离线出图，正确性由肉眼看图兜底。
fn write_png(path: &str, size: u32, rgba: &[u8]) {
    use std::io::Write;

    fn crc32(data: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for (i, item) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *item = c;
        }
        let mut crc = 0xFFFF_FFFFu32;
        for b in data {
            crc = table[((crc ^ *b as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        crc ^ 0xFFFF_FFFF
    }

    fn chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = Vec::with_capacity(4 + data.len());
        body.extend_from_slice(tag);
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
    }

    // 每行前置 filter byte 0（None）
    let w = size as usize;
    let mut raw = Vec::with_capacity((w * w * 4 + w) as usize);
    for y in 0..w {
        raw.push(0u8);
        let start = y * w * 4;
        raw.extend_from_slice(&rgba[start..start + w * 4]);
    }

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8bit + color type 6 (RGBA)

    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &zlib_store(&raw));
    chunk(&mut png, b"IEND", &[]);

    let mut f = fs::File::create(path).expect("创建 PNG 失败");
    f.write_all(&png).expect("写 PNG 失败");
}

/// zlib 存储块（不压缩）—— 免去 deflate 依赖。
fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01]; // CMF/FLG：deflate + 32K 窗口
    let mut i = 0;
    while i < data.len() {
        let n = std::cmp::min(65535, data.len() - i);
        let last = if i + n == data.len() { 1u8 } else { 0u8 };
        out.push(last);
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&(!(n as u16)).to_le_bytes());
        out.extend_from_slice(&data[i..i + n]);
        i += n;
    }
    // Adler-32
    let (mut a, mut b) = (1u32, 0u32);
    for byte in data {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

fn main() {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    // 16 = 托盘在 100% DPI 下的实际显示尺寸，24 = 150% DPI
    for size in [16u32, 24, 32] {
        for (name, rgb) in STATES {
            let path = format!("{out_dir}/tray-{name}-{size}.png");
            write_png(&path, size, &render(size, rgb));
            println!("{path}");
        }
    }
    println!("\n四态：safe=绿 suspect=黄 danger=红 paused=灰");
}
