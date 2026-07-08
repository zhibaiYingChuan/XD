import math
import os
from PIL import Image, ImageDraw, ImageFont

BG_COLOR = (26, 26, 46)
SHIELD_COLOR = (226, 183, 20)
SHIELD_DARK = (180, 145, 15)
SHIELD_LIGHT = (255, 210, 60)
BORDER_COLOR = (226, 183, 20)
SYMBOL_COLOR = (26, 26, 46)
OUTER_BORDER_COLOR = (200, 165, 20)

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src-tauri", "icons")


def draw_shield(draw, cx, cy, size):
    w = size * 0.38
    h = size * 0.44
    top_y = cy - h * 0.65
    mid_y = cy + h * 0.05
    bot_y = cy + h * 0.75

    points = [
        (cx - w, top_y),
        (cx - w, mid_y),
        (cx - w * 0.5, bot_y),
        (cx, bot_y + h * 0.1),
        (cx + w * 0.5, bot_y),
        (cx + w, mid_y),
        (cx + w, top_y),
    ]

    draw.polygon(points, fill=SHIELD_COLOR, outline=BORDER_COLOR)

    inner_w = w * 0.82
    inner_h = h * 0.82
    inner_top = cy - inner_h * 0.60
    inner_mid = cy + inner_h * 0.08
    inner_bot = cy + inner_h * 0.68

    inner_points = [
        (cx - inner_w, inner_top),
        (cx - inner_w, inner_mid),
        (cx - inner_w * 0.5, inner_bot),
        (cx, inner_bot + inner_h * 0.08),
        (cx + inner_w * 0.5, inner_bot),
        (cx + inner_w, inner_mid),
        (cx + inner_w, inner_top),
    ]

    draw.polygon(inner_points, fill=SHIELD_DARK, outline=None)

    return inner_top, inner_bot, inner_w


def draw_xuan_symbol(draw, cx, cy, size):
    s = size * 0.12
    lw = max(1, int(size * 0.025))

    top = cy - s
    bot = cy + s
    left = cx - s
    right = cx + s

    draw.line([(left, top), (right, bot)], fill=SYMBOL_COLOR, width=lw)
    draw.line([(right, top), (left, bot)], fill=SYMBOL_COLOR, width=lw)

    mid_y = cy
    draw.line([(left, mid_y), (right, mid_y)], fill=SYMBOL_COLOR, width=lw)

    hook_s = s * 0.4
    draw.arc(
        [cx - hook_s, top - hook_s * 0.3, cx + hook_s, top + hook_s * 0.7],
        start=180, end=360, fill=SYMBOL_COLOR, width=lw
    )

    dot_r = max(1, int(size * 0.015))
    draw.ellipse(
        [cx - dot_r, bot + dot_r * 0.5, cx + dot_r, bot + dot_r * 2.5],
        fill=SYMBOL_COLOR
    )


def draw_rounded_rect(draw, bbox, radius, fill, outline=None, width=1):
    x0, y0, x1, y1 = bbox
    draw.rounded_rectangle(bbox, radius=radius, fill=fill, outline=outline, width=width)


def generate_icon(size):
    img = Image.new("RGBA", (size, size), BG_COLOR + (255,))
    draw = ImageDraw.Draw(img)

    margin = max(2, int(size * 0.04))
    radius = max(2, int(size * 0.12))
    border_w = max(1, int(size * 0.02))

    draw_rounded_rect(
        draw,
        [margin, margin, size - margin, size - margin],
        radius=radius,
        fill=None,
        outline=OUTER_BORDER_COLOR,
        width=border_w,
    )

    cx, cy = size // 2, size // 2 - int(size * 0.02)
    draw_shield(draw, cx, cy, size)
    draw_xuan_symbol(draw, cx, cy + int(size * 0.01), size)

    return img


def create_ico(sizes_list, output_path):
    images = []
    for s in sizes_list:
        images.append(generate_icon(s))
    images[0].save(
        output_path,
        format="ICO",
        sizes=[(s, s) for s in sizes_list],
        append_images=images[1:],
    )


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    icon_configs = [
        ("32x32.png", 32),
        ("128x128.png", 128),
        ("128x128@2x.png", 256),
        ("icon.png", 512),
    ]

    for filename, size in icon_configs:
        img = generate_icon(size)
        filepath = os.path.join(OUTPUT_DIR, filename)
        img.save(filepath, "PNG")
        print(f"Generated: {filepath} ({size}x{size})")

    ico_path = os.path.join(OUTPUT_DIR, "icon.ico")
    create_ico([16, 32, 48, 64, 128, 256], ico_path)
    print(f"Generated: {ico_path} (ICO)")

    print("\nAll icons generated successfully!")


if __name__ == "__main__":
    main()
