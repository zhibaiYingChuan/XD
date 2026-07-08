import subprocess
import sys
import os
import platform


def build_engine():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    engine_script = os.path.join(script_dir, "engine_flask.py")
    output_dir = os.path.join(script_dir, "src-tauri", "binaries")

    os.makedirs(output_dir, exist_ok=True)

    system = platform.system().lower()
    if system == "windows":
        target = "x86_64-pc-windows-msvc"
        ext = ".exe"
    elif system == "darwin":
        target = f"{platform.machine().lower()}-apple-darwin"
        ext = ""
    else:
        target = f"{platform.machine().lower()}-unknown-linux-gnu"
        ext = ""

    output_name = f"xuandun-engine-{target}{ext}"

    src_dir = os.path.join(project_root, "src")
    icon_path = os.path.join(script_dir, "src-tauri", "icons", "icon.ico")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--noconsole",
        f"--name={output_name}",
        f"--distpath={output_dir}",
        f"--workpath={os.path.join(script_dir, 'build_pyinstaller')}",
        f"--specpath={os.path.join(script_dir, 'build_pyinstaller')}",
        f"--paths={src_dir}",
        f"--paths={script_dir}",
        "--hidden-import=daoti_xuandun.xuandun",
        "--hidden-import=daoti_xuandun.luoshu_mapper",
        "--hidden-import=daoti_xuandun.preprocessors",
        "--hidden-import=daoti_xuandun.atlas_mapping",
        "--hidden-import=daoti_xuandun.dynamic_shell",
        "--hidden-import=daoti_xuandun.timing_checker",
        "--hidden-import=daoti_xuandun.ancient_mapper",
        "--hidden-import=daoti_xuandun.reject_gate",
        "--hidden-import=daoti_xuandun.config",
        "--hidden-import=daoti_xuandun.types",
        "--hidden-import=daoti_xuandun.secure_strings",
        "--hidden-import=anti_debug",
        "--hidden-import=waitress",
        "--collect-submodules=daoti_xuandun",
        "--collect-data=daoti_xuandun",
    ]

    if system == "windows" and os.path.exists(icon_path):
        cmd.append(f"--icon={icon_path}")

    cmd.append(engine_script)

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([src_dir, script_dir])

    print(f"Building: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=env, cwd=script_dir)

    if result.returncode == 0:
        output_path = os.path.join(output_dir, output_name)
        print(f"Build successful: {output_path}")
        if os.path.exists(output_path):
            size_mb = os.path.getsize(output_path) / (1024 * 1024)
            print(f"Size: {size_mb:.1f} MB")
    else:
        print(f"Build failed with code {result.returncode}")
        sys.exit(result.returncode)


if __name__ == "__main__":
    build_engine()
