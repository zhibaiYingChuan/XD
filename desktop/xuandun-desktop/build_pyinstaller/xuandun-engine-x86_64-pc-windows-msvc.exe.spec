# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.hooks import collect_submodules

datas = []
hiddenimports = ['daoti_xuandun.xuandun', 'daoti_xuandun.luoshu_mapper', 'daoti_xuandun.preprocessors', 'daoti_xuandun.atlas_mapping', 'daoti_xuandun.dynamic_shell', 'daoti_xuandun.timing_checker', 'daoti_xuandun.ancient_mapper', 'daoti_xuandun.reject_gate', 'daoti_xuandun.config', 'daoti_xuandun.types', 'daoti_xuandun.secure_strings', 'anti_debug', 'waitress']
datas += collect_data_files('daoti_xuandun')
hiddenimports += collect_submodules('daoti_xuandun')


a = Analysis(
    ['E:\\smallloong\\XuanDun\\desktop\\xuandun-desktop\\engine_flask.py'],
    pathex=['E:\\smallloong\\XuanDun\\src', 'E:\\smallloong\\XuanDun\\desktop\\xuandun-desktop'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='xuandun-engine-x86_64-pc-windows-msvc.exe',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['E:\\smallloong\\XuanDun\\desktop\\xuandun-desktop\\src-tauri\\icons\\icon.ico'],
)
