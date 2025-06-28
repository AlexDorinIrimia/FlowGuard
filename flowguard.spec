# flowguard_backend.spec

# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.building.api import PYZ, EXE, COLLECT
from PyInstaller.building.build_main import Analysis
import os

block_cipher = None

a = Analysis(
    ['run_ids.py'],  # Main entry point
    pathex=[os.path.abspath('.')],

    binaries=[
        # Include xgboost.dll unde îl caută xgboost
        ('libs/xgboost/lib/xgboost.dll', 'xgboost/lib'),

        # Alte biblioteci native
        ('libs/msvcp140.dll', '.'),
        ('libs/libscipy_openblas64.dll', '.'),
    ],

    datas=[
        # Modele ML
        ('ml_model/models/*', 'ml_model/models'),

        # Web UI - HTML & statice
        ('web_ui/static/*', 'web_ui/static'),
        ('web_ui/templates/*', 'web_ui/templates'),

        # Fișierul VERSION necesar pentru xgboost
        ('libs/xgboost/VERSION', 'xgboost'),
        ('logs/', 'logs'),
    ],

    hiddenimports=(
        collect_submodules('scapy') +
        collect_submodules('tensorflow') +
        collect_submodules('sklearn') +
        collect_submodules('joblib') +
        collect_submodules('backend') +
        collect_submodules('flask_socketio') +
        collect_submodules('socketio') +
        collect_submodules('engineio') +
        [
            'plyer.platforms.win.notification',
            'plyer.platforms.linux.notification',
            'plyer.platforms.darwin.notification',
        ]
    ),

    hookspath=[],
    runtime_hooks=[],
    excludes=['xgboost.testing'],
    cipher=block_cipher
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='flowguard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='flowguard'
)
