# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: один переносимый EXE (RDPConnectionMonitor.exe), без консоли, без запроса UAC.
#
#   pyinstaller --noconfirm --clean rdp_monitor.spec
#
# Если на компьютере политика AppLocker/WDAC запрещает запуск из %TEMP% (куда распаковывается
# однофайловый EXE), соберите папочную версию:  set RDPMON_ONEDIR=1  и запустите сборку снова.
import os

ONEDIR = os.environ.get("RDPMON_ONEDIR") == "1"

# Модули Qt, которые приложению не нужны — уменьшают размер EXE
QT_EXCLUDES = [
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtMultimedia", "PySide6.QtSql",
    "PySide6.QtTest", "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtDesigner", "PySide6.QtHelp",
    "PySide6.QtXml", "PySide6.QtConcurrent", "PySide6.QtDBus", "PySide6.QtPrintSupport",
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[("assets", "assets")],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "PIL", "numpy", *QT_EXCLUDES],
    noarchive=False,
)
pyz = PYZ(a.pure)

common = dict(
    name="RDPConnectionMonitor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # UPX часто вызывает ложные срабатывания антивирусов
    console=False,             # --windowed
    disable_windowed_traceback=False,
    uac_admin=False,           # requestedExecutionLevel = asInvoker
    uac_uiaccess=False,
    icon="assets/icons/app.ico",
    version="version_info.txt",
    manifest="rdp_monitor.manifest",
)

if not ONEDIR:
    # --onefile
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], runtime_tmpdir=None, **common)
else:
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, **common)
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="RDPConnectionMonitor")
