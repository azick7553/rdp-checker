@echo off
REM ============================================================
REM  Сборка RDPConnectionMonitor.exe (выполняется на машине разработчика)
REM  Требуется Python 3.12+ и доступ к PyPI. На целевом ПК ничего ставить не нужно.
REM
REM    build.bat          - один EXE: dist\RDPConnectionMonitor.exe
REM    build.bat onedir   - папка dist\RDPConnectionMonitor\ (если AppLocker блокирует %TEMP%)
REM ============================================================
setlocal
chcp 65001 >nul
cd /d "%~dp0"

set "PY=python"
where py >nul 2>nul && set "PY=py -3"

if not exist ".venv-build\Scripts\python.exe" (
    echo [1/4] Создание виртуального окружения...
    %PY% -m venv .venv-build || goto :error
)
call ".venv-build\Scripts\activate.bat" || goto :error

echo [2/4] Установка зависимостей...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements-dev.txt || goto :error

echo [3/4] Тесты...
python -m pytest -q || goto :error

if /I "%~1"=="onedir" (set "RDPMON_ONEDIR=1") else (set "RDPMON_ONEDIR=")

echo [4/4] PyInstaller...
python -m PyInstaller --noconfirm --clean rdp_monitor.spec || goto :error

echo.
if defined RDPMON_ONEDIR (
    echo Готово: dist\RDPConnectionMonitor\RDPConnectionMonitor.exe
) else (
    echo Готово: dist\RDPConnectionMonitor.exe
)
exit /b 0

:error
echo.
echo ОШИБКА СБОРКИ (код %errorlevel%)
exit /b 1
