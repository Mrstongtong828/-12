@echo off
:: 使用 65001 (UTF-8) 编码防止中文显示乱码
chcp 65001 >nul
color 0B

echo =======================================================
echo          团队专属比赛启动器 V2.1 (防断流修复版)
echo =======================================================
echo.

:: 强制切换到脚本所在的目录
cd /d "%~dp0"

:: --- 1. 智能探测与唤醒 Docker ---
echo [状态] 正在检测 Docker 引擎状态...
docker info >nul 2>&1
if %ERRORLEVEL% equ 0 goto DOCKER_READY

echo [状态] 发现 Docker 未运行，正在为你唤醒它...
:: 👇👇👇 队友修改位置 1：Docker 安装路径 👇👇👇
if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
) else (
    echo.
    echo ❌ [致命错误] 找不到 Docker 软件！
    echo 请确认 Docker 是否安装在 C 盘。如果不在，请右键编辑本脚本修改路径！
    pause
    exit
)
:: 👆👆👆 队友修改位置 1 👆👆👆

echo [状态] 正在智能等待 Docker 引擎就绪 (请耐心等待)...

:WAIT_DOCKER
timeout /t 3 /nobreak >nul
docker info >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [状态] 引擎还在预热中，请稍候...
    goto WAIT_DOCKER
)

:DOCKER_READY
echo [状态] ✅ 太棒了！Docker 引擎已完全启动并就绪！
echo.

:: --- 2. 检查配置文件 ---
if not exist "docker-compose.yml" (
    echo.
    echo ❌ [错误] 找不到 docker-compose.yml 文件！
    echo 请把这个脚本文件移动到和 docker-compose.yml 同一个文件夹里！
    pause
    exit
)

:: --- 3. 启动数据库集装箱 ---
echo [状态] 正在执行启动指令，拉起比赛数据库...
:: ⚠️ 关键修复：加入 call 防止脚本运行完 docker-compose 后意外退出
call docker-compose up -d

if %ERRORLEVEL% neq 0 (
    echo.
    echo ❌ [错误] 数据库启动失败！请检查端口是否被占用。
    pause
    exit
)

echo [状态] ✅ 数据库已成功在后台运行。
echo.

:: --- 4. 召唤 DBeaver ---
echo [状态] 正在召唤 DBeaver...

:: ⚠️ 关键修复：拆解 else if 逻辑，防止不可见空格导致脚本崩溃
:: 👇👇👇 队友修改位置 2：DBeaver 安装路径 👇👇👇
if exist "C:\Program Files\DBeaver\dbeaver.exe" (
    start "" "C:\Program Files\DBeaver\dbeaver.exe"
    goto END_SUCCESS
)

if exist "%LOCALAPPDATA%\DBeaver\dbeaver.exe" (
    start "" "%LOCALAPPDATA%\DBeaver\dbeaver.exe"
    goto END_SUCCESS
)

echo [警告] 找不到 DBeaver 软件，请自行在桌面上双击打开它。
:: 👆👆👆 队友修改位置 2 👆👆👆

:END_SUCCESS
echo.
echo =======================================================
echo    🚀 一切就绪！请在 DBeaver 中双击连接！
echo =======================================================
:: 暂停 5 秒让你能看到结果，然后自动关闭
timeout /t 5 /nobreak >nul
exit