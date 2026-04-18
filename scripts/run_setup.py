import subprocess
import sys

project_dir = r"E:\数据库敏感字段识别与安全管控系统\项目"

# 激活虚拟环境并安装依赖
activate = subprocess.run(
    [sys.executable, "-m", "venv", "venv311"],
    cwd=project_dir,
    capture_output=True, text=True
)
print("激活虚拟环境:", activate.returncode)

# 使用虚拟环境中的pip安装
pip_path = subprocess.run(
    [r"venv311\Scripts\python.exe", "-m", "pip", "install", "-r", "requirements.txt"],
    cwd=project_dir,
    capture_output=True, text=True
)
print("安装依赖:", pip_path.returncode)
print(pip_path.stdout[:500])
print(pip_path.stderr[:500] if pip_path.stderr else "")
