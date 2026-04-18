import os

project = r"E:\数据库敏感字段识别与安全管控系统\项目"

# 查找所有脚本文件
for root, dirs, files in os.walk(project):
    for f in files:
        if f.endswith(('.py', '.sql', '.sh', '.bat', '.ps1', '.yml', '.yaml')):
            full = os.path.join(root, f)
            rel = os.path.relpath(full, project)
            print(rel)
