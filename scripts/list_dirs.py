import os

project = r"E:\数据库敏感字段识别与安全管控系统\项目"
print("所有目录:")
for item in os.listdir(project):
    full = os.path.join(project, item)
    if os.path.isdir(full):
        print(f"  [DIR] {item}")
