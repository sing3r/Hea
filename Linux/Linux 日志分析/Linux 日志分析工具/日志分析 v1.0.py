# -*- coding: utf-8 -*-
import subprocess


# secure 日志分析

def secureLogAnalyze():
    # 使用find命令找到所有名为secure的文件
    find_command = "find ./ -type f -name 'secure*'"
    find_result = subprocess.run(find_command, capture_output=True, text=True, shell=True)

    # 检查find命令是否成功执行
    if find_result.returncode != 0:
        print("查找文件时出错:", find_result.stderr)
        exit()

    # 获取找到的文件列表
    secure_files = find_result.stdout.splitlines()

    # 查找登录失败的日志
    for file in secure_files:
        grep_command = f"grep -a 'Failed password' {file}"
        grep_result = subprocess.run(grep_command, capture_output=True, text=True, shell=True)
        
        if grep_result.stdout:
            print(f"在文件{file}中找到登录失败的日志:")
            print(grep_result.stdout)


    # 查找 SSH 登陆日志
    for file in secure_files:
        grep_command = f"grep -a 'sshd' {file}"
        grep_result = subprocess.run(grep_command, capture_output=True, text=True, shell=True)
        
        if grep_result.stdout:
            print(f"在文件{file}中找到 SSH 登录日志:")
            print(grep_result.stdout)


    # 查找非法用户登陆日志
    for file in secure_files:
        grep_command = f"grep -a 'invalid user' {file}"
        grep_result = subprocess.run(grep_command, capture_output=True, text=True, shell=True)
        
        if grep_result.stdout:
            print(f"在文件{file}中找到 invalid user 登录日志:")
            print(grep_result.stdout)

    # 查找 sudo 认证失败日志
    for file in secure_files:
        grep_command = f"grep -a 'sudo:auth.*not identify' {file} | grep -Po '\[.*?\]' | sort | uniq -c" 
        grep_result = subprocess.run(grep_command, capture_output=True, text=True, shell=True)
        
        if grep_result.stdout:
            print(f"在文件{file}中找到 sudo 认证失败日志，失败认证账号有:")
            print(grep_result.stdout)

    # 查找登录成功的 IP 地址
    for file in secure_files:
        awk_command = r"awk '{print $11}'"
        grep_command = f"grep -a 'Accepted' {file} | {awk_command} | sort | uniq -c" 
        grep_result = subprocess.run(grep_command, capture_output=True, text=True, shell=True)
        
        if grep_result.stdout:
            print(f"在文件{file}中找到成功登录 IP 地址有:")
            print(grep_result.stdout)

def messageLogAnalyze():
    # 使用find命令找到所有名为message的文件
    find_command = "find ./ -type f -name 'message*'"
    find_result = subprocess.run(find_command, capture_output=True, text=True, shell=True)

    # 检查find命令是否成功执行
    if find_result.returncode != 0:
        print("查找文件时出错:", find_result.stderr)
        exit()

    # 获取找到的文件列表
    secure_files = find_result.stdout.splitlines()

    # 查找登录成功的 IP 地址
    for file in secure_files:
        awk_command = r"awk '{print $11}'"
        grep_command = f"grep -a 'Accepted' {file} | {awk_command} | sort | uniq -c" 
        grep_result = subprocess.run(grep_command, capture_output=True, text=True, shell=True)
        
        if grep_result.stdout:
            print(f"在文件{file}中找到成功登录 IP 地址有:")
            print(grep_result.stdout)

# find ./internal-10.194.184.47/ -name "access*" -type f -print0 | xargs -0 cat | awk -F " " '{print $6, $12}' | sort | uniq -c

# find ./10.194.184.47/ -name "access*" -type f -print0 | xargs -0 cat | awk -F " " '{print $1, $7}' | sort | uniq -c
    
secureLogAnalyze()
messageLogAnalyze()