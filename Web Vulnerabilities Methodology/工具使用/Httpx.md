---
created: 2025-02-10T10:10:00 (UTC +08:00)
tags: []
source: https://mp.weixin.qq.com/s/6IvWw7bVE7QK6YknR1b2YA
author: VlangCN
---

## 引言

在网络安全领域，高效的侦察工具对于发现潜在漏洞至关重要。httpx作为一款功能强大的HTTP探测工具，不仅被包含在Kali Linux的默认工具集中，更是深受安全研究人员的青睐。这款被Kali Linux官方认可的工具，能够帮助安全研究人员快速收集和分析网络服务信息。

对于使用Kali Linux的渗透测试人员来说，httpx已经预装并随时可用，这体现了它在安全评估过程中的重要性。对于其他Linux发行版或操作系统的用户，则需要手动安装这个强大的工具。无论是日常的安全评估，还是大规模的资产梳理，httpx都能提供专业级的探测和分析能力。本文将深入介绍httpx的核心功能与实战应用，帮助您更好地利用这个出色的安全工具。

## 基础用法

### 单主机探测

最简单的使用方式是探测单个主机：

```shell
httpx -u example.com -probe
```

这个命令会检查目标网站是否可访问，并返回基本信息。

### 批量扫描

对于大规模目标，可以从文件读取：

```shell
httpx -l hosts.txt
```

这种方式特别适合子域名枚举后的批量检测。

### 管道操作

httpx支持与其他工具配合使用：

```shell
cat hosts.txt | grep example.com | httpx
```

## 高级功能

### 多端口扫描

网站服务可能运行在非标准端口上：

```shell
httpx -u example.com -ports 80,443,8080,8443
```

这有助于发现隐藏的Web服务。

### 路径测试

可以检测多个路径的存在性：

```shell
httpx -l urls.txt -sc -path "/,/admin,/login,/api"
```

## 信息收集探针

### 常用探针组合

```shell
httpx -status-code -content-type -title -web-server -tech-detect -ip -cname -word-count -response-time
```

这个组合能收集到网站的关键信息：

-   状态码
    
-   内容类型
    
-   页面标题
    
-   服务器类型
    
-   使用的技术栈
    
-   IP地址
    
-   CNAME记录
    
-   响应时间
    

### 性能优化参数

```shell
httpx -t 10 -rate-limit 50 -timeout 5
```

这些参数可以：

-   控制并发线程数
    
-   限制请求速率
    
-   设置超时时间
    

## 高级过滤与匹配

### 状态码过滤

```shell
httpx -l urls.txt -fc&nbsp;404,403,401,500
```

排除常见的错误页面。

### 内容匹配

```shell
httpx -l urls.txt -ms&nbsp;"admin"
```

查找包含特定关键词的响应。

### 正则匹配

```shell
httpx -l urls.txt -mr&nbsp;'admin.*panel'
```

使用正则表达式进行更精确的匹配。

## 输出处理

### JSON格式输出

```shell
httpx -l urls.txt -j -o scan.json
```

便于后续数据处理和分析。

### 响应保存

```shell
httpx -l urls.txt -sr responses/
```

保存完整的HTTP响应内容。

### 截图功能

```shell
httpx -l urls.txt -ss -st 10
```

自动捕获页面截图，便于视觉分析。

### 我的实践

```shell
Httpx -l domianList -status-code -content-type -title -web-server -tech-detect -ip -cname -word-count -response-time -o HttpxScan.json -p http:1-65535,https:1-65535
```

## 实战应用场景

### 安全评估

1.  资产发现
    

-   扫描子域名
    
-   识别活跃服务
    
-   技术栈分析
    

3.  漏洞前期准备
    

-   路径探测
    
-   服务识别
    
-   响应分析
    

### 资产管理

1.  清点网络服务
    

-   端口映射
    
-   服务类型识别
    
-   技术栈统计
    

3.  变更监控
    

-   定期扫描
    
-   对比分析
    
-   异常检测
    

## 最佳实践

1.  **扫描策略**
    

-   从小规模开始
    
-   逐步增加并发
    
-   注意目标承受能力
    

3.  **数据处理**
    

-   使用JSON输出
    
-   编写分析脚本
    
-   建立知识库
    

5.  **效率优化**
    

-   合理设置超时
    
-   控制请求速率
    
-   避免过度扫描
    

## 总结

httpx作为一款现代化的HTTP探测工具，其强大的功能和灵活的配置使其成为安全研究人员不可或缺的工具。通过合理使用其各项功能，可以大大提高侦察和评估的效率。在实际应用中，需要根据具体场景选择适当的参数和功能，同时注意遵守相关法律法规和目标系统的使用策略。

掌握httpx不仅能提高工作效率，还能帮助我们更好地理解和保护网络系统。随着网络安全领域的不断发展，类似httpx这样的工具将发挥越来越重要的作用。



