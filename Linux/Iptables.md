# iptables 配置指引

## 帮助信息
选项：

  * --append (-A) chain：向链中追加
  * --check (-C) chain：检查链中是否存在某个规则
  * --delete (-D) chain：从链中删除匹配的规则
  * --delete (-D) chain rulenum：从链中删除编号为 rulenum（1 表示第一个）的规则
  * --insert (-I) chain [rulenum]：作为指定编号（默认 1 = 第一个）插入链中
  * --replace (-R) chain rulenum：在链中替换编号为 rulenum（1 表示第一个）的规则
  * --list (-L) [chain [rulenum]]：列出指定链或所有链中的规则
  * --list-rules (-S) [chain [rulenum]]：打印指定链或所有链中的规则
  * --flush (-F) [chain]：删除指定链或所有链中的所有规则
  * --zero (-Z) [chain [rulenum]]：将指定链或所有链中的计数器置零
  * --new (-N) chain：创建新的用户自定义链
  * --delete-chain (-X) [chain]：删除一个用户自定义链
  * --policy (-P) chain target：更改链上的策略至目标
  * --rename-chain (-E) old-chain new-chain：更改链名称（移动任何引用）

其他选项：
  * **!** --protocol (-p) proto：协议，按数字或名称指定，如 `tcp'
  * **!** --source (-s) address [/mask][...]：源地址规格
  * **!** --destination (-d) address [/mask][...]：目的地址规格
  * **!** --in-interface (-i) input name [+]：网络接口名称（+ 表示通配符）, 不指定则对所有接口生效
  * --jump (-j) target：规则的目标（可能加载目标扩展）
  * --goto (-g) chain：跳转至链，不返回
  * --match (-m) match：扩展匹配（可能加载扩展）
  * --numeric (-n)：以数字形式输出地址和端口
  * **!** --out-interface (-o) output name [+]：网络接口名称（+ 表示通配符）
  * --table (-t) table：要操作的表（默认为 `filter'）
  * --verbose (-v)：详细模式
  * --wait (-w) [seconds]：获取 xtables 锁前的最大等待时间
  * --wait-interval (-W) [usecs]：尝试获取 xtables 锁的等待时间，默认为 1 秒
  * --line-numbers：在列表时打印行号
  * --exact (-x)：展开数字（显示精确值）
  * **!** --fragment (-f)：仅匹配第二或更多片段
  * --modprobe=<command>：尝试使用指定命令插入模块
  * --set-counters PKTS BYTES：在插入 / 追加时设置计数器
  * **!** --version (-V)：打印包版本信息。

## iptables 配置

### 1. 备份
```shell
iptables-save > /etc/iptables/rule.v4_20240101
```

### 2. 查看
```shell
iptables -nvL --line-numbers
```

### 3. 配置
```shell
# 允许 RELATED 与 ESTABLISHED 状态的连接通过防火墙
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# 允许环回地址通信
iptables -A INPUT -i lo -j ACCEPT
# 允许 ping
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# 追加策略
iptables -A INPUT -p tcp -s 10.1.10.1 --dport 22 -j ACCEPT
# 插入策略
iptables -I INPUT 1 -p tcp -s 10.1.10.1 --dport 22 -j ACCEPT
# 替换策略
iptables -R INPUT 1 -p tcp -s 10.1.10.1 --dport 22 -j ACCEPT
# 删除策略
iptables -D INPUT 1

## 多端口策略配置
sudo iptables -A INPUT -p tcp -m multiport -s 10.1.10.1 --dports 80,443,8080,9000:9999 -j ACCEPT

## 配置默认策略
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

## 阻止所有并返回主机不可达响应
sudo iptables -A INPUT -p tcp -j REJECT --reject-with icmp-host-unreachable
sudo iptables -A INPUT -p udp -j REJECT --reject-with icmp-host-unreachable
sudo iptables -A INPUT -p icmp -j REJECT --reject-with icmp-host-unreachable

## 日志记录
sudo iptables -A INPUT -j LOG --log-prefix "iptables denied: " --log-level 7

# 保存为默认的 iptables 规则，重启后会从默认的 iptables 规则中恢复
service iptables save

## 从指定文件恢复策略
iptables-restore < etc/iptables/rule.v4_20240101
```

## 4. 优雅配置
```shell
# 创建自定义链
sudo iptables -N ALLOWED_SERVICES

# 将相关规则添加到自定义链
sudo iptables -A ALLOWED_SERVICES -p tcp --dport 22 -j ACCEPT
sudo iptables -A ALLOWED_SERVICES -p tcp -m multiport --dports 80,443 -j ACCEPT
sudo iptables -A ALLOWED_SERVICES -p tcp --dport 3306 -j ACCEPT

# 将 INPUT 链流量引导到自定义链
sudo iptables -A INPUT -j ALLOWED_SERVICES
```
