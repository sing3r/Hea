---
created: 2024-11-06T10:02:38 (UTC +08:00)
tags: []
source: https://yufanonsoftware.me/posts/intro-linux-audit-with-auditd.html
author: 
---

# Auditd 审计

---
-   [Configure Linux system auditing with auditd](https://www.redhat.com/sysadmin/configure-linux-auditing-auditd)
-   [Linux auditd for Threat Detection](https://izyknows.medium.com/linux-auditd-for-threat-detection-d06c8b941505)
-   [Chapter 7. System Auditing - redhat.com](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
-   [Understanding Linux Audit](https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-audit-comp.html)
-   [linux-audit / audit-userspace - GitHub](https://github.com/linux-audit/audit-userspace/tree/master)
-   [Neo23x0’s Best Practice Auditd Configuration](https://github.com/Neo23x0/auditd)

![](Auditd%20%E5%AE%A1%E8%AE%A1/ce8c8254129760dfa3e1fc63adc4ae24.webp)

> Sysadmins use audits to discover security violations and track security-relevant information on their systems. Based on preconfigured rules and properties, the **audit daemon** (`auditd`) generates log entries to record information about the events happening on the system. Administrators use this information to analyze what went wrong with the security policies and improve them further by taking additional measures.

RHEL 7 以上的系统默认安装 audit，Ubuntu / Debian 可能需要 `apt install auditd -y`。audit 守护进程需要使用 `service` 命令来管理以便 `auid` 值可以被正确地记录，`systemctl` 仅用于设置自启动和检查状态。

## 配置 Audit 守护进程

配置文件位于 `/etc/audit/auditd.conf`，默认配置对一般系统应该已经足够，对于记录事件较多的系统，可能需要调整缓冲区等配置。

## 编写审计规则

`/etc/audit/audit.rules`定义哪些事件需要被记录，安装 audit 后审计规则默认是空的，可以使用 `auditctl <rule>` 临时定义审计规则，也可以在配置文件中添加规则，重载守护进程来持久化。

## 文件与目录监听

```sh
-w <path-of-file> -p <permission> -k <key>
```

-   `-w <path-of-file>` 指示需要监听的文件
-   `-p <permission>` 声明能够触发记录的事件类型，支持
    -   `(r)ead` 读
    -   `(w)rite` 写
    -   `e(x)ecute` 执行
    -   `(a)ttribute` 属性变更
-   `-k <key>` 添加一个写入到日志信息中的自定义标签

自定义标签允许 `grep`（ `cat /var/log/audit/audit.log | grep user-modify`）或 `ausearch`（`ausearch -i -k user-modify`）搜索和过滤日志信息，后者的交互模式 `-i` 会自动把日志中的一些十六进制编码转换为可读的形式。

**例子：记录用户变更动作**

```sh
-w /etc/passwd -p wa -k user-modify
```

**例子：监测 selinux 配置修改动作**

文件系统监听也可应用于目录：

```sh
-w /etc/selinux/ -p wa -k selinux-modify
```

## 记录系统调用

```sh
-a <action,filter> -S <system-call> -F <field=value> -k <key>
```

-   `-a <action,filter>` 指定何时记录事件
    -   `action` 可以是 `always | never`
    -   「filter specifies which kernel rule-matching filter is applied to the event」，通常选择 `exit`
-   `-S <system-call>` 表示监听哪些系统调用，所有系统调用都记录在 `/usr/include/asm/unistd_64.h` 文件中
-   `-F <field=value>` 声明过滤器，多个过滤器使用 **AND** 连接，要了解过滤器支持哪些属性，请参考 `man auditctl`

由于每个系统调用触发时都会对规则进行解析，推荐相关的系统调用都组合起来以减少对性能的影响。

**例子：记录变更文件所有者动作**

```sh
-a always,exit -S lchown,fchown,chown,fchownat -F arch=b64 -F auid>=1000 -F auid!=4294967295 key=owner-change
```

-   `-F auid>=1000` 表示仅记录 UID 大于等于 1000 的用户
-   `-F auid!=4294967295` 表示排除没有 UID 的情况，这个数在 `uint32_t` 下表示 `-1`
-   `-S <sys-call>` 指定监听哪些系统调用，

**例子：记录文件删除动作**

```sh
-a always,exit -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
```

## 记录可执行文件调用

```sh
-a <action,filter> [ -F <arch=cpu> -S <system-call>] -F exe=<path-to-executable> -k <key>
```

`path-to-executable` 是指向可执行文件的绝对路径。

**例子：记录对 `/usr/bin/id` 的调用**

```sh
-a always,exit -F exe=/usr/bin/id -F arch=b64 -S execve -k execute-id
```

## 最佳实践

通过 `auditctl` 添加的审计规则会在服务器重启后失效。

在大多数发行版上，`/etc/audit/audit.rules` 是由 `/etc/audit/rules.d/*.rules` 生成的，推荐使用 [Neo23x0’s Best Practice Auditd Configuration](https://github.com/Neo23x0/auditd) 项目提供的 `audit.rules` 作为基础替换 `/etc/audit/rules.d/audit.rules`。

```sh
curl https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -o /etc/audit/rules.d/audit.rules
```

注意这份规则比较全面，目标系统上不存在某些用户或服务（也就没有对应的文件）时会抛出 `Error sending add rule data request (No such file or directory)`，通过 `auditctl -l` 查看是否正确加载了需要的规则即可。

除此之外，如果系统中保存了一些应用程序的密钥文件，可以为这些文件添加访问监听。

审计规则按照「先命中者执行（_first-match-win_）」的规则匹配和运行，因此添加自己的自定义规则时需要注意顺序。

修改规则后需要重载 `auditd` 服务，使用 `service auditd reload`。

## 解读审计日志

审计日志输出到 `/var/log/audit/audit.log`，可以通过 `cat` 等命令查看原始格式的文本。由于演示系统的 `/etc/audit/auditd.conf` 中配置了 `log_format = ENRICHED`，所以日志中有额外的大写风格的键把一些日志信息转换为人类可读的文本。取其中一条：

```
type=SYSCALL msg=audit(1691461034.411:4103): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffe64bcf32b a2=0 a3=0 items=1 ppid=5301 pid=5573 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=16 comm="cat" exe="/usr/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="auditlog"ARCH=x86_64 SYSCALL=openat AUID="root" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
```

该条日志记录了用户 `root` 通过 `/usr/bin/cat` 发起的系统调用 `openat`。通过 `ausearch -i -m syscall -x cat` 可以查到相同的内容，但是经过了格式化：

```
type=SYSCALL msg=audit(2023年08月08日 10:17:14.411:4103) : arch=x86_64 syscall=openat success=yes exit=3 a0=AT_FDCWD a1=0x7ffe64bcf32b a2=O_RDONLY a3=0x0 items=1 ppid=5301 pid=5573 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=16 comm=cat exe=/usr/bin/cat subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=auditlog
```

## 创建审计报告

> aureport produces summary reports of audit daemon logs

查询失败的登录尝试，可以看到 `192.168.29.22` 这个 IP 频繁地尝试登录，说明这台机器可能已经被安全团队渗透。

```sh
# aureport -au --failed | less Authentication Report ============================================ # date time acct host term exe success event ============================================ 216. 2023年08月01日 17:49:36 root 192.168.29.22 ssh /usr/sbin/sshd no 907 217. 2023年08月01日 17:49:39 root 192.168.29.22 ssh /usr/sbin/sshd no 915 218. 2023年08月01日 17:49:41 root 192.168.29.22 ssh /usr/sbin/sshd no 923 219. 2023年08月01日 17:49:44 root 192.168.29.22 ssh /usr/sbin/sshd no 931 220. 2023年08月01日 17:49:47 root 192.168.29.22 ssh /usr/sbin/sshd no 939 221. 2023年08月01日 17:49:50 root 192.168.29.22 ssh /usr/sbin/sshd no 947
```

其他功能可通过 `man aureport` 查看。
