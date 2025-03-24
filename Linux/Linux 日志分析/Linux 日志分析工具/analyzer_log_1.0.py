import os
import re
import json
import gzip
import bz2
import argparse
import fnmatch
import subprocess
from datetime import datetime
from collections import defaultdict

# 风险等级排序字典
RISK_ORDER = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'notice': 1
}

class LogProcessor:
    def __init__(self):
        self.handlers = {
            'syslog': {
                'patterns': ['*syslog*'],
                'handler': self.parse_syslog
            },
            'auth': {
                'patterns': ['*auth.log*'],
                'handler': self.parse_auth
            },
            'audit': {
                'patterns': ['*audit.log*'],
                'handler': self.parse_audit
            },
            'kern': {
                'patterns': ['*kern.log*'],
                'handler': self.parse_kern
            },
            'secure': {
                'patterns': ['*secure*'],
                'handler': self.parse_secure
            },
             'messages': {
                'patterns': ['*messages*'],
                'handler': self.parse_messages
            }
        }

        self.debug_mode = False  # 调试模式默认关闭

        # syslog 规则
        self.syslog_rules = {
            'service_fail': {
                'regex': re.compile(r"Failed to start (.+?) service|(segmentation fault)"),
                'risk_level': 'high'  # 核心服务崩溃应立即响应
            },
            'oom_killer': {
                'regex': re.compile(r"Out of memory: Kill process (\d+) \((.+?)\)"),
                'risk_level': 'critical'  # 系统稳定性威胁
            },
            'disk_errors': {
                'regex': re.compile(r"(I/O error|exception Emask|EXT4-fs error|XFS corruption)"),
                'risk_level': 'critical'  # 数据损坏风险
            },
            'network_issues': {
                'regex': re.compile(r"(DNS (failed|timed out)|connection reset|nf_conntrack table full)"),
                'risk_level': 'high'  # 网络服务的可用性问题
            },
            'suspicious_ips': {
                'regex': re.compile(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
                'risk_level': 'medium'  # 需结合行为模式判断攻击
            },
            'memory_pressure': {
                'regex': re.compile(r"low memory in zone (\w+)|page allocation failure"),
                'risk_level': 'medium'  # 资源压力需观察趋势
            },
            'fs_metadata_error': {
                'regex': re.compile(r"(XFS metadata IO error|BTRFS transaction abort)"),
                'risk_level': 'critical'  # 文件系统元数据不可逆损坏
            },
            'ecc_memory_error': {
                'regex': re.compile(r"(EDAC.*CE error|Corrected hardware memory error)"), 
                'risk_level': 'high'  # 硬件可靠性预警
            },
            'time_sync_failure': {
                'regex': re.compile(r"chronyd: No suitable source|systemd-timesyncd: Synchronization failed"), 
                'risk_level': 'medium'  # 证书验证可能失效但不会立即崩溃
            },
            'virt_error': {
                'regex': re.compile(r"(qemu-kvm: terminating on signal|libvirtd: internal error)"),
                'risk_level': 'high'  # 虚拟化基础设施可靠性问题
            }
        }

        # auth 规则
        self.auth_rules = {
            'ssh_fail': {
                'regex': re.compile(
                    r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+?) "
                    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)(?: port \d+)?"
                ),
                'risk_level': 'medium'
            },
            'ssh_success': {
                'regex': re.compile(
                    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) "
                    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)(?: port \d+)?"
                ),
                'risk_level': 'notice'
            },
            'sudo_usage': {
                'regex': re.compile(
                    r"(?P<operator>\w+) : .*COMMAND=(?P<command>(?:/[^/ ]+)+)"
                ),
                'risk_level': 'high'
            },
            'user_change': {
                'regex': re.compile(
                    r"(useradd|usermod|userdel)\[\d+\]: "
                    r"(?P<action>new user|modifying user|deleting user) '(?P<username>\w+)'"
                ),
                'risk_level': 'critical'
            },
            'brute_force': {
                'regex': re.compile(
                    r"message repeated (?P<count>\d+) times:.* Failed password"
                ),
                'risk_level': 'high'
            },
            'sensitive_login': {
                'regex': re.compile(
                    r"Accepted (password) for (root|admin) "
                    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
                ),
                'risk_level': 'high' 
            },
            # 防御T1059攻击链
            'dangerous_sudo': {
                'regex': re.compile(
                    r"COMMAND=(/usr?/bin/(bash|sh|python|perl)|"
                    r"sudo.*-u\s+\w+\s+/bin/)"
                ),
                'risk_level': 'critical'
            },
            # 基于T1098检测提权后门
            'authorized_keys_change': {
                'regex': re.compile(
                    r"\/\.ssh\/authorized_keys.*(opened for writing|modified)"
                ),
                'risk_level': 'critical'
            },
            # 检测T1110密码喷洒攻击
            'password_spray': {
                'regex': re.compile(
                    r"(Failed password for \S+).*"
                    r"message repeated (\d+) times"
                ),
                'risk_level': 'medium'  # 低频+多用户模式
            }
        }

        # audit 规则
        self.audit_rules = {
            # 原规则优化
            'sudo_abuse': {
                'regex': re.compile(
                    r'comm="sudo".*exe="(/usr/sbin/)(useradd|usermod|visudo|passwd)\b'),  # 修正转义字符和结尾的括号
                'sensitive_cmds': {
                    'useradd': '创建可疑账号',
                    'visudo': '修改sudo权限'
                },
                'severity': 'high'
            },
            'secret_access': {
                'file_regex': re.compile(
                    r'name="(\/etc\/(passwd|shadow|sudoers|\S+\.pem)|'
                    r'\/var\/lib\/mysql\/\S+\.key)"',
                    re.IGNORECASE
                ),
                'mode_check': r'O_(WRONLY|RDWR|CREAT)',
                'whitelist': ['/usr/bin/vim'],  # 添加白名单机制
                'severity': 'critical'
            },
            'proc_injection': {
                'syscalls': ['execve', 'ptrace', 'memfd_create', 'process_vm_writev'],
                'arg_regex': re.compile(
                    r'(arg=".*(\/dev\/shm\/|nc |\becho [A-Za-z0-9+/]{50,})|'
                    r'proto=HTTP)'
                ),
                'severity': 'high'
            },
            
            # 新增规则
            'mount_abuse': {  # T1564.004
                'regex': re.compile(
                    r'comm=\"mount\".*fstype=\"(nfs|cifs|tmpfs)\".*'
                    r'name=\"(\/etc|\/root)\"'
                ),
                'severity': 'medium'
            },
            'ssh_agent_abuse': {  # T1552.004
                'regex': re.compile(
                    r'exe=\"/usr/bin/ssh-agent\".*'
                    r'sock_dir=\"(\/tmp\/\S+|/dev/shm/)\"'
                ),
                'severity': 'high'
            }
        }

        # Kern 规则
        self.kern_rules = {
            'panic': {
                'regex': re.compile(r"Kernel panic - not syncing: (.+)$"), 
                'level': 'critical'
            },
            'hardware': {
                'regex': re.compile(r"(Hardware Error|MCE|PCIe Bus Error).*severity: (\w+)"),
                'level': 'high'
            },
            'oom': {
                'regex': re.compile(r"Out of memory: Kill process (\d+) \((\S+)\) " 
                                    r"total-vm:(\d+)kB, anon-rss:(\d+)kB"),
                'level': 'high'
            },
            'storage': {
                'regex': re.compile(r"(sd[a-z]|nvme\d+n\d+)\s: (I/O error|access beyond end)"),
                'level': 'medium'
            },
            'firewall': {
                'regex': re.compile(r"IN=(\S+)\sOUT=(\S*)\s.*SRC=(\d+\.\d+\.\d+\.\d+)"), 
                'level': 'notice'
            },
            'thermal': {
                'regex': re.compile(r"CPU(\d+):.+?(temperature above|clock throttled)"), 
                'level': 'warning'
            },
            'acpi': { 
                'regex': re.compile(r"ACPI Error: (\w+ .+?) \(.+\)"),
                'level': 'medium'
            }
        }

        # Secure 规则
        self.secure_rules = {
            # 增强账户变更检测（T1098）
            'account_change': {
                'regex': re.compile(
                    r"USER_ADD|USER_MOD.*(name='(?P<username>\w+)'.*(add to 'sudo')|shell='/bin/bash)|"
                    r"CRON.*\((add|remove) job for user"
                ),
                'risk_level': 'high',
                'desc': "账户权限变更"
            },
            
            # SSH爆破检测（T1110）
            'ssh_bruteforce': {
                'regex': re.compile(
                    r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+).*"
                    r"message repeated (?P<count>\d+) times"
                ),
                'risk_level': 'high',
                'desc': "多频次账号爆破"
            },
            # 特权用户登录（T1078）
            'privileged_login': {
                'regex': re.compile(
                    r"Accepted publickey for (root|admin) "
                    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port \d+"
                ),
                'risk_level': 'medium',
                'geo_check': True  # 需IP地理位置分析
            },
            
            # 危险命令执行（T1059）
            'dangerous_sudo': {
            'regex': re.compile(
                r"COMMAND=(\S*?(?:/bin/(bash|sh)|"  # 注意括号闭合
                r"visudo|chmod [0-7][0-7][0-7] \S+|"
                r"useradd -G sudo))"  # 这里需要补全两重闭合
            ),
                'risk_level': 'critical',
                'desc': "高风险提权操作"
            },
            # 后门行为（T1136）
            'backdoor_check': {
                'regex': re.compile(
                    r"WARNING: Illegal entry at line \d+ in /etc/cron\.d/|"
                    r"key='ssh-rsa [A-Za-z0-9+/]{300,}"
                ),
                'risk_level': 'critical',
                'desc': "后门植入预警"
            }
        }

        # messages 规则
        self.messages_rules = {
            # ================== 硬件层面监控 ==================
            'kernel_errors': {
                'regex': re.compile(
                    r"(Kernel panic|BUG: |general protection fault|soft lockup|"
                    r"Hardware name:.*(corrected error|fatal))", 
                    re.IGNORECASE
                ),
                'risk_level': 'critical',  # A级故障
                'desc': "内核级严重故障"
            },
            'storage_errors': {
                'regex': re.compile(
                    r"(EXT4-fs error (.*) at |XFS (corruption|metadata IO error)|"
                    r"BTRFS transaction abort|SCSI disk error .*sector \d+)"
                ),
                'risk_level': 'critical',  # 数据完整性风险
                'tags': ['fs', 'disk']
            },
            'hardware_alert': {
                'regex': re.compile(
                    r"(temperature .* exceeded|"
                    r"Corrected hardware memory error|"
                    r"PSU[0-9]_STATUS is (FAILED|CRITICAL)|"
                    r"Drive Bay.*S.M.A.R.T Alert)", 
                    re.IGNORECASE
                ),
                'risk_level': 'high',  # B级硬件故障
                'suppress_keywords': ['test_mode=1']  # 测试模式不告警
            },
            
            # ================== 系统服务监控 ==================
            'service_crash': {
                'regex': re.compile(
                    r"(nginx: emergency restart|"
                    r"mysql: Shutdown complete|"
                    r"docker:.*OOMKilled|"
                    r"kubelet: Pod worker lost)"
                ),
                'risk_level': 'high',
                'desc': "关键服务异常终止"
            },
            
            # ================== 安全事件检测 ==================
            'auth_elevation': {
                'regex': re.compile(
                    r"(sudo:.*COMMAND=/bin/su |"
                    r"pam_unix\(sshd:auth\): authentication failure.*user=root)", 
                    re.IGNORECASE
                ),
                'risk_level': 'high',  # T1548权限提升
                'mitre_tactic': "TA0004"
            },
            'network_tamper': {
                'regex': re.compile(
                    r"(iptables: rules updated.*DROP|"
                    r"interface (eth0|enp3s0) (link down|promiscuous mode))"
                ),
                'risk_level': 'medium'
            },
            
            # ================== 现有规则优化 ==================
            'fs_critical': {
                'regex': re.compile(
                    r"Remounting filesystem read-only|"
                    r"metadata corruption detected.*REPAIR NEEDED"
                ),
                'risk_level': 'critical',
                'auto_repair': True  # 标注是否需要触发自动修复
            },
            # ...保留原有ssh/sudo等规则并确保结构统一...
            
            # ================== 新增监控项 ================== 
            'time_skew': {
                'regex': re.compile(
                    r"CLOCK: time jump detected|"
                    r"systemd-timesyncd: (Synchronization failed|No server suitable)"
                ),
                'risk_level': 'medium',  # 证书校验失效风险
                'desc': "时间同步异常"
            },
            'container_escape': {
                'regex': re.compile(
                    r"docker:.*--privileged=true |"
                    r"oci-runtime error: namespace violation"
                ),
                'risk_level': 'high'  # T1611容器逃逸
            }
        }

    # ---------- 核心方法实现 ----------
    def detect_rotated_files(self, log_dir='/var/log'):
        print(f"[DEBUG FILE] 扫描目录: {log_dir}")  # 显示扫描路径

        """递归查找日志文件"""
        log_files = []
        max_depth = 5
        base_depth = log_dir.count(os.sep)
        
        for root, dirs, files in os.walk(log_dir):
            current_depth = root.count(os.sep) - base_depth
            if current_depth > max_depth:
                del dirs[:]
                continue

            for config in self.handlers.values():
                for pattern in config['patterns']:
                    for filename in fnmatch.filter(files, pattern):
                        fpath = os.path.join(root, filename)
                        if os.path.isfile(fpath):
                            log_files.append(fpath)

        log_files = list(set(log_files))
        log_files.sort(key=lambda x: os.path.getmtime(x))
        
        print(f"[DEBUG FILE] 找到文件列表:")  # 显示所有检测到的文件
        for f in log_files:
            print(f"  - {f}")
            
        return log_files

    def _open_logfile(self, filepath):
        """打开各种格式的日志文件"""
        if filepath.endswith('.gz'):
            return gzip.open(filepath, 'rt')
        elif filepath.endswith('.bz2'):
            return bz2.open(filepath, 'rt')
        else:
            return open(filepath, 'r')


    def process_directory(self, log_dir):
        """处理指定目录"""
        log_dir = os.path.abspath(os.path.expanduser(log_dir))
        if not os.path.isdir(log_dir):
            print(f"[ERROR] 无效目录: {log_dir}")
            return

        print(f"\n▶ 开始分析目录: {log_dir}")

        for fpath in self.detect_rotated_files(log_dir):
            print(f"[DEBUG HANDLER] 处理文件: {fpath}")
            
            handler = None
            # 显示各处理器模式匹配结果
            for handler_name, config in self.handlers.items():
                print(f"  检查处理器 {handler_name}: 模式 {config['patterns']}")
                if any(fnmatch.fnmatch(fpath, p) for p in config['patterns']):
                    print(f"  ✅ 分配处理器: {handler_name}")
                    handler = config['handler']
                    break

            if not handler:
                continue

            # 处理文件内容
            with self._open_logfile(fpath) as f:
                for line in f:
                    handler(line.strip(), fpath)

    def _debug_match(self, category, rule_name, line, match):
        """调试输出"""
        if not self.debug_mode:
            return

        status = "✅ 匹配成功" if match else "❌ 未匹配"
        output = [
            f"[DEBUG][{category}] 规则: {rule_name}",
            f"  正则模式: pattern",
            f"  日志内容: {line[:100]}{'...' if len(line)>100 else ''}",
            f"  匹配状态: {status}"
        ]
        if match and match.groupdict():
            output.append(f"  捕获字段: {dict(match.groupdict())}")
        print("\n".join(output) + "\n" + "-"*60)

    # ---------- 日志分析方法 ----------
    ## syslog 日志分析
    def parse_syslog(self, line, fpath):
        """Syslog多规则顺序检测"""
        # === 原始规则 ===
        # 服务启动失败检测
        match = self.syslog_rules['service_fail'].search(line)
        self._debug_match('syslog', 'service_fail', line, match)
        if match:
            service = match.group(1) or "系统组件段错误"
            print(f"[SYSLOG] 服务故障 ({fpath}): {service}")
        # 内存不足检测
        match = self.syslog_rules['oom_killer'].search(line)
        self._debug_match('syslog', 'oom_killer', line, match)
        if match:
            print(f"[SYSLOG] OOM终止进程 ({fpath}): PID={match.group(1)} ({match.group(2)})")
        # 磁盘错误检测
        match = self.syslog_rules['disk_errors'].search(line)
        self._debug_match('syslog', 'disk_errors', line, match)
        if match:
            error_type = "I/O错误" if "I/O" in line else "文件系统错误"
            print(f"[SYSLOG] 存储问题 ({fpath}): {error_type}")
        # 网络问题
        match = self.syslog_rules['network_issues'].search(line)
        self._debug_match('syslog', 'network_issues', line, match)
        if match:
            if "nf_conntrack" in line:
                print(f"[SYSLOG] 网络连接表已满 ({fpath}) → 需调整内核参数")
            else:
                print(f"[SYSLOG] 网络异常 ({fpath}): {match.group(0)}")
        # 可疑IP检测
        match = self.syslog_rules['suspicious_ips'].search(line)
        self._debug_match('syslog', 'suspicious_ips', line, match)
        if match:
            src_ip = match.group(1)
            print(f"[SYSLOG] 可疑IP访问 ({fpath}): SRC={src_ip}")
        # 内存压力检测
        match = self.syslog_rules['memory_pressure'].search(line)
        self._debug_match('syslog', 'memory_pressure', line, match)
        if match:
            zone = match.group(1) if match.group(1) else "未知区域"
            print(f"[SYSLOG] 内存压力预警 ({fpath}): 内存区[{zone}]可用页不足")
        # 文件系统元数据错误
        match = self.syslog_rules['fs_metadata_error'].search(line)
        self._debug_match('syslog', 'fs_metadata_error', line, match)
        if match:
            print(f"[SYSLOG] 存储元数据损坏 ({fpath}): {match.group(1)} → 可能导致数据丢失")
        # ECC内存错误检测
        match = self.syslog_rules['ecc_memory_error'].search(line)
        self._debug_match('syslog', 'ecc_memory_error', line, match)
        if match:
            print(f"[SYSLOG] 内存硬件错误 ({fpath}): {match.group(0)} → 建议硬件检查")
        # 时间同步失败
        match = self.syslog_rules['time_sync_failure'].search(line)
        self._debug_match('syslog', 'time_sync_failure', line, match)
        if match:
            print(f"[SYSLOG] 时间同步失败 ({fpath}): 系统时钟可能偏移")
        # 虚拟化异常检测
        match = self.syslog_rules['virt_error'].search(line)
        self._debug_match('syslog', 'virt_error', line, match)
        if match:
            print(f"[SYSLOG] 虚拟化组件异常 ({fpath}): {match.group(1)} → 检查虚拟机状态")

    ## auth 日志分析
    def parse_auth(self, line, fpath):
        """认证日志解析（优化后支持9大规则）"""
        # 调试模式输出原始日志
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析认证日志: {line}")

        # 暴力破解检测（优先级1）
        brute_match = self.auth_rules['brute_force']['regex'].search(line)
        self._debug_match('auth', 'brute_force', line, brute_match)
        if brute_match:
            count = brute_match.group('count')
            print(f"[AUTH][HIGH] 账号爆破 ({fpath}): 检测到 {count} 次连续失败")

        # 特权账户密码登录（优先级2）
        sensitive_login_match = self.auth_rules['sensitive_login']['regex'].search(line)
        self._debug_match('auth', 'sensitive_login', line, sensitive_login_match)
        if sensitive_login_match:
            user = sensitive_login_match.group(2)
            ip = sensitive_login_match.group('ip')
            print(f"[AUTH][HIGH] 特权登录 ({fpath}): 用户 {user}(密码验证) 来自 {ip}")

        # SSH认证失败（优先级3）
        ssh_fail_match = self.auth_rules['ssh_fail']['regex'].search(line)
        self._debug_match('auth', 'ssh_fail', line, ssh_fail_match)
        if ssh_fail_match:
            method = ssh_fail_match.group('method')
            ip = ssh_fail_match.group('ip')
            user = ssh_fail_match.group('user')
            invalid_flag = "（无效用户）" if 'invalid' in line else ""
            print(f"[AUTH][MED] SSH验证失败 ({fpath}): {invalid_flag}{user} 使用 {method}")

        # SSH认证成功（优先级4）
        ssh_success_match = self.auth_rules['ssh_success']['regex'].search(line)
        self._debug_match('auth', 'ssh_success', line, ssh_success_match)
        if ssh_success_match:
            user = ssh_success_match.group('user')
            method = "密码" if "password" in line else "密钥"
            ip = ssh_success_match.group('ip')
            print(f"[AUTH][INFO] SSH登录成功 ({fpath}): {user} 通过 {method}")

        # 用户变更审计（优先级5）
        user_change_match = self.auth_rules['user_change']['regex'].search(line)
        self._debug_match('auth', 'user_change', line, user_change_match)
        if user_change_match:
            action_map = {
                'new user': '创建', 
                'modifying user': '修改',
                'deleting user': '删除'
            }
            username = user_change_match.group('username')
            print(f"[AUTH][CRIT] 账户变更 ({fpath}): {action_map[user_change_match.group('action')]} {username}")

        # 危险Sudo操作（优先级6）
        sudo_danger_match = self.auth_rules['dangerous_sudo']['regex'].search(line)
        self._debug_match('auth', 'dangerous_sudo', line, sudo_danger_match)
        if sudo_danger_match:
            bad_command = sudo_danger_match.group(1).split('/')[-1]
            operator = re.search(r'USER=(\w+)', line).group(1) if 'USER=' in line else '未知用户'
            print(f"[AUTH][CRIT] Sudo风险 ({fpath}): {operator} 执行危险命令 {bad_command}")

        # SSH密钥后门检测（优先级7）
        key_change_match = self.auth_rules['authorized_keys_change']['regex'].search(line)
        self._debug_match('auth', 'authorized_keys_change', line, key_change_match)
        if key_change_match:
            action = "修改" if "modified" in line else "写入"
            print(f"[AUTH][CRIT] 密钥异常变动 ({fpath}): authorized_keys 文件被 {action}")

        # 密码喷洒攻击（优先级8）
        spray_match = self.auth_rules['password_spray']['regex'].search(line)
        self._debug_match('auth', 'password_spray', line, spray_match)
        if spray_match and spray_match.group(2) > '3':  # 同一用户失败尝试超过3次
            user = spray_match.group(1).split()[-1]
            print(f"[AUTH][MED] 密码喷洒告警 ({fpath}): 用户 {user} 遭遇 {spray_match.group(2)} 次尝试")

        # 常规Sudo操作（优先级9）
        sudo_match = self.auth_rules['sudo_usage']['regex'].search(line)
        self._debug_match('auth', 'sudo_usage', line, sudo_match)
        if sudo_match and not sudo_danger_match:  # 排除已处理的高危命令
            print(f"[AUTH][HIGH] 权限提升 ({fpath}): {sudo_match.group('operator')} 执行 {sudo_match.group('command')}")


    ## audit 日志分析
    def parse_audit(self, line, fpath):
        """深度解析Audit日志（适配新规则）"""
        # 调试模式显示原始日志
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析审计日志: {line}")
        # ================== 规则处理 ==================
        # 1. 检测可疑sudo滥用
        sudo_match = self.audit_rules['sudo_abuse']['regex'].search(line)
        self._debug_match('audit', 'sudo_abuse', line, sudo_match)
        if sudo_match:
            cmd_type = sudo_match.group(2)  # 获取命令类型如useradd
            desc = self.audit_rules['sudo_abuse']['sensitive_cmds'].get(cmd_type, "可疑操作")
            exe_path = sudo_match.group(1) + cmd_type
            print(f"[AUDIT][HIGH] 提权风险 ({fpath}): 执行{desc}命令 -> {exe_path}")
        # 2. 关键文件访问监控
        file_match = self.audit_rules['secret_access']['file_regex'].search(line)
        mode_match = re.search(self.audit_rules['secret_access']['mode_check'], line) if file_match else None
        self._debug_match('audit', 'secret_access', line, file_match)
        if file_match and mode_match:
            # 白名单过滤
            exe = re.search(r'exe="(.*?)"', line).group(1) if 'exe=' in line else "未知程序"
            if exe not in self.audit_rules['secret_access']['whitelist']:
                sensitive_file = file_match.group(1)
                print(f"[AUDIT][CRITICAL] 敏感文件访问 ({fpath}): {exe}以{mode_match.group(0)}模式操作{sensitive_file}")
        # 3. 进程注入检测
        proc_syscall = any(sc in line for sc in self.audit_rules['proc_injection']['syscalls']) 
        proc_args_match = self.audit_rules['proc_injection']['arg_regex'].search(line) if proc_syscall else None
        self._debug_match('audit', 'proc_injection', line, proc_args_match)
        if proc_syscall and proc_args_match:
            suspect_arg = proc_args_match.group(1)[:50]  # 截断长参数
            print(f"[AUDIT][HIGH] 进程注入风险 ({fpath}): 检测到危险参数 -> {suspect_arg}...")
        # 4. 异常挂载行为（新增）
        mount_match = self.audit_rules['mount_abuse']['regex'].search(line)
        self._debug_match('audit', 'mount_abuse', line, mount_match)
        if mount_match:
            fs_type = mount_match.group(1)
            mount_point = mount_match.group(2)
            print(f"[AUDIT][MEDIUM] 可疑挂载 ({fpath}): 使用{fs_type}挂载系统目录{mount_point}")
        # 5. SSH代理滥用（新增）
        ssh_agent_match = self.audit_rules['ssh_agent_abuse']['regex'].search(line)
        self._debug_match('audit', 'ssh_agent_abuse', line, ssh_agent_match)
        if ssh_agent_match:
            sock_path = ssh_agent_match.group(1)
            print(f"[AUDIT][HIGH] SSH代理风险 ({fpath}): 非安全socket路径 {sock_path}")

    ## kren 日志分析
    def parse_kern(self, line, fpath):
        """分析内核日志（规范结构化实现）"""
        # 显示原始日志内容（与原始代码完全一致的调试输出）
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析内核日志行: {line}")

        # 逐条执行内核规则匹配（严格遵循原始代码模式）
        # 规则 1: 内核崩溃检测
        match = self.kern_rules['panic']['regex'].search(line)
        self._debug_match(
            category='kern',
            rule_name='panic',
            pattern=self.kern_rules['panic']['regex'].pattern,
            line=line,
            match=match
        )
        if match:
            print(f"[KERN] 严重故障 ({fpath}): 内核崩溃 -> {match.group(1)}")

        # 规则 2: 硬件错误检测
        match = self.kern_rules['hardware']['regex'].search(line)
        self._debug_match(
            category='kern',
            rule_name='hardware',
            pattern=self.kern_rules['hardware']['regex'].pattern,
            line=line,
            match=match
        )
        if match:
            error_type = match.group(1)
            severity = match.group(2)
            print(f"[KERN] 硬件告警 ({fpath}): 类型={error_type}, 严重程度={severity}")

        # 规则 3: OOM事件检测
        match = self.kern_rules['oom']['regex'].search(line)
        self._debug_match(
            category='kern',
            rule_name='oom',
            pattern=self.kern_rules['oom']['regex'].pattern,
            line=line,
            match=match
        )
        if match:
            pid, process, vm_usage, rss_usage = match.groups()
            print(f"[KERN] 内存不足 ({fpath}): 进程 {process}(PID:{pid}) 占用 (VM:{vm_usage}KB RSS:{rss_usage}KB)")

        # 规则 4: 存储设备错误检测
        match = self.kern_rules['storage']['regex'].search(line)
        self._debug_match(
            category='kern',
            rule_name='storage',
            pattern=self.kern_rules['storage']['regex'].pattern,
            line=line,
            match=match
        )
        if match:
            device, error_type = match.groups()
            print(f"[KERN] 存储故障 ({fpath}): 设备 {device} 发生 {error_type}")

        # 规则 5: 防火墙事件检测
        match = self.kern_rules['firewall']['regex'].search(line)
        self._debug_match(
            category='kern',
            rule_name='firewall',
            pattern=self.kern_rules['firewall']['regex'].pattern,
            line=line,
            match=match
        )
        if match:
            in_iface, out_iface, src_ip = match.groups()
            direction = f"入口网卡={in_iface}"
            if out_iface:
                direction += f" → 出口网卡={out_iface}"
            print(f"[KERN] 网络事件 ({fpath}): {direction} 来源IP: {src_ip}")

        # 规则 6: 温度异常检测
        match = self.kern_rules['thermal']['regex'].search(line)
        self._debug_match(
            category='kern',
            rule_name='thermal',
            pattern=self.kern_rules['thermal']['regex'].pattern,
            line=line,
            match=match
        )
        if match:
            cpu_num, condition = match.groups()
            condition_desc = "温度超标" if "temperature" in condition else "频率受限"
            print(f"[KERN] 硬件监控 ({fpath}): CPU{cpu_num} {condition_desc}")

        # 规则 7: ACPI错误检测
        match = self.kern_rules['acpi']['regex'].search(line)
        self._debug_match(
            category='kern',
            rule_name='acpi',
            pattern=self.kern_rules['acpi']['regex'].pattern,
            line=line,
            match=match
        )
        if match:
            print(f"[KERN] 电源管理错误 ({fpath}): {match.group(1)}")

        ## secure 日志分析
    def parse_secure(self, line, fpath):
        """Secure日志合规性检测（保持原有处理顺序）"""
        if self.debug_mode:
            print(f"[DEBUG SECURE] 原始日志: {line.strip()}")
        # ==== 账户权限变更检测 ====
        acc_match = self.secure_rules['account_change']['regex'].search(line)
        self._debug_match('secure', 'account_change', line, acc_match)
        if acc_match:
            action = "添加" if 'add to' in line else "权限调整"
            user = acc_match.group('username')
            print(f"[SECURE/{self.secure_rules['account_change']['risk_level'].upper()}] 账户风险 ({fpath}): {user}被{action}")
        # ==== SSH暴力破解检测 ====
        brute_match = self.secure_rules['ssh_bruteforce']['regex'].search(line)
        self._debug_match('secure', 'ssh_bruteforce', line, brute_match)
        if brute_match and int(brute_match.group('count')) >= 5:
            ip = brute_match.group('ip')
            print(f"[SECURE/{self.secure_rules['ssh_bruteforce']['risk_level'].upper()}] 爆破攻击 ({fpath}): {ip}尝试{brute_match.group('count')}次")
        # ==== 特权账号登录 ====
        priv_match = self.secure_rules['privileged_login']['regex'].search(line)
        self._debug_match('secure', 'privileged_login', line, priv_match)
        if priv_match:
            user = priv_match.group(1)
            print(f"[SECURE/{self.secure_rules['privileged_login']['risk_level'].upper()}] 特权访问 ({fpath}): {user}@[{priv_match.group('ip')}]")
        # ==== 高危Sudo命令 ====
        sudo_match = self.secure_rules['dangerous_sudo']['regex'].search(line)
        self._debug_match('secure', 'dangerous_sudo', line, sudo_match)
        if sudo_match:
            cmd = sudo_match.group(1).split('/')[-1]
            print(f"[SECURE/{self.secure_rules['dangerous_sudo']['risk_level'].upper()}] 危险操作 ({fpath}): {cmd}命令被调用")
        # ==== 后门特征检测 ====
        backdoor_match = self.secure_rules['backdoor_check']['regex'].search(line)
        self._debug_match('secure', 'backdoor_check', line, backdoor_match)
        if backdoor_match:
            alert_sign = "非法Cron项" if "cron" in line else "长密钥注入" 
            print(f"[SECURE/{self.secure_rules['backdoor_check']['risk_level'].upper()}] 后门警告 ({fpath}): 检测到{alert_sign}")
                
    ## messages 日志分析
    def parse_messages(self, line, fpath):
        """系统日志解析器（保持原处理结构）"""
        # 调试信息输出
        if self.debug_mode:
            print(f"[DEBUG] 解析系统日志: {line.strip()}")
        # 内核严重错误检测
        kernel_err = self.messages_rules['kernel_errors']['regex'].search(line)
        self._debug_match('massage', 'kernel_errors', line, kernel_err)
        if kernel_err:
            err_type = 'Kernel Panic' if 'panic' in line else 'Fatal BUG'
            print(f"[SYSTEM/{self.messages_rules['kernel_errors']['risk_level'].upper()}] 内核级错误: {err_type}")
        # 存储设备故障
        storage_err = self.messages_rules['storage_errors']['regex'].search(line)
        self._debug_match('massage', 'storage_errors', line, storage_err)
        if storage_err:
            fs_type = 'XFS' if 'XFS' in line else 'EXT4' if 'EXT4' in line else 'UnknowFS'
            print(f"[SYSTEM/{self.messages_rules['storage_errors']['risk_level'].upper()}] 存储异常 ({fs_type}): {line[:60]}...")
        # 权限提升行为
        auth_elev = self.messages_rules['auth_elevation']['regex'].search(line)
        self._debug_match('massage', 'auth_elevation', line, auth_elev)
        if auth_elev:
            action = 'root密码登录' if 'accepted password' in line else '特权切换'
            print(f"[SYSTEM/{self.messages_rules['auth_elevation']['risk_level'].upper()}] 权限变更: {action}")
        # 硬性规则错误（如文件系统只读重挂载）
        fs_crit = self.messages_rules['fs_critical']['regex'].search(line)
        self._debug_match('massage', 'fs_critical', line, fs_crit)
        if fs_crit:
            print(f"[SYSTEM/CRITICAL] 文件系统紧急事件: 系统进入只读模式") 
        # SSH相关规则（复用原有逻辑）
        ssh_fail_match = self.messages_rules['ssh_fail']['regex'].search(line)
        if ssh_fail_match:  # 与auth模块一致的告警
            print(f"[SSH/MEDIUM] 认证失败: IP {ssh_fail_match.group('ip')}")
        # 用户账户变更（日志跨多个组件时需要兼容）
        user_change_match = self.messages_rules['user_change']['regex'].search(line)
        self._debug_match('massage', 'user_change', line, user_change_match)
        if user_change_match:
            username = user_change_match.group('username')
            print(f"[SYSTEM/CRITICAL] 用户管理: 账户 {username} 被{user_change_match.group('action')}")


# ------------------ 主程序入口 ------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Linux日志深度分析工具 v2.0",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--path', nargs='+', required=True,
                       help="指定要分析的日志目录（支持多个目录）\n示例: --path /var/log /backup/logs")
    parser.add_argument('--debug', action='store_true',
                       help="启用调试模式显示匹配细节")
    args = parser.parse_args()

    processor = LogProcessor()
    processor.debug_mode = args.debug  # 控制调试输出
    
    print("="*60)
    print("Linux日志深度分析工具 开始运行".center(50))
    print(f"[DEBUG INIT] 调试模式: {'开启' if processor.debug_mode else '关闭'}")  # 🚨关键验证点
    print("="*60)

    for idx, path in enumerate(args.path, 1):
        print(f"\n🔍 [{idx}/{len(args.path)}] 正在处理目录: {path}")
        try:
            processor.process_directory(path)
        except PermissionError as e:
            print(f"  权限不足: {str(e)}")
        except Exception as e:
            print(f"  处理异常: {str(e)}")

    print("\n" + "="*60)
    print("分析完成，结果已保存至 .log_processor_state".center(50))
    print("="*60)