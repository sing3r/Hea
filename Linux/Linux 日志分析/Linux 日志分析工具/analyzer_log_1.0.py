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
            'service_fail': re.compile(
                r"Failed to start (.+?) service|(segmentation fault)"
            ),
            'oom_killer': re.compile(
                r"Out of memory: Kill process (\d+) \((.+?)\)"
            ),
            'disk_errors': re.compile(
                r"(I/O error|exception Emask|EXT4-fs error)"
            ),
            'auth_events': re.compile(
                r"(\buseradd\b|\buserdel\b|\bsudo\b)"
            ),
            'network_issues': re.compile(
                r"(DNS (failed|timed out)|connection reset)"
            ),
            'suspicious_ips': re.compile(
                r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            )
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
            }
        }

        # audit 规则
        self.audit_rules = {
            'sudo_abuse': {
                'regex': re.compile(r'comm="sudo".*cmd=".*(useradd|visudo|passwd)\b'),
                'sensitive_cmds': ['/usr/sbin/useradd', '/usr/sbin/visudo'],
                'severity': 'high'
            },
            'secret_access': {
                'file_regex': re.compile(r'name="(/etc/(?:passwd|shadow)|.*\.(?:pem|key))"'),
                'mode_check': r'(O_WRONLY|O_RDWR)',
                'severity': 'critical'
            },
            'proc_injection': {
                'syscalls': ['execve', 'ptrace', 'memfd_create'],
                'arg_regex': re.compile(r'arg="(.*(/tmp/|http://|\s-e\s).*)'),
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
            'auth_failure': re.compile(
                r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
            ),
            'auth_success': re.compile(
                r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
            ),
            'sudo_usage': re.compile(
                r"(?P<operator>\w+) : .*COMMAND=(?P<command>.+?)(\s|$)"
            ),
            'account_change': re.compile(
                r"user (?P<action>added|modified|deleted): .* name='(?P<username>[^']+)'"
            ),
            'session_activity': re.compile(
                r"session (?P<operation>opened|closed) for user (?P<user>\S+)( by (?P<by>\S+))?"
            )
        }

        # Massage 规则
        self.massage_rules = {
            'kernel_errors': re.compile(
                r"(BUG | oops | general protection fault | kernel panic | Kernel stack guard page)\b",
                flags=re.IGNORECASE
            ),
            'storage_errors': re.compile(
                r"(XFS (error|warning) | EXT4-fs error | MD_FAULTY_SECTION\.\.\. | I/O error)"
            ),
            'hardware_alert': re.compile(
                r"(temperature | voltage | fan[0-9]? | thermal zone)\b.*\b(critical|exceeded|unrecoverable)",
                re.IGNORECASE
            ),
            'auth_elevation': re.compile(
                r"sudo: session | pam_unix\(su:session\) | accepted password for \S+"
            ),
            'fs_critical': re.compile(
                r"Remounting filesystem read-only | corruption detected in filesystem metadata"
            ),
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

    def _debug_match(self, category, rule_name, pattern, line, match):
        """调试输出"""
        if not self.debug_mode:
            return

        status = "✅ 匹配成功" if match else "❌ 未匹配"
        output = [
            f"[DEBUG][{category}] 规则: {rule_name}",
            f"  正则模式: {pattern}",
            f"  日志内容: {line[:100]}{'...' if len(line)>100 else ''}",
            f"  匹配状态: {status}"
        ]
        if match and match.groupdict():
            output.append(f"  捕获字段: {dict(match.groupdict())}")
        print("\n".join(output) + "\n" + "-"*60)

    # ---------- 日志分析方法 ----------
    ## syslog 日志分析
    def parse_syslog(self, line, fpath):
        # 显示原始日志内容
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析日志行: {line}")

        """分析syslog日志"""
        # 服务故障检测
        match = self.syslog_rules['service_fail'].search(line)
        self._debug_match('syslog', 'service_fail', 
                        self.syslog_rules['service_fail'].pattern, line, match)
        if match:
            detail = match.group(1) or "段错误"
            print(f"[SYSLOG] 服务异常 ({fpath}): {detail}")

        # 内存异常检测
        match = self.syslog_rules['oom_killer'].search(line)
        self._debug_match('syslog', 'oom_killer', 
                        self.syslog_rules['oom_killer'].pattern, line, match)
        if match:
            print(f"[SYSLOG] OOM事件 ({fpath}): 进程 {match.group(2)}({match.group(1)}) 被终止")

        # 网络问题
        match = self.syslog_rules['network_issues'].search(line)
        self._debug_match('syslog', 'network_issues', 
                        self.syslog_rules['network_issues'].pattern, line, match)
        if match:
            issue = 'DNS故障' if 'DNS' in line else '连接重置'
            print(f"[SYSLOG] 网络问题 ({fpath}): {issue}")

    ## auth 日志分析
    def parse_auth(self, line, fpath):
        # 显示原始日志内容
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析日志行: {line}")

        """分析认证日志"""
        # SSH登录失败
        match = self.auth_rules['ssh_fail']['regex'].search(line)
        self._debug_match('auth', 'ssh_fail', 
                        self.auth_rules['ssh_fail']['regex'].pattern, line, match)
        if match:
            user_type = "无效用户" if 'invalid' in line else "用户"
            print(f"[AUTH] 登录失败 ({fpath}): {user_type} {match.group('user')} 来自 {match.group('ip')}")

        # 暴力破解检测
        match = self.auth_rules['brute_force']['regex'].search(line)
        self._debug_match('auth', 'brute_force', 
                        self.auth_rules['brute_force']['regex'].pattern, line, match)
        if match:
            print(f"[AUTH] 暴力破解尝试 ({fpath}): {match.group('count')}次失败登录")

        # 用户变更检测
        match = self.auth_rules['user_change']['regex'].search(line)
        self._debug_match('auth', 'user_change', 
                        self.auth_rules['user_change']['regex'].pattern, line, match)
        if match:
            action_map = {
                'new user': '创建', 
                'modifying user': '修改',
                'deleting user': '删除'
            }
            print(f"[AUTH] 用户变更 ({fpath}): {action_map[match.group('action')]}用户 {match.group('username')}")

    ## audit 日志分析
    def parse_audit(self, line, fpath):
        # 显示原始日志内容
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析日志行: {line}")

        """分析审计日志"""
        # 特权命令滥用检测
        match = re.search(self.audit_rules['sudo_abuse']['regex'], line)
        self._debug_match('audit', 'sudo_abuse', 
                        self.audit_rules['sudo_abuse']['regex'].pattern, line, match)
        if match:
            print(f"[AUDIT] 可疑提权操作 ({fpath}): {match.group(0)}")

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
        # 显示原始日志内容
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析Secure日志: {line}")
        """分析 secure 日志（安全相关事件）"""
        # SSH认证失败
        match = self.secure_rules['auth_failure'].search(line)
        self._debug_match(
            category='secure', 
            rule_name='auth_failure',
            pattern=self.secure_rules['auth_failure'].pattern,
            line=line,
            match=match
        )
        if match:
            is_invalid = "无效用户" if match.group('invalid') else ""
            print(f"[SECURE] 认证失败事件 ({fpath}): {is_invalid}{match.group('user')} "
                f"通过 {match.group('method')} 来自IP: {match.group('ip')}")
        # SSH认证成功
        match = self.secure_rules['auth_success'].search(line)
        self._debug_match(
            category='secure',
            rule_name='auth_success',
            pattern=self.secure_rules['auth_success'].pattern,
            line=line,
            match=match
        )
        if match:
            print(f"[SECURE] 认证成功记录 ({fpath}): 用户 {match.group('user')} 通过 "
                f"{match.group('method')} 登录，来源IP: {match.group('ip')}")
        # Sudo操作
        match = self.secure_rules['sudo_usage'].search(line)
        self._debug_match(
            category='secure',
            rule_name='sudo_usage',
            pattern=self.secure_rules['sudo_usage'].pattern,
            line=line,
            match=match
        )
        if match:
            print(f"[SECURE] 提权操作 ({fpath}): 用户 {match.group('operator')} 执行命令 -> "
                f"{match.group('command')}")
        # 账户变更
        match = self.secure_rules['account_change'].search(line)
        self._debug_match(
            category='secure',
            rule_name='account_change',
            pattern=self.secure_rules['account_change'].pattern,
            line=line,
            match=match
        )
        if match:
            action_map = {
                'added': '创建',
                'modified': '修改', 
                'deleted': '删除'
            }
            print(f"[SECURE] 用户账户变更 ({fpath}): {action_map[match.group('action')]}用户 "
                f"{match.group('username')}")
        # 会话活动
        match = self.secure_rules['session_activity'].search(line)
        self._debug_match(
            category='secure',
            rule_name='session_activity',
            pattern=self.secure_rules['session_activity'].pattern,
            line=line,
            match=match
        )
        if match:
            operation = "开启" if match.group('operation') == 'opened' else "关闭"
            by_user = f" (操作者: {match.group('by')})" if match.group('by') else ""
            print(f"[SECURE] 会话状态变化 ({fpath}): 用户 {match.group('user')} 会话已"
                f"{operation}{by_user}")
                
    ## messages 日志分析
    def parse_messages(self, line, fpath):
        """分析 messages 日志（综合系统事件）"""
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析Messages日志行: {line}")
        # 内核错误检测
        match = self.massage_rules['kernel_errors'].search(line)
        self._debug_match(
            category='messages', 
            rule_name='kernel_errors',
            pattern=self.massage_rules['kernel_errors'].pattern,
            line=line,
            match=match
        )
        if match:
            error_type = next((e for e in match.groups() if e), "未知错误").strip().upper()
            print(f"[MESSAGES] 内核级故障 ({fpath}): {error_type} → 需立即人工检查")
        # 存储错误
        match = self.massage_rules['storage_errors'].search(line)
        self._debug_match(
            category='messages', 
            rule_name='storage_errors',
            pattern=self.massage_rules['storage_errors'].pattern,
            line=line,
            match=match
        )
        if match:
            subsystem = match.group(1).split()[0]  # 如 XFS/EXT4
            print(f"[MESSAGES] 存储子系统告警 ({fpath}): {subsystem} 错误类型: {match.group(2)}")
        # 硬件警报
        match = self.massage_rules['hardware_alert'].search(line)
        self._debug_match(
            category='messages', 
            rule_name='hardware_alert',
            pattern=self.massage_rules['hardware_alert'].pattern,
            line=line,
            match=match
        )
        if match:
            component = match.group(1).upper()
            status = match.group(2)
            print(f"[MESSAGES] 硬件状态异常 ({fpath}): {component} → 已达 {status} 阈值")
        # 权限提升事件
        match = self.massage_rules['auth_elevation'].search(line)
        self._debug_match(
            category='messages', 
            rule_name='auth_elevation',
            pattern=self.massage_rules['auth_elevation'].pattern,
            line=line,
            match=match
        )
        if match:
            event_type = "sudo会话创建" if "sudo: session" in line else "密码认证通过"
            print(f"[MESSAGES] 权限变更 ({fpath}): {event_type} → 安全检查建议")
        # 文件系统紧急事件
        match = self.massage_rules['fs_critical'].search(line)
        self._debug_match(
            category='messages', 
            rule_name='fs_critical',
            pattern=self.massage_rules['fs_critical'].pattern,
            line=line,
            match=match
        )
        if match:
            action = "文件系统强制只读" if "Remounting" in line else "元数据损坏事件"
            print(f"[MESSAGES] 文件系统应急操作 ({fpath}): {action} → 需数据恢复操作")


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