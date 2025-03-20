import os
import re
import json
import gzip
import bz2
import glob
import fnmatch
import subprocess
import argparse  # <- 新增这行关键导入
from collections import defaultdict
from datetime import datetime

# 风险等级排序字典（新增）
RISK_ORDER = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'notice': 1
}

class LogProcessor:
    """统一日志处理基类"""
    def __init__(self):
        self.handlers = {
            'syslog': {
                'patterns': ['syslog*'],
                'handler': self.parse_syslog
            },
            'auth': {
                'patterns': ['auth.log*', 'secure*', 'messages*'],
                'handler': self.parse_auth
            },
            'audit': {
                'patterns': ['audit.log*'],
                'handler': self.parse_audit
            },
            'kern': {
                'patterns': ['kern.log*'],
                'handler': self.parse_kern
            }
        }

        # 初始化状态管理
        self.state_file = '.log_processor_state'
        self.processed = self._load_state()
        self.current_stats = {}

        # 调试开关（新增）
        self.debug_mode = True
        # 初始化所有规则模式 
        self._init_rules()

    def _init_rules(self):
        """初始化所有检测规则"""
        # Syslog规则
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


        # Secure日志分析规则（统一命名捕获组）
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

        # Massage日志分析规则
        self.system_rules = {
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
            )
        }

        # Kern日志分析规则
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

        # 认证日志规则库（包含威胁情报）
        self.auth_rules = {
            'ssh_fail': {
                'regex': re.compile(
                    r"Failed (password|publickey) for (?:invalid user )?(?P<user>\S+?) "
                    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)(?: port \d+)?"
                ),
                'risk_level': 'medium'
            },
            'ssh_success': {
                'regex': re.compile(
                    r"Accepted (password|publickey) for (?P<user>\S+) "
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

        # 审计日志高级检测规则
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
        # kern日志高级检测规则
        self.kern_rules = {
            'panic': {
                'regex': re.compile(r"Kernel panic - not syncing: (.+)$"), 
                'severity': 'critical'
            },
            'hardware': {
                'regex': re.compile(r"(Hardware Error|MCE|PCIe Bus Error).*severity: (\w+)"),
                'severity': 'high'
            },
            'oom': {
                'regex': re.compile(
                    r"Out of memory: Kill process (\d+) \((\S+)\) " 
                    r"total-vm:(\d+)kB, anon-rss:(\d+)kB"
                ),
                'severity': 'high'
            },
            'storage': {
                'regex': re.compile(r"(sd[a-z]|nvme\d+n\d+)\s: (I/O error|access beyond end)"),
                'severity': 'medium'
            },
            'firewall': {
                'regex': re.compile(r"IN=(\S+)\sOUT=(\S*)\s.*SRC=(\d+\.\d+\.\d+\.\d+)"), 
                'severity': 'notice'
            },
            'thermal': {
                'regex': re.compile(r"CPU(\d+):.+?(temperature above|clock throttled)"), 
                'severity': 'warning'
            },
            'acpi': { 
                'regex': re.compile(r"ACPI Error: (\w+ .+?) \(.+\)"),
                'severity': 'medium'
            }
        }

        

    def _load_state(self):
        """最终版状态加载方法"""
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"初始化新状态记录: {str(e)}")
            # 使用安全的嵌套defaultdict
            return defaultdict(lambda: {'sig': '', 'pos': 0})

    def _save_state(self):
        """保存处理状态"""
        with open(self.state_file, 'w') as f:
            json.dump(self.current_stats, f)

    def detect_rotated_files(self, log_dir='/var/log'):
        """识别所有日志文件及其轮转版本（支持递归子目录）"""
        log_files = []
        
        # 递归遍历目录结构（最多5层子目录）
        max_depth = 5
        base_depth = log_dir.count(os.sep)
        for root, dirs, files in os.walk(log_dir):
            # 计算当前递归深度
            current_depth = root.count(os.sep) - base_depth
            if current_depth > max_depth:
                del dirs[:]  # 不再深入读取子目录
                continue
            
            # 识别所有可能的日志文件
            for log_type, config in self.handlers.items():
                for pattern in config['patterns']:
                    matched_files = fnmatch.filter(files, pattern)
                    for filename in matched_files:
                        fpath = os.path.join(root, filename)
                        if os.path.isfile(fpath):
                            log_files.append(fpath)
        # 【新增关键代码】处理结果集
        log_files = list(set(log_files))  # 去重
        log_files.sort(key=lambda x: os.path.getmtime(x))  # 按时间排序
        
        return log_files  # 【修复点】必须返回列表

    def _open_logfile(self, filepath):
        """智能打开日志文件（支持压缩格式）"""
        if filepath.endswith('.gz'):
            return gzip.open(filepath, 'rt')
        elif filepath.endswith('.bz2'):
            return bz2.open(filepath, 'rt')
        else:
            return open(filepath, 'r')

    def _get_file_signature(self, fpath):
        """获取文件唯一标识（inode+大小）"""
        stat = os.stat(fpath)
        return f"{stat.st_ino}-{stat.st_size}"

    def process_directory(self, log_dir='/var/log'):
        """处理日志目录前进行路径标准化"""
        log_dir = os.path.abspath(os.path.expanduser(log_dir))
        
        if not os.path.exists(log_dir):
            print(f"  警告：路径 {log_dir} 不存在，跳过")
            return False
        
        if not os.path.isdir(log_dir):
            print(f"  警告：{log_dir} 不是有效目录，跳过")
            return False
        
        print(f"开始分析日志目录: {log_dir}")
        
        for fpath in self.detect_rotated_files(log_dir):
            print(f"正在处理文件: {os.path.basename(fpath)}")
            
            # 获取文件类型对应的处理器
            handler = None
            for log_type, config in self.handlers.items():
                if any(fnmatch.fnmatch(fpath, p) for p in config['patterns']):
                    handler = config['handler']
                    break
            
            if not handler:
                continue
                
            file_sig = self._get_file_signature(fpath)
            last_pos = self.processed.get(fpath, {}).get('pos', 0)
            
            # 如果文件未被修改且已完全处理过
            if self.processed.get(fpath, {}).get('sig') == file_sig and last_pos == os.path.getsize(fpath):
                continue
                
            with self._open_logfile(fpath) as f:
                # 跳转到之前处理的位置
                f.seek(last_pos)
                for line in f:
                    handler(line.strip(), fpath)
                new_pos = f.tell()
                
            # 更新处理状态
            self.current_stats[fpath] = {
                'sig': file_sig,
                'pos': new_pos,
                'last_processed': datetime.now().isoformat()
            }
        
        self._save_state()


    def _debug_match(self, rule_name, pattern, line, match):
        """统一的调试输出方法"""
        if not self.debug_mode:
            return
            
        status = "✓" if match else "✗"
        debug_output = [
            f"[DEBUG] 规则 '{rule_name}' {status}",
            f"模式: {pattern}",
            f"日志行: {line[:80]}{'...' if len(line)>80 else ''}"
        ]
        
        if match:
            debug_output.append(f"捕获字段: {dict(match.groupdict())}")
            
        print("\n".join(debug_output) + "\n" + "-"*50)


    # 以下是示例处理函数，可替换为实际检测逻辑
    def parse_syslog(self, line, fpath):
        # 服务启动失败检测
        service_match = self.syslog_rules['service_fail'].search(line)
        self._debug_match('syslog/service_fail',
                        self.syslog_rules['service_fail'].pattern,
                        line, service_match)
        
        """syslog多规则高级分析"""
        matched = False
        alert_msg = f"[SYSLOG] 检测到安全事件 ({fpath}): "
        details = []
        
        # 服务启动失败检测
        service_match = self.syslog_rules['service_fail'].search(line)
        if service_match:
            if service_match.group(1):
                details.append(f"服务启动失败: {service_match.group(1)}")
            elif service_match.group(2):
                details.append("段错误(内存错误检测)")
            matched = True
        
        # 内存不足杀进程检测
        oom_match = self.syslog_rules['oom_killer'].search(line)
        if oom_match:
            details.append(f"内存不足杀死进程: PID={oom_match.group(1)} ({oom_match.group(2)})")
            matched = True
        
        # 磁盘错误检测
        disk_match = self.syslog_rules['disk_errors'].search(line)
        if disk_match:
            error_type = 'I/O错误' if 'I/O' in disk_match.group(0) else '文件系统错误'
            details.append(f"存储异常: {error_type}")
            matched = True
        
        # 账户操作监控
        auth_match = self.syslog_rules['auth_events'].search(line)
        if auth_match:
            operation = {
                'useradd': '用户添加', 
                'userdel': '用户删除', 
                'sudo': '权限变更'
            }.get(auth_match.group(1), '敏感操作')
            details.append(f"账户变更: {operation}")
            matched = True
        
        # 网络问题分析
        net_match = self.syslog_rules['network_issues'].search(line)
        if net_match:
            issue = 'DNS故障' if 'DNS' in net_match.group(0) else '连接重置'
            details.append(f"网络异常: {issue}")
            matched = True
        
        # 可疑IP提取
        ip_match = self.syslog_rules['suspicious_ips'].search(line)
        if ip_match:
            details.append(f"可疑IP: {ip_match.group(1)}")
            matched = True
            
        if matched:
            print(alert_msg + " | ".join(details))
    
    def parse_auth(self, line, fpath):
        """认证日志高级分析"""
        matched = False
        alert_msg = f"[AUTH] 检测到安全事件 ({fpath}): "
        
        # SSH登录失败检测
        failure = self.secure_rules['auth_failure'].search(line)
        if failure:
            user_type = "无效用户" if failure.group('invalid') else "用户"
            details = [
                f"{user_type}: {failure.group('user')}",
                f"方法: {failure.group('method')}",
                f"来源IP: {failure.group('ip')}"
            ]
            print(alert_msg + " | ".join(details))
            matched = True
        
        # SSH登录成功记录
        success = self.secure_rules['auth_success'].search(line)
        if success:
            print(f"[AUTH] 成功登录: 用户 {success.group('user')} 来自 {success.group('ip')}")
            matched = True
        
        # Sudo操作跟踪
        sudo = self.secure_rules['sudo_usage'].search(line)
        if sudo:
            print(f"[AUTH] 权限提升: {sudo.group('operator')} 执行了: {sudo.group('command')}")
            matched = True
        
        # 账户变更监控
        account = self.secure_rules['account_change'].search(line)
        if account:
            action_map = {
                'added': '添加', 
                'modified': '修改', 
                'deleted': '删除'
            }
            print(f"[AUTH] 账户变更: {action_map[account.group('action')]}用户 {account.group('username')}")
            matched = True
        
        # 会话追踪
        session = self.secure_rules['session_activity'].search(line)
        if session:
            operation = "开启" if session.group('operation') == 'opened' else "关闭"
            log = f"会话{operation}: 用户 {session.group('user')}"
            if session.group('by'):
                log += f" 由 {session.group('by')}"
            print(f"[AUTH] {log}")
            matched = True
            
        if not matched and 'error' in line.lower():
            print(f"[AUTH] 未分类错误: {line[:60]}...")

    def parse_system(self, line, fpath):
        """系统通用日志分析（messages）"""
        # 内核级错误检测
        kernel_event = self.system_rules['kernel_errors'].search(line)
        if kernel_event:
            error_type = kernel_event.group(1).upper()
            print(f"[SYSTEM] 严重内核错误 ({error_type})：{line[:80]}...")
            return
        
        # 存储故障检测
        storage_error = self.system_rules['storage_errors'].search(line)
        if storage_error:
            component = storage_error.group(1).split()[0]  # 如XFS/EXT4
            print(f"[SYSTEM] 存储异常 ({component}): {line[:60]}...")
            return
        
        # 硬件健康预警
        hw_alert = self.system_rules['hardware_alert'].search(line)
        if hw_alert:
            sensor = hw_alert.group(1).capitalize()
            status = hw_alert.group(2).upper()
            print(f"[SYSTEM] 硬件告警 {sensor}: {status}")
            return
        
        # 认证提升操作
        auth_alert = self.system_rules['auth_elevation'].search(line)
        if auth_alert:
            event = "sudo会话" if "sudo" in line else "su切换"
            print(f"[SYSTEM] 权限变更检测: {event}")
            return
        
        # 文件系统紧急事件
        fs_event = self.system_rules['fs_critical'].search(line)
        if fs_event:
            action = "只读重挂载" if "Remounting" in line else "元数据损坏"
            print(f"[SYSTEM] 文件系统紧急状态: {action}") 
            return

    def parse_kern(self, line, fpath):
        """内核日志深度分析"""
        # 内核崩溃最优先检测
        panic_match = self.kern_rules['panic']['regex'].search(line)
        if panic_match:
            reason = panic_match.group(1).strip()
            print(f"[KERN][CRIT] 系统崩溃: {reason} (需立即处理!)")
            return
        
        # 硬件错误检测
        hw_match = self.kern_rules['hardware']['regex'].search(line)
        if hw_match:
            error_type = hw_match.group(1)
            severity = hw_match.group(2)
            print(f"[KERN][{severity.upper()}] 硬件错误: {error_type} (严重度: {severity})")
            return
        
        # 内存溢出杀进程
        oom_match = self.kern_rules['oom']['regex'].search(line)
        if oom_match:
            pid, proc, vm, rss = oom_match.groups()
            print(f"[KERN][HIGH] OOM杀进程: PID={pid} ({proc}) 内存用量: {int(rss)//1024}MB")
            return
        
        # 物理磁盘错误
        disk_match = self.kern_rules['storage']['regex'].search(line)
        if disk_match:
            device = disk_match.group(1)  # 例如sda1/nvme0n1
            error_type = disk_match.group(2)
            print(f"[KERN][DISK] 存储设备{device}异常: {error_type.replace('_',' ')}")
            return
        
        # 防火墙拦截解析
        fw_match = self.kern_rules['firewall']['regex'].search(line)
        if fw_match and 'DROP' in line:
            in_if = fw_match.group(1)
            src_ip = fw_match.group(3)
            print(f"[KERN][NET] 网络阻断: 来自 {src_ip} 通过 {in_if} 接口")
            return
        
        # 温度事件
        temp_match = self.kern_rules['thermal']['regex'].search(line)
        if temp_match:
            cpu_core = temp_match.group(1)
            condition = "超温" if 'temperature' in line else "降频"
            print(f"[KERN][HW] CPU{cpu_core} {condition}状态")
            return
        
        # ACPI规范错误
        acpi_match = self.kern_rules['acpi']['regex'].search(line)
        if acpi_match:
            error_detail = acpi_match.group(1)
            print(f"[KERN][ACPI] 电源管理错误: {error_detail}")

    def parse_auth(self, line, fpath):
        """认证日志多维分析"""
        events = []
        
        # 1. 暴力破解检测
        brute_match = self.auth_rules['brute_force']['regex'].search(line)
        if brute_match:
            count = brute_match.group('count')
            ctx = {
                'type': 'brute_force',
                'count': count,
                'recommendation': '封锁源IP'
            }
            events.append((self.auth_rules['brute_force']['risk_level'], ctx))
        
        # 2. SSH登录结果解析
        for event_type in ['ssh_fail', 'ssh_success']:
            match = self.auth_rules[event_type]['regex'].search(line)
            if match:
                ctx = {
                    'type': event_type,
                    'user': match.group('user'),
                    'ip': match.group('ip'),
                    'method': '密码' if 'password' in line else '密钥'
                }
                if event_type == 'ssh_fail' and 'invalid' in line:
                    ctx['user_status'] = '无效用户'
                events.append((self.auth_rules[event_type]['risk_level'], ctx))
        
        # 3. 特权命令监控
        sudo_match = self.auth_rules['sudo_usage']['regex'].search(line)
        if sudo_match:
            ctx = {
                'type': 'sudo',
                'user': sudo_match.group('operator'),
                'command': sudo_match.group('command'),
                'sanitized_cmd': self._sanitize_command(sudo_match.group('command'))
            }
            if any(s in ctx['command'] for s in ('/bin/rm', '/usr/bin/chmod')):
                ctx['risk_level'] = 'critical'
            events.append((self.auth_rules['sudo_usage']['risk_level'], ctx))
        
        # 4. 用户变更审计
        user_change_match = self.auth_rules['user_change']['regex'].search(line)
        if user_change_match:
            action_map = {
                'new user': '添加',
                'modifying user': '修改', 
                'deleting user': '删除'
            }
            ctx = {
                'type': 'user_change',
                'action': action_map[user_change_match.group('action')],
                'username': user_change_match.group('username'),
                'executor': self._extract_uid(line)
            }
            events.append((self.auth_rules['user_change']['risk_level'], ctx))
        
        # 根据风险等级排序并输出
        for risk, data in sorted(events, key=lambda x: RISK_ORDER[x[0]], reverse=True):
            self._generate_auth_alert(risk, data, fpath)
    def _generate_auth_alert(self, risk_level, data, fpath):
        """生成标准化安全警报"""
        template = {
            'critical': "[AUTH][CRIT] ⚠️ 高危操作",
            'high': "[AUTH][HIGH] ⚠️ 安全告警",
            'medium': "[AUTH][MED] 注意",
            'notice': "[AUTH][INFO] 常规事件"
        }
        
        msg_header = template.get(risk_level, "[AUTH] 未分类事件")
        details = []
        
        if data['type'] == 'brute_force':
            details.append(f"暴力破解尝试 {data['count']} 次 | {data['recommendation']}")
            
        elif data['type'] in ('ssh_fail', 'ssh_success'):
            details.append(f"用户: {data['user']} ({data.get('user_status','')})")
            details.append(f"来源IP: {data['ip']}")
            details.append(f"认证方式: {data['method']}")
            
        elif data['type'] == 'sudo':
            details.append(f"操作员: {data['user']}")
            details.append(f"危险命令: {data['sanitized_cmd']}")
            if 'risk_level' in data:
                details.append(f"高危操作: 立即审计!")
                
        elif data['type'] == 'user_change':
            details.append(f"账户变更: {data['action']} {data['username']}")
            details.append(f"执行者UID: {data['executor']}")
        
        print(f"{msg_header} ({fpath}): {' | '.join(details)}")
    def _sanitize_command(self, cmd):
        """命令清洗避免注入"""
        return re.sub(r";.*|\|\|.*", "", cmd).strip()
    
    def _extract_uid(self, line):
        """从日志行提取UID"""
        return re.search(r"uid=(\d+)", line).group(1) if 'uid=' in line else 'system'
    

    def parse_audit(self, line, fpath):
        """审计日志多维度行为分析"""
        # 结构化审计日志字段
        event = self._parse_audit_fields(line)
        
        # 规则匹配流程（按风险降序）
        alerts = []
        if 'comm="sudo"' in line:
            alerts.extend(self._check_sudo_abuse(event))
        if 'type=SYSCALL' in line:
            alerts.extend(self._check_secret_access(event))
            alerts.extend(self._check_process_injection(event))
        
        # 生成标准化告警
        for alert in sorted(alerts, key=lambda x: x['severity'], reverse=True):
            self._generate_audit_alert(alert, fpath)
    def _parse_audit_fields(self, line):
        """将审计日志解析为字典"""
        fields = {}
        for pair in re.findall(r'(\w+)=("[^"]*"|\S+)', line):
            key, value = pair
            fields[key] = value.strip('"')
        return fields
    def _check_sudo_abuse(self, event):
        """检测特权命令滥用"""
        alerts = []
        rule = self.audit_rules['sudo_abuse']
        if re.search(rule['regex'], line:=event.get('msg', '')):
            # 提取关键信息
            cmd_path = next((p for p in rule['sensitive_cmds'] if p in line), "未知命令")
            user = event.get('acct', '未知用户')
            
            alerts.append({
                'type': 'sudo_abuse',
                'severity': rule['severity'],
                'details': {
                    'user': user,
                    'command': cmd_path,
                    'raw_cmd': line
                }
            })
        return alerts
    def _check_secret_access(self, event):
        """敏感文件访问审计"""
        alerts = []
        rule = self.audit_rules['secret_access']
        
        # 检查文件路径匹配
        file_match = rule['file_regex'].search(line:=event.get('msg', ''))
        if file_match and f'exe="{event.get("exe")}"' not in self.whitelist:
            # 检查访问模式
            if re.search(rule['mode_check'], line):
                alerts.append({
                    'type': 'secret_access',
                    'severity': rule['severity'],
                    'details': {
                        'file': file_match.group(1),
                        'mode': re.search(r'a0="(\d+)"', line).group(1),  # 访问flag十六进制值
                        'process': event.get('exe'),
                        'pid': event.get('pid')
                    }
                })
        return alerts
    def _check_process_injection(self, event):
        """进程注入行为检测"""
        alerts = []
        rule = self.audit_rules['proc_injection']
        
        # 系统调用类型匹配
        if event.get('syscall') not in rule['syscalls']:
            return []
        
        # 参数可疑性检测
        arg_match = rule['arg_regex'].search(line:=event.get('msg', ''))
        if arg_match:
            alerts.append({
                'type': 'proc_injection',
                'severity': rule['severity'],
                'details': {
                    'syscall': event['syscall'],
                    'suspicious_args': arg_match.group(1),
                    'cwd': event.get('cwd', '/'),
                    'uid': event.get('uid')
                }
            })
        return alerts
    def _generate_audit_alert(self, alert, fpath):
        """生成审计告警报告"""
        severity_colors = {
            'critical': '\033[91m[CRIT]\033[0m',  # 红色
            'high': '\033[93m[HIGH]\033[0m',      # 黄色
            'medium': '\033[94m[MED]\033[0m'       # 蓝色
        }
        header = f"[AUDIT]{severity_colors.get(alert['severity'], '')}"
        
        details = []
        if alert['type'] == 'sudo_abuse':
            details.append(
                f"特权滥用: 用户 {alert['details']['user']} 执行敏感命令 {alert['details']['command']}"
            )
            details.append(f"完整命令: {alert['details']['raw_cmd'][:50]}...")
            
        elif alert['type'] == 'secret_access':
            access_mode = {
                'O_WRONLY': '写操作',
                'O_RDWR': '读写操作'
            }.get(alert['details']['mode'], '异常模式')
            details.append(
                f"敏感文件访问: {alert['details']['file']} 被 {access_mode} 打开"
            )
            details.append(f"进程: {alert['details']['process']} (PID:{alert['details']['pid']})")
            
        elif alert['type'] == 'proc_injection':
            details.append(
                f"可疑进程注入: 通过 {alert['details']['syscall']} 系统调用执行"
            )
            details.append(f"参数: {alert['details']['suspicious_args'][:80]}")
            details.append(f"工作目录: {alert['details']['cwd']}")
        
        print(f"{header} ({fpath}): {' | '.join(details)}")

class EnhancedLogProcessor(LogProcessor):
    """增强型处理器（支持二进制日志）"""
    def _open_logfile(self, filepath):
        """扩展支持二进制日志（如btmp）"""
        if 'btmp' in filepath:
            return self._parse_lastb(filepath)
        return super()._open_logfile(filepath)

    def _parse_lastb(self, fpath):
        """使用lastb解析二进制日志"""
        try:
            output = subprocess.check_output(
                ['lastb', '-f', fpath], 
                text=True,
                stderr=subprocess.DEVNULL  # 抑制错误输出
            )
            return output.split('\n')
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[BTMP] 无法解析文件 {os.path.basename(fpath)}: {str(e)}")
            return []

if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='Linux日志深度分析工具',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--path', 
                        nargs='+',
                        required=True,
                        metavar='DIR',
                        help='''指定日志目录（可多个），例如：
                        --path /var/log                        # 系统默认日志
                        --path /backup/202404/logs /tmp/audit  # 多个备份目录''',
                        )
    args = parser.parse_args()
    # 初始化处理器
    processor = EnhancedLogProcessor()
    
    # 按优先级处理所有输入的日志目录
    for idx, log_dir in enumerate(args.path, 1):
        print(f"\n[{idx}/{len(args.path)}] 正在分析目录: {log_dir}")
        
        if not os.path.exists(log_dir):
            print(f"  警告：路径 {log_dir} 不存在，跳过")
            continue
            
        if not os.path.isdir(log_dir):
            print(f"  警告：{log_dir} 不是目录，跳过")
            continue
            
        try:
            processor.process_directory(log_dir)
        except PermissionError as e:
            print(f"  权限拒绝：{str(e)}")
        except Exception as e:
            print(f"  处理异常：{str(e)}")
    
    print("\n分析完成，结果已保存到状态文件")
