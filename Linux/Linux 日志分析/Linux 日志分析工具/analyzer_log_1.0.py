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
    """Linux日志分析处理器（完整实现版）"""
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
        self.state_file = '.log_processor_state'
        self.processed = self._load_state()
        self.current_stats = {}
        self.debug_mode = False  # 调试模式默认关闭

        # 初始化所有检测规则
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

    # ---------- 核心方法实现 ----------
    def _load_state(self):
        """加载处理状态"""
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return defaultdict(lambda: {'sig': '', 'pos': 0})

    def _save_state(self):
        """保存处理状态"""
        with open(self.state_file, 'w') as f:
            json.dump(self.current_stats, f)

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

    def _get_file_signature(self, fpath):
        """生成文件唯一签名"""
        stat = os.stat(fpath)
        return f"{stat.st_ino}-{stat.st_size}"

    def process_directory(self, log_dir):
        """处理指定目录"""
        log_dir = os.path.abspath(os.path.expanduser(log_dir))
        if not os.path.isdir(log_dir):
            print(f"[ERROR] 无效目录: {log_dir}")
            return

        print(f"\n▶ 开始分析目录: {log_dir}")

        for fpath in self.detect_rotated_files(log_dir):
            print(f"[DEBUG HANDLER] 处理文件: {fpath}")
            
            # 显示各处理器模式匹配结果
            for handler_name, config in self.handlers.items():
                print(f"  检查处理器 {handler_name}: 模式 {config['patterns']}")
                if any(fnmatch.fnmatch(fpath, p) for p in config['patterns']):
                    print(f"  ✅ 分配处理器: {handler_name}")

        for fpath in self.detect_rotated_files(log_dir):
            print(f"  正在处理文件: {os.path.relpath(fpath, log_dir)}")
            
            # 匹配处理器
            handler = None
            for config in self.handlers.values():
                if any(fnmatch.fnmatch(fpath, p) for p in config['patterns']):
                    handler = config['handler']
                    break

            if not handler:
                continue

            # 状态检查
            file_sig = self._get_file_signature(fpath)
            last_pos = self.processed.get(fpath, {}).get('pos', 0)
            current_size = os.path.getsize(fpath)
            
            if self.processed.get(fpath, {}).get('sig') == file_sig and last_pos == current_size:
                continue

            # 处理文件内容
            with self._open_logfile(fpath) as f:
                print("打开文件？")
                f.seek(last_pos)
                for line in f:
                    handler(line.strip(), fpath)
                new_pos = f.tell()

            # 更新状态
            self.current_stats[fpath] = {
                'sig': file_sig,
                'pos': new_pos,
                'last_processed': datetime.now().isoformat()
            }

        self._save_state()

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

    def parse_kern(self, line, fpath):
        # 显示原始日志内容
        if self.debug_mode:
            print(f"[DEBUG LINE] 解析日志行: {line}")

        """分析内核日志"""
        # 硬件错误检测
        match = re.search(r'Hardware Error', line)  # 示例检测规则
        self._debug_match('kern', 'hardware_error', 
                         r'Hardware Error', line, match)
        if match:
            print(f"[KERN] 硬件错误 ({fpath}): 请检查系统硬件状态")


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