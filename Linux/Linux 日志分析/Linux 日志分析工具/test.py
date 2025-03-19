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
    """Linux日志分析处理器（修复增强版）"""
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
        self.debug_mode = False

        # 初始化检测规则（保持原有规则）
        self._init_rules()

    def _init_rules(self):
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

    # ---------- 核心方法修复 ----------
    def process_directory(self, log_dir):
        """处理目录（单次扫描优化）"""
        log_dir = os.path.abspath(os.path.expanduser(log_dir))
        if not os.path.isdir(log_dir):
            print(f"[ERROR] 无效目录: {log_dir}")
            return

        print(f"\n▶ 分析目录: {log_dir}")
        log_files = self.detect_rotated_files(log_dir)  # 只扫描一次

        # 1. 调试显示处理配置
        for fpath in log_files:
            print(f"[文件匹配检查] {os.path.relpath(fpath, log_dir)}")
            matched = False
            for handler_name, config in self.handlers.items():
                for pattern in config['patterns']:
                    if fnmatch.fnmatch(os.path.basename(fpath), pattern):
                        print(f"  ✅ 匹配处理器: {handler_name} (模式: {pattern})")
                        matched = True
                        break
                if matched: break
            if not matched:
                print("  ❌ 未匹配到任何处理器")

        # 2. 实际处理流程
        for fpath in log_files:
            self._process_single_file(fpath, log_dir)

        self._save_state()

    def _process_single_file(self, fpath, log_dir):
        """单文件处理核心逻辑"""
        rel_path = os.path.relpath(fpath, log_dir)
        handler = None
        # 匹配处理器
        for config in self.handlers.values():
            if any(fnmatch.fnmatch(os.path.basename(fpath), p) for p in config['patterns']):
                handler = config['handler']
                break

        if not handler:
            if self.debug_mode:
                print(f"  ❌ 跳过未匹配文件: {rel_path}")
            return

        if self.debug_mode:
            print(f"\n🔍 开始处理: {rel_path} -> 处理器: {handler.__name__}")

        # 状态校验
        file_sig = self._get_file_signature(fpath)
        last_pos = self.processed.get(fpath, {}).get('pos', 0)
        current_size = os.path.getsize(fpath)
        
        if self.debug_mode:
            print(f"  文件签名: {file_sig} (原签名: {self.processed.get(fpath, {}).get('sig', '<新文件>')})")
            print(f"  文件尺寸: {current_size} bytes (上次处理位置: {last_pos})")

        if self.processed.get(fpath, {}).get('sig') == file_sig and last_pos == current_size:
            if self.debug_mode:
                print(f"  ⏩ 已处理完成: 跳过执行")
            return

        # 处理内容
        try:
            with self._open_logfile(fpath) as f:
                f.seek(last_pos)
                if self.debug_mode:
                    print(f"  当前文件指针: {f.tell()}")
                    print(f"  {'─'*30} 开始处理内容 {'─'*30}")
                
                line_count = 0
                for line in f:
                    line_count += 1
                    handler(line.strip(), fpath)
                    if self.debug_mode and line_count % 100 == 0:
                        print(f"  已处理 {line_count} 行...")
                
                new_pos = f.tell()
                if self.debug_mode:
                    print(f"  {'─'*30} 处理完成 {'─'*30}")
                    print(f"  新文件指针位置: {new_pos}")
        except Exception as e:
            print(f"  ⚠ 处理异常: {str(e)}")
            return

        # 更新状态
        self.current_stats[fpath] = {
            'sig': file_sig,
            'pos': new_pos,
            'last_processed': datetime.now().isoformat()
        }

    def _open_logfile(self, filepath):
        """带调试的文件打开方法"""
        if self.debug_mode:
            print(f"  🚪 打开文件: {filepath} (大小: {os.path.getsize(filepath)} bytes)")
        
        if filepath.endswith('.gz'):
            return gzip.open(filepath, 'rt')
        elif filepath.endswith('.bz2'):
            return bz2.open(filepath, 'rt')
        elif 'btmp' in filepath:
            return self._parse_lastb(filepath)
        else:
            return open(filepath, 'r')

# ------------------ 其他方法保持原有功能 ------------------ 
# （_init_rules, detect_rotated_files, _debug_match 等方法内容保持不变）

class EnhancedLogProcessor(LogProcessor):
    """增强版-支持二进制日志解析"""
    def _parse_lastb(self, fpath):
        """二进制日志解析"""
        try:
            output = subprocess.check_output(['lastb', '-f', fpath], 
                                            text=True, stderr=subprocess.DEVNULL)
            return output.split('\n')
        except Exception as e:
            print(f"[WARN] 解析失败: {fpath} ({str(e)})")
            return []

# ------------------ 主程序入口 ------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Linux日志分析工具 v2.1 (修复增强版)",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--path', nargs='+', required=True,
                      help="日志目录路径（支持多个）\n例: --path /var/log /backup_logs")
    parser.add_argument('--debug', action='store_true',
                      help="启用调试模式")
    args = parser.parse_args()

    processor = EnhancedLogProcessor()
    processor.debug_mode = args.debug
    
    print("="*60)
    print("Linux日志深度分析工具 开始运行".center(50))
    print(f"[系统状态] 调试模式: {'✅ 已启用' if processor.debug_mode else '❌ 未启用'}")
    print("="*60)

    for idx, path in enumerate(args.path, 1):
        print(f"\n🔍 任务进度: [{idx}/{len(args.path)}] 目录: {path}")
        try:
            processor.process_directory(path)
        except PermissionError as e:
            print(f"  权限错误: {str(e)} (尝试使用sudo运行)")
        except Exception as e:
            print(f"  运行异常: {str(e)}")

    print("\n" + "="*60)
    print("分析完成！".center(50))
    print("="*60)
