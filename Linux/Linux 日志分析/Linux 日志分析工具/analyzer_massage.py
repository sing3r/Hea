#!/usr/bin/env python3
import re
import json
import argparse
from collections import defaultdict
from datetime import datetime

class LogAnalyzer:
    def __init__(self):
        self.patterns = {
            # 原有 syslog 检测模式
            'service_fail': re.compile(r"Failed to start (.+?)( service|.target)"),
            'oom_killer': re.compile(r"Out of memory: Kill process (\d+) \((.+?)\)"),
            'auth_events': re.compile(r"(\buseradd\b|\buserdel\b|\bsudo:\b)"),
            'network_issues': re.compile(r"(DNS (failed|timed out)|connection reset)"),
            'suspicious_ips': re.compile(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
            
            # 新增 messages 专用模式
            'kernel_errors': re.compile(
                r"(BUG|Oops|general protection fault|kernel panic|Kernel stack guard page)",
                flags=re.IGNORECASE
            ),
            'storage_errors': re.compile(
                r"(XFS error|EXT4-fs error|LVM|MD_FAULTY|reported corrupted sector|I/O error)"
            ),
            'hardware_alerts': re.compile(
                r"(temperature|voltage|fan|thermal|cpu clock throttled).* (critical|exceeded|above)",
                re.IGNORECASE
            ),
            'privilege_events': re.compile(
                r"(sudo: session|pam_unix\(su:session\)|password for .* accepted)"
            ),
            'filesystem_events': re.compile(
                r"(Remounting filesystem read-only|File system corruption detected)"
            )
        }
        

        self.stats = {
            'critical': {
                'kernel_panics': [],
                'storage_failures': [],
                'emergency_remounts': []
            },
            'hardware': {
                'sensor_alerts': defaultdict(int),
                'pcie_errors': []
            },
            'security': {
                'privilege_escalations': [],
                'sudo_commands': []
            },
            'performance': {
                'oom_kills': defaultdict(int),
                'thermal_throttling': 0
            },
            '_metadata': {
                'log_source': None,
                'analyzed_lines': 0
            }
        }


    def parse_timestamp(self, line):
        try:
            ts_str = ' '.join(line.split()[:3])
            return datetime.strptime(ts_str, "%b %d %H:%M:%S")
        except Exception as e:
            print(f"时间解析错误: {str(e)}")
            return None

    def parse_line(self, line):
        parts = line.split(maxsplit=4)
        if len(parts) < 5:
            return None  # 忽略格式异常的日志条目

        return {
            'timestamp': self.parse_timestamp(line),
            'host': parts[3],
            'process': parts[4].strip(":") if ':' in parts[4] else None,
            'message': parts[-1].strip()
        }

    def analyze(self, line):
        entry = self.parse_line(line)
        if not entry:
            return

        self.stats['_metadata']['analyzed_lines'] += 1

        # ---- 关键错误检测 ----
        if self.patterns['kernel_errors'].search(line):
            self.stats['critical']['kernel_panics'].append({
                'timestamp': entry['timestamp'].isoformat() if entry['timestamp'] else None,
                'host': entry['host'],
                'error_snippet': self._extract_error_snippet(line)
            })

        if self.patterns['filesystem_events'].search(line):
            self.stats['critical']['emergency_remounts'].append({
                'timestamp': entry['timestamp'],
                'message': entry['message']
            })

        # ---- 硬件问题检测 ----
        if self.patterns['hardware_alerts'].search(line):
            alert_type = re.search(r"(temperature|voltage|fan)", line, re.I).group(0)
            self.stats['hardware']['sensor_alerts'][alert_type] += 1

        if "PCIe Bus Error" in line:
            self.stats['hardware']['pcie_errors'].append({
                'timestamp': entry['timestamp'],
                'component': re.search(r"device (\w+):", line).group(1)
            })

        # ---- 安全事件检测 ----
        if "sudo:" in line and "COMMAND=" in line:
            user_match = re.search(r"user (\w+)", line)
            command_match = re.search(r"COMMAND=(.*?)(\d|$)", line)
            if user_match and command_match:
                self.stats['security']['sudo_commands'].append({
                    'user': user_match.group(1),
                    'command': command_match.group(1).strip(),
                    'timestamp': entry['timestamp']
                })

        # ---- 性能问题检测 ----
        if self.patterns['oom_killer'].search(line):
            process = self.patterns['oom_killer'].search(line).group(2)
            self.stats['performance']['oom_kills'][process] += 1

        if "CPU throttling" in line:
            self.stats['performance']['thermal_throttling'] += 1

    def _extract_error_snippet(self, line):
        """从日志中提取关键错误片段和可能的错误代码"""
        code_match = re.search(r"error code (0x[0-9a-fA-F]+)", line)
        call_trace = re.search(r"Call Trace:\n((\s*\[\<.+?\>\].*\n)+)", line)
        return {
            'error_code': code_match.group(1) if code_match else None,
            'call_trace': call_trace.group(1).strip() if call_trace else None,
            'raw_line': line.strip()
        }

    def generate_report(self):
        report = {
            'summary': {
                'critical_issues': len(self.stats['critical']['kernel_panics']) 
                                 + len(self.stats['critical']['storage_failures']),
                'hardware_alerts': dict(self.stats['hardware']['sensor_alerts']),
                'privilege_changes': len(self.stats['security']['privilege_escalations']),
                'performance_issues': {
                    'oom_events': sum(self.stats['performance']['oom_kills'].values()),
                    'thermal_throttling': self.stats['performance']['thermal_throttling']
                }
            },
            'details': {
                'kernel_errors': self.stats['critical']['kernel_panics'][:5],
                'sudo_commands': self.stats['security']['sudo_commands'][:10],
                'full_hardware_errors': self.stats['hardware']['pcie_errors']
            },
            'metadata': dict(self.stats['_metadata'])
        }
        return report

    def console_output(self, report):
        print(f"\n{' 系统深度分析报告 ':=^80}")
        print(f"分析文件: {report['metadata']['log_source']}")
        print(f"扫描条目: {report['metadata']['analyzed_lines']}")
        
        print("\n[ 关键问题 ]")
        print(f"* 内核级错误: {len(report['details']['kernel_errors'])} 次")
        print(f"* 紧急文件系统只读挂载: {len(self.stats['critical']['emergency_remounts'])} 次")
        
        print("\n[ 硬件状态 ]")
        for alert, count in report['summary']['hardware_alerts'].items():
            print(f"* {alert.capitalize()}异常: {count} 次报警")
        if self.stats['hardware']['pcie_errors']:
            devices = {e['component'] for e in self.stats['hardware']['pcie_errors']}
            print(f"  - 受影响的PCI设备: {', '.join(devices)}")

        print("\n[ 特权操作审计 ]")
        if report['details']['sudo_commands']:
            users = defaultdict(int)
            for cmd in report['details']['sudo_commands']:
                users[cmd['user']] += 1
            print("最近特权命令执行用户:")
            for user, count in users.items():
                print(f"  - {user}: {count} 次操作")
        else:
            print("未检测到特权命令执行")

def main():
    parser = argparse.ArgumentParser(description="高级系统日志分析工具")
    parser.add_argument('-f', '--file', default='/var/log/messages', 
                       help="日志文件路径 (支持 syslog/messages)")
    parser.add_argument('-o', '--output', default='system_audit.json',
                       help="输出报告文件名")
    args = parser.parse_args()
    
    analyzer = LogAnalyzer()
    
    try:
        with open(args.file, 'r') as f:
            analyzer.stats['_metadata']['log_source'] = args.file
            for line in f:
                analyzer.analyze(line)
    except Exception as e:
        print(f"日志处理异常: {str(e)}")
        exit(1)
    
    report = analyzer.generate_report()
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    analyzer.console_output(report)
    print(f"\n{' 报告生成完成 ':=^80}\n输出文件: {args.output}")

if __name__ == '__main__':
    main()
