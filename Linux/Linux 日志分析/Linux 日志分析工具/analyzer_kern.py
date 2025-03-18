#!/usr/bin/env python3
import re
import json
import argparse
from collections import defaultdict
from datetime import datetime

class KernelLogAnalyzer:
    def __init__(self):
        # 内核专用检测模式
        self.patterns = {
            'hardware_error': re.compile(
                r"(Hardware Error|MCE|PCIe Bus Error).*severity: (\w+)"
            ),
            'oom_kill': re.compile(
                r"Out of memory: Killed process (\S+).*total-vm:(\d+).*anon-rss:(\d+)"
            ),
            'kernel_panic': re.compile(
                r"Kernel panic - not syncing: (.*)$"
            ),
            'disk_error': re.compile(
                r"(sd\S+|nvme\d+n\d+)\s: (I/O error|access beyond end of device)"
            ),
            'firewall_drop': re.compile(
                r"IN=(\S+)\sOUT=(\S*)\sMAC=([\w:]+).*SRC=(\d+\.\d+\.\d+\.\d+)"
            ),
            'thermal_event': re.compile(
                r"CPU\d+:.*(temperature above threshold|clock throttled)"
            ),
            'acpi_error': re.compile(
                r"ACPI Error:.*([^\]]+)\)"
            )
        }

        self.kernel_stats = {
            'hardware': {
                'critical_errors': [],
                'storage_errors': defaultdict(int)
            },
            'memory': {
                'oom_kills': []
            },
            'security': {
                'firewall_drops': defaultdict(int)
            },
            'system_events': {
                'panics': [],
                'thermal_alerts': []
            },
            'acpi_events': {
                'errors': [],
                'warnings': []
            },
            '_metadata': {
                'parsed_lines': 0,
                'time_range': {}
            }
        }

    def parse_kernel_timestamp(self, line):
        """针对内核日志的时间解析优化"""
        ts_match = re.search(
            r"^(\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})", line)
        if ts_match:
            try:
                raw_ts = ts_match.group(1)
                year = datetime.now().year
                return datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
            except ValueError:
                return None
        return None

    def analyze_kernel_line(self, line):
        entry = self.parse_kernel_line(line)
        if not entry:
            return

        self.kernel_stats['_metadata']['parsed_lines'] += 1
        msg = entry['message']

        # 硬件错误检测
        if hw_error := self.patterns['hardware_error'].search(msg):
            error_type, severity = hw_error.groups()
            self.kernel_stats['hardware']['critical_errors'].append({
                'type': error_type.strip(),
                'severity': severity,
                'timestamp': entry['timestamp'].isoformat(),
                'raw': msg[:120]  # 截取关键信息
            })

        # 内存不足杀进程
        if oom := self.patterns['oom_kill'].search(msg):
            process, total_vm, rss = oom.groups()
            self.kernel_stats['memory']['oom_kills'].append({
                'process': process,
                'memory_usage': {
                    'total': int(total_vm),
                    'rss': int(rss)
                },
                'timestamp': entry['timestamp'].isoformat()
            })

        # 网络防火墙丢包
        if fw_drop := self.patterns['firewall_drop'].search(msg):
            interface, out_dev, mac, src_ip = fw_drop.groups()
            self.kernel_stats['security']['firewall_drops'][src_ip] += 1

        # CPU温度异常
        if thermal := self.patterns['thermal_event'].search(msg):
            self.kernel_stats['system_events']['thermal_alerts'].append({
                'message': thermal.group(0),
                'timestamp': entry['timestamp'].isoformat()
            })

        # 系统崩溃事件
        if panic := self.patterns['kernel_panic'].search(msg):
            self.kernel_stats['system_events']['panics'].append({
                'cause': panic.group(1),
                'timestamp': entry['timestamp'].isoformat(),
                'critical': True
            })

    def parse_kernel_line(self, line):
        """解析内核日志结构"""
        match = re.match(
            r"^(?P<timestamp>\w{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2})\s"
            r"(?P<host>\S+)\s"
            r"kernel: \[.*?\]\s"  # 过滤内核时间戳
            r"(?P<message>.*)$",
            line
        )
        if not match:
            return None

        return {
            'timestamp': self.parse_kernel_timestamp(line),
            'host': match.group('host'),
            'message': match.group('message')
        }

    def generate_kernel_report(self):
        """生成带健康评级的内核报告"""
        report = {
            'health_summary': {
                'critical_errors': len(self.kernel_stats['hardware']['critical_errors']),
                'disk_errors': sum(self.kernel_stats['hardware']['storage_errors'].values()),
                'oom_events': len(self.kernel_stats['memory']['oom_kills'])
            },
            'detailed_events': {
                'last_hardware_error': self.kernel_stats['hardware']['critical_errors'][-1] 
                    if self.kernel_stats['hardware']['critical_errors'] else None,
                'frequent_firewall_drops': sorted(
                    self.kernel_stats['security']['firewall_drops'].items(),
                    key=lambda x: x[1], 
                    reverse=True
                )[:5],
                'thermal_history': [
                    event['timestamp'] 
                    for event in self.kernel_stats['system_events']['thermal_alerts']
                ]
            },
            '_metadata': self.kernel_stats['_metadata']
        }
        return report

class UnifiedLogAnalyzer(KernelLogAnalyzer, AuthLogAnalyzer):
    """集成分析内核和认证日志的统一分析器"""
    def __init__(self):
        AuthLogAnalyzer.__init__(self)
        KernelLogAnalyzer.__init__(self)
        self.total_stats = defaultdict(dict)

    def analyze_any_log(self, line):
        """自动分流到相应分析模块"""
        if "kernel: [" in line:
            self.analyze_kernel_line(line)
        elif "sshd" in line or "sudo" in line:
            self.analyze_auth(line)
            # 合并元数据统计
            self.total_stats['_metadata']['parsed_lines'] = \
                self.stats['_metadata']['analyzed_lines'] + \
                self.kernel_stats['_metadata']['parsed_lines']

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="统一日志审计工具 (支持 auth/kern 等)")
    parser.add_argument('-f', '--file', required=True, help="日志文件路径")
    parser.add_argument('-t', '--type', choices=['auto', 'auth', 'kern'], 
                       default='auto', help="指定日志类型")
    args = parser.parse_args()

    analyzer = UnifiedLogAnalyzer()
    
    with open(args.file) as f:
        for line in f:
            analyzer.analyze_any_log(line)
    
    # 生成综合报告
    auth_report = analyzer.generate_security_report()
    kern_report = analyzer.generate_kernel_report()
    
    final_report = {
        'authentication': auth_report,
        'kernel_health': kern_report,
        'cross_analysis': {
            'suspicious_ips': [
                ip for ip in auth_report['threat_analysis']['top_attack_sources']
                if ip in kern_report['detailed_events']['frequent_firewall_drops']
            ]
        }
    }
    
    with open('full_audit.json', 'w') as f:
        json.dump(final_report, f, indent=2)
    
    print(f"综合审计报告已生成: full_audit.json")
