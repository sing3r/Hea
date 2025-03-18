#!/usr/bin/env python3
import re
import json
import argparse
from collections import defaultdict
from datetime import datetime

class SyslogAnalyzer:
    def __init__(self):
        self.patterns = {
            'service_fail': re.compile(r"Failed to start (.+?) service|(segmentation fault)"),
            'oom_killer': re.compile(r"Out of memory: Kill process (\d+) \((.+?)\)"),
            'disk_errors': re.compile(r"(I/O error|exception Emask|EXT4-fs error)"),
            'auth_events': re.compile(r"(\buseradd\b|\buserdel\b|\bsudo\b)"),
            'network_issues': re.compile(r"(DNS (failed|timed out)|connection reset)"),
            'suspicious_ips': re.compile(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        }
        
        self.stats = {
            'critical_errors': [],
            'oom_kills': defaultdict(int),
            'hardware_errors': [],
            'security_events': defaultdict(int),
            'network_problems': defaultdict(int),
            'high_risk_ips': defaultdict(int)
        }
        
        self.ip_threshold = 5  # 触发警报的IP出现阈值
    
    def parse_line(self, line):
        timestamp_str = ' '.join(line.split()[:3])
        try:
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        except:
            timestamp = None
        
        message = ' '.join(line.split()[4:])
        
        return {
            'timestamp': timestamp,
            'host': line.split()[3],
            'message': message
        }
    
    def analyze(self, line):
        entry = self.parse_line(line)
        
        # 服务故障检测
        service_fail = self.patterns['service_fail'].search(line)
        if service_fail:
            error = service_fail.group(1) or service_fail.group(2)
            self.stats['critical_errors'].append({
                'timestamp': entry['timestamp'].isoformat() if entry['timestamp'] else None,
                'error': f"Service failure: {error}",
                'raw': line.strip()
            })
        
        # 内存不足事件
        oom_match = self.patterns['oom_killer'].search(line)
        if oom_match:
            process = oom_match.group(2)
            self.stats['oom_kills'][process] += 1
        
        # 磁盘错误检测
        if self.patterns['disk_errors'].search(line):
            self.stats['hardware_errors'].append({
                'timestamp': entry['timestamp'].isoformat() if entry['timestamp'] else None,
                'message': line.strip()
            })
        
        # 安全相关事件
        auth_match = self.patterns['auth_events'].search(line)
        if auth_match:
            event_type = auth_match.group(0)
            self.stats['security_events'][event_type] += 1
        
        # 网络问题检测
        network_issue = self.patterns['network_issues'].search(line)
        if network_issue:
            issue_type = network_issue.group(0)
            self.stats['network_problems'][issue_type] += 1
        
        # 可疑IP检测
        ip_match = self.patterns['suspicious_ips'].search(line)
        if ip_match:
            ip = ip_match.group(1)
            self.stats['high_risk_ips'][ip] += 1
    
    def generate_report(self):
        report = {
            'summary': {
                'total_critical_errors': len(self.stats['critical_errors']),
                'most_killed_process': max(self.stats['oom_kills'], 
                                        key=self.stats['oom_kills'].get, default=None),
                'hardware_errors_count': len(self.stats['hardware_errors']),
                'common_network_issues': dict(self.stats['network_problems']),
                'security_events_summary': dict(self.stats['security_events']),
                'suspicious_ips': [ip for ip, count in self.stats['high_risk_ips'].items() 
                                if count >= self.ip_threshold]
            },
            'details': {
                'critical_errors': self.stats['critical_errors'][:10],  # 显示前10条关键错误
                'hardware_errors': self.stats['hardware_errors'][:5],
                'full_oom_stats': dict(self.stats['oom_kills'])
            }
        }
        return report

def main():
    parser = argparse.ArgumentParser(description='Linux syslog分析工具')
    parser.add_argument('-f', '--file', default='/var/log/syslog',
                       help='日志文件路径（默认：/var/log/syslog）')
    parser.add_argument('-o', '--output', default='syslog_report.json',
                       help='输出报告文件名（默认：syslog_report.json）')
    args = parser.parse_args()
    
    analyzer = SyslogAnalyzer()
    
    try:
        with open(args.file, 'r') as logfile:
            for line in logfile:
                analyzer.analyze(line)
    except FileNotFoundError:
        print(f"错误：文件 {args.file} 不存在！")
        return
    except PermissionError:
        print(f"错误：无权读取文件 {args.file}！")
        return
    
    report = analyzer.generate_report()
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    # 控制台摘要输出
    print("\n=== 系统日志分析报告 ===")
    print(f"* 严重错误数量: {report['summary']['total_critical_errors']}")
    print(f"* 触发OOM Killer次数最多的进程: {report['summary']['most_killed_process']}")
    print(f"* 硬件/磁盘错误数量: {report['summary']['hardware_errors_count']}")
    print("\n可疑IP地址：")
    for ip in report['summary']['suspicious_ips']:
        print(f"  - {ip} (出现次数: {analyzer.stats['high_risk_ips'][ip]})")
    
    print(f"\n完整报告已保存至 {args.output}")

if __name__ == '__main__':
    main()
