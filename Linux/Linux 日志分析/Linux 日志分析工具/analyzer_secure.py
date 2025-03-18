#!/usr/bin/env python3
import re
import json
import argparse
from collections import defaultdict
from datetime import datetime

class UnifiedSecurityAnalyzer:
    def __init__(self):
        # 兼容两种日志格式的正则表达式库
        self.patterns = {
            'ssh_failed': re.compile(
                r"Failed\s(?:password|publickey)\sfor\s(?:invalid\suser\s)?(\S+)\sfrom\s(\d+\.\d+\.\d+\.\d+)"
            ),
            'ssh_success': re.compile(
                r"Accepted\s(?:password|publickey)\sfor\s(\S+)\sfrom\s(\d+\.\d+\.\d+\.\d+)"
            ),
            'sudo_cmd': re.compile(
                r"(\w+)\s:\s.*COMMAND=(.+?)(\s|$)"
            ),
            'user_change': re.compile(
                r"user\s(added|modified|deleted).* '(.*?)'"
            ),
            'session_open': re.compile(
                r"session opened for user (\S+) by (\S+)\[pid=\d+\]"
            )
        }
        
        # 增强型数据结构
        self.stats = {
            'auth_events': {
                'failed_attempts': defaultdict(lambda: {'count':0, 'users':set()}), # {ip: {count, users}}
                'success_logins': defaultdict(list), # {user: [login_details]}
                'session_starts': []
            },
            'privilege_ops': {
                'sudo_commands': defaultdict(list),
                'setuid_execs': []
            },
            'account_changes': {
                'created': [],
                'modified': [],
                'deleted': []
            },
            'risk_assessment': {
                'high_frequency_ips': [],
                'suspicious_users': defaultdict(int)
            }
        }
        
        # 日志格式自动检测
        self.log_type = None  # 'auth' 或 'secure'

    def detect_log_format(self, line):
        """根据首行日志自动检测日志类型"""
        if re.search(r"sudo|sshd.*Failed password", line):
            if "systemd-logind" in line or "sudo" in line:
                self.log_type = 'auth'
            elif "pam_unix" in line and "authentication failure" in line:
                self.log_type = 'secure'
        return self.log_type

    def parse_timestamp(self, raw_ts):
        """智能时间戳解析，支持以下格式：
        - auth.log: Mar 31 10:45:01
        - secure:   Jul 15 09:20:01 2023
        """
        ts_formats = [
            ('%b %d %H:%M:%S %Y', 30),  # secure带年份的格式
            ('%b %d %H:%M:%S', 19)      # auth.log不带年份的格式
        ]
        
        for fmt, max_len in ts_formats:
            try:
                if len(raw_ts) > max_len:
                    continue
                dt = datetime.strptime(raw_ts, fmt)
                # 如果年份未被捕获，补当前年份
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        return None

    def unified_parser(self, line):
        """通用日志解析器，返回结构化字典"""
        # 尝试两种日志格式的正则匹配
        patterns = [
            # secure 格式 (带年份)
            r"^(?P<timestamp>\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})\s"
            r"(?P<host>\S+)\s"
            r"(?P<service>\w+)(?:\[\d+\])?:\s"
            r"(?P<message>.*)$",
            
            # auth.log 格式 (不带年份)
            r"^(?P<timestamp>\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})\s"  
            r"(?P<host>\S+)\s"
            r"(?P<service>\w+)(?:\[?\d+\]?):?\s"
            r"(?P<message>.*)$"
        ]
        
        entry = None
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                entry = match.groupdict()
                break
        if not entry:
            return None
        
        # 统一字段名称
        return {
            'timestamp': self.parse_timestamp(entry['timestamp']),
            'hostname': entry['host'],
            'service': entry['service'].replace('[', '').replace(']', '').split(':')[0],
            'message': entry['message'],
            'raw': line.strip()
        }

    def analyze_line(self, parsed):
        """统一分析逻辑"""
        if not parsed:
            return
        
        # === SSH 认证分析 ===
        if failed := self.patterns['ssh_failed'].search(parsed['message']):
            user, ip = failed.groups()
            self.stats['auth_events']['failed_attempts'][ip]['count'] += 1
            self.stats['auth_events']['failed_attempts'][ip]['users'].add(user)
            self.stats['risk_assessment']['suspicious_users'][user] += 1
            
        if success := self.patterns['ssh_success'].search(parsed['message']):
            user, ip = success.groups()
            login_record = {
                'ip': ip,
                'timestamp': parsed['timestamp'].isoformat(),
                'service': parsed['service'],
                'protocol': 'SSHv2' if 'ssh2' in parsed['message'] else 'SSHv1'
            }
            self.stats['auth_events']['success_logins'][user].append(login_record)
            
        # === 特权操作监控 ===
        if sudo := self.patterns['sudo_cmd'].search(parsed['message']):
            user, cmd, _ = sudo.groups()
            self.stats['privilege_ops']['sudo_commands'][user].append({
                'command': cmd.strip('"'),
                'timestamp': parsed['timestamp'].isoformat(),
                'from_ip': self._extract_ip(parsed['message'])
            })
            
        # === 账户变更检测 ===
        if account := self.patterns['user_change'].search(parsed['message']):
            action, user = account.groups()
            event = {
                'user': user,
                'timestamp': parsed['timestamp'].isoformat(),
                'initiator': self._extract_initiator(parsed['message'])
            }
            if action == 'added':
                self.stats['account_changes']['created'].append(event)
            elif action == 'modified':
                self.stats['account_changes']['modified'].append(event)
            elif action == 'deleted':
                self.stats['account_changes']['deleted'].append(event)
                
    def _extract_ip(self, msg):
        """从日志消息中提取IP地址"""
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", msg)
        return ip_match.group(0) if ip_match else None
        
    def _extract_initiator(self, msg):
        """提取账户变更操作发起者"""
        initiator = re.search(r"by (\S+)", msg)
        return initiator.group(1) if initiator else 'unknown'

    def generate_report(self):
        """生成带风险评级的报告"""
        # 统计高频攻击IP (超过5次失败)
        high_risk_ips = [
            {'ip': ip, 'attempts': data['count'], 'users': list(data['users'])} 
            for ip, data in self.stats['auth_events']['failed_attempts'].items()
            if data['count'] >= 5
        ]
        
        # 可疑用户标记 (超过3次失败)
        suspicious_users = [
            user for user, count in self.stats['risk_assessment']['suspicious_users'].items()
            if count > 3
        ]
        
        return {
            'summary': {
                'total_events': sum([
                    len(self.stats['auth_events']['success_logins']),
                    sum([v['count'] for v in self.stats['auth_events']['failed_attempts'].values()])
                ]),
                'period': {
                    'start': min([e['timestamp'] for e in self.stats['auth_events']['success_logins']], default=None),
                    'end': max([e['timestamp'] for e in self.stats['auth_events']['success_logins']], default=None)
                }
            },
            'risks': {
                'high_risk_ips': sorted(high_risk_ips, key=lambda x: x['attempts'], reverse=True),
                'suspicious_users': suspicious_users
            },
            'details': {
                'account_operations': {
                    'created': self.stats['account_changes']['created'],
                    'modified': self.stats['account_changes']['modified'],
                    'deleted': self.stats['account_changes']['deleted']
                },
                'privilege_escalation': {
                    'sudo_usage': {user: len(cmds) for user, cmds in self.stats['privilege_ops']['sudo_commands'].items()}
                }
            },
            '_metadata': {
                'log_type': self.log_type or 'unidentified',
                'processed_lines': len(self.stats['auth_events']['success_logins']) + sum(
                    v['count'] for v in self.stats['auth_events']['failed_attempts'].values()
                )
            }
        }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='SecureLogAnalyzer', 
                                    description='统一安全日志分析工具 (支持 auth.log 和 secure)')
    parser.add_argument('-f', '--file', required=True, help='日志文件路径')
    parser.add_argument('-o', '--output', default='security_audit.json', help='输出报告文件')
    args = parser.parse_args()
    
    analyzer = UnifiedSecurityAnalyzer()
    
    with open(args.file, 'r') as f:
        first_line = f.readline()
        analyzer.detect_log_format(first_line)
        f.seek(0)
        
        for line in f:
            parsed = analyzer.unified_parser(line)
            analyzer.analyze_line(parsed)
    
    report = analyzer.generate_report()
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"生成安全报告到 {args.output}")
    print(f"检测到 {len(report['risks']['high_risk_ips'])} 个高风险IP")
    print(f"发现 {len(report['risks']['suspicious_users'])} 个可疑用户")
