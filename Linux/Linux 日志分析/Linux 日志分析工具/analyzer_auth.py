#!/usr/bin/env python3
import re
import json
import argparse
from collections import defaultdict
from datetime import datetime

class AuthLogAnalyzer:
    def __init__(self):
        # 专用安全事件检测模式
        self.patterns = {
            'ssh_failed_login': re.compile(
                r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
            ),
            'ssh_success': re.compile(
                r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
            ),
            'sudo_events': re.compile(
                r"(\w+) :.*COMMAND=(/.+?)($|\s)"
            ),
            'user_changes': re.compile(
                r"(useradd|usermod|userdel).* (new user|old UID|deleted user) (\w+)"
            ),
            'brute_force': re.compile(
                r"message repeated (\d+) times:.* Failed password"
            ),
            'pubkey_auth': re.compile(
                r"Accepted publickey for (\S+) from (\d+\.\d+\.\d+\.\d+)"
            )
        }

        # 专用安全统计结构
        self.stats = {
            'authentication': {
                'ssh_failures': defaultdict(lambda: defaultdict(int)),
                'success_logins': [],
                'pubkey_logins': []
            },
            'privilege': {
                'sudo_commands': defaultdict(list),
                'privilege_esc': []
            },
            'user_management': {
                'created': [],
                'modified': [],
                'deleted': []
            },
            'threat_detection': {
                'brute_force_attempts': [],
                'ip_reputation': defaultdict(int)
            },
            '_metadata': {
                'log_source': None,
                'analyzed_lines': 0
            }
        }

    def parse_timestamp(self, line):
        """兼容多种时间格式的智能解析"""
        try:
            # 匹配 syslog 格式时间戳：Mar 31 10:45:01
            ts_str = re.search(r"^(\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})", line).group(1)
            current_year = datetime.now().year
            full_ts = f"{current_year} {ts_str}"
            return datetime.strptime(full_ts, "%Y %b %d %H:%M:%S")
        except Exception as e:
            print(f"时间解析警告: {str(e)} - 原始日志行: {line[:60]}")
            return None

    def parse_auth_line(self, line):
        """针对 auth.log 的增强解析器"""
        match = re.match(
            r"(?P<timestamp>\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
            r"(?P<host>\S+)\s"
            r"(?P<process>\w+(?:\[\d+\])?):?\s"
            r"(?P<message>.*)$",
            line
        )
        
        if not match:
            return None

        entry = match.groupdict()
        return {
            'timestamp': self.parse_timestamp(line),
            'host': entry['host'],
            'process': entry['process'].split('[')[0],  # 去掉进程号
            'message': entry['message']
        }

    def analyze_auth(self, line):
        entry = self.parse_auth_line(line)
        if not entry:
            return

        self.stats['_metadata']['analyzed_lines'] += 1
        msg = entry['message']

        # SSH登录分析
        if ssh_fail := self.patterns['ssh_failed_login'].search(msg):
            user, ip = ssh_fail.groups()
            self.stats['authentication']['ssh_failures'][ip][user] += 1
            self.stats['threat_detection']['ip_reputation'][ip] += 1

        if ssh_ok := self.patterns['ssh_success'].search(msg):
            user, ip = ssh_ok.groups()
            self.stats['authentication']['success_logins'].append({
                'user': user,
                'source_ip': ip,
                'timestamp': entry['timestamp'].isoformat(),
                'auth_method': 'password'
            })

        if ssh_pubkey := self.patterns['pubkey_auth'].search(msg):
            user, ip = ssh_pubkey.groups()
            self.stats['authentication']['pubkey_logins'].append({
                'user': user,
                'source_ip': ip,
                'timestamp': entry['timestamp'].isoformat(),
                'auth_method': 'publickey'
            })

        # 特权命令监控
        if sudo_cmd := self.patterns['sudo_events'].search(msg):
            user, command = sudo_cmd.groups()
            self.stats['privilege']['sudo_commands'][user].append({
                'command': command.strip('"'), 
                'timestamp': entry['timestamp'].isoformat()
            })

        # 用户变更事件
        if user_change := self.patterns['user_changes'].search(msg):
            action, _, user = user_change.groups()
            event = {
                'user': user,
                'timestamp': entry['timestamp'].isoformat(),
                'action': action
            }
            if action == 'useradd':
                self.stats['user_management']['created'].append(event)
            elif action == 'usermod':
                self.stats['user_management']['modified'].append(event)
            elif action == 'userdel':
                self.stats['user_management']['deleted'].append(event)

        # 暴力破解检测
        if brute := self.patterns['brute_force'].search(msg):
            count = int(brute.group(1))
            last_failure = next(
                (item for item in reversed(
                    self.stats['authentication']['ssh_failures'].items())
                ), None)
            if last_failure:
                ip, users = last_failure
                self.stats['threat_detection']['brute_force_attempts'].append({
                    'source_ip': ip,
                    'attempts': count,
                    'last_attempt': entry['timestamp'].isoformat()
                })

    def generate_security_report(self):
        # 生成详细安全报表
        report = {
            'security_overview': {
                'total_failed_logins': sum(
                    sum(users.values()) 
                    for users in self.stats['authentication']['ssh_failures'].values()
                ),
                'successful_logins': len(self.stats['authentication']['success_logins']),
                'privileged_commands': sum(
                    len(cmds) for cmds in self.stats['privilege']['sudo_commands'].values()
                )
            },
            'threat_analysis': {
                'top_attack_sources': sorted(
                    self.stats['threat_detection']['ip_reputation'].items(),
                    key=lambda x: x[1], 
                    reverse=True
                )[:5],
                'repeated_brute_force': self.stats['threat_detection']['brute_force_attempts']
            },
            'user_activity': {
                'recent_sudo_users': [
                    {'user': u, 'count': len(c)} 
                    for u, c in list(self.stats['privilege']['sudo_commands'].items())[-5:]
                ],
                'new_accounts': [
                    {'user': u['user'], 'when': u['timestamp']} 
                    for u in self.stats['user_management']['created'][-3:]
                ]
            },
            '_metadata': self.stats['_metadata']
        }
        return report

    def console_security_report(self, report):
        print(f"\n{' 安全审计报告 ':=^80}")
        print(f"分析文件: {report['_metadata']['log_source']}")
        print(f"处理日志行: {report['_metadata']['analyzed_lines']}")
        
        # 登录尝试统计
        print("\n[ 认证分析 ]")
        print(f"* 失败登录尝试: {report['security_overview']['total_failed_logins']}")
        print(f"* 成功登录次数: {report['security_overview']['successful_logins']}")
        
        # 威胁情报
        print("\n[ 威胁检测 ]")
        if report['threat_analysis']['top_attack_sources']:
            print("可疑IP排行:")
            for ip, count in report['threat_analysis']['top_attack_sources']:
                print(f"  - {ip}: {count} 次尝试")
        
        # 用户行为分析
        print("\n[ 用户行为 ]")
        if report['user_activity']['recent_sudo_users']:
            print("近期特权命令执行:")
            for user in report['user_activity']['recent_sudo_users']:
                print(f"  - {user['user']}: {user['count']} 条命令")
        
        print("\n" + "="*80)

def main():
    parser = argparse.ArgumentParser(description="高级安全日志审计工具")
    parser.add_argument('-f', '--file', required=True,
                       help="指定认证日志文件路径 (如 /var/log/auth.log)")
    parser.add_argument('-o', '--output', default='security_audit.json',
                       help="输出报告文件名")
    args = parser.parse_args()
    
    analyzer = AuthLogAnalyzer()
    
    try:
        with open(args.file, 'r') as f:
            analyzer.stats['_metadata']['log_source'] = args.file
            for line in f:
                analyzer.analyze_auth(line)
    except Exception as e:
        print(f"日志处理异常: {str(e)}")
        exit(1)
    
    report = analyzer.generate_security_report()
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    analyzer.console_security_report(report)
    print(f"\n{' 报告生成完成 ':=^80}\n输出文件: {args.output}")

if __name__ == '__main__':
    main()
