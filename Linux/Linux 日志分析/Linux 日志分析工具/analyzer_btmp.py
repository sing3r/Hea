import subprocess
from datetime import datetime, timedelta

class BTMPAnalyzer:
    def __init__(self):
        self.btmp_stats = {
            'failed_attempts': defaultdict(int),
            'user_targeting': defaultdict(lambda: defaultdict(int)),
            'time_patterns': defaultdict(int),
            '_raw_data': []
        }
        
        # 用于检测暴力破解的模式
        self.BRUTE_FORCE_THRESHOLD = 20  # 同IP每小时超过20次视为暴力破解
        self.SENSITIVE_USERS = {'root', 'admin', 'oracle', 'nobody'}

    def parse_btmp(self, filename='/var/log/btmp'):
        """通过lastb命令解析btmp日志"""
        try:
            result = subprocess.run(
                ['lastb', '-F', '-a', '-i', '-f', filename],
                capture_output=True, 
                text=True,
                check=True
            )
            self._process_lastb_output(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"错误: 无法读取btmp文件 ({e})")
            if "Permission denied" in str(e):
                print("提示: 需要sudo权限执行（建议添加当前用户到adm组）")

    def _process_lastb_output(self, output): 
        """处理lastb命令的输出"""
        line_pattern = re.compile(
            r"(?P<user>\S+)\s+pts/\d+\s+"
            r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
            r"(?P<date>\w{3}\s\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})\s+-"
            r"\s+\d{2}:\d{2}\s+\(\d+:\d+\)"
        )

        for line in output.split('\n'):
            if not line.strip():
                continue
                
            match = line_pattern.search(line)
            if not match:
                continue
                
            entry = match.groupdict()
            dt = datetime.strptime(entry['date'], "%a %b %d %H:%M:%S %Y")
            hour_window = dt.replace(minute=0, second=0, microsecond=0)
            
            # 记录原始数据
            self.btmp_stats['_raw_data'].append({
                'user': entry['user'],
                'ip': entry['ip'],
                'timestamp': dt.isoformat()
            })
            
            # 分类统计
            self.btmp_stats['failed_attempts'][entry['ip']] += 1
            self.btmp_stats['user_targeting'][entry['ip']][entry['user']] += 1
            self.btmp_stats['time_patterns'][hour_window.isoformat()] += 1

    def detect_brute_force(self):
        """识别可能的暴力破解行为"""
        suspects = []
        for ip, count in self.btmp_stats['failed_attempts'].items():
            time_slots = [
                ts for ts in self.btmp_stats['time_patterns']
                if ip in self.btmp_stats['time_patterns'][ts]
            ]
            # 按小时窗口计算频率
            freq = max([
                sum(ts.count(ip) for ts in time_slots[i:i+5])  # 检测5小时窗口
                for i in range(len(time_slots)-4)
            ], default=0)
            
            targeted_users = self.btmp_stats['user_targeting'][ip]
            high_value_target = any(u in self.SENSITIVE_USERS for u in targeted_users)
            
            if freq > self.BRUTE_FORCE_THRESHOLD or high_value_target:
                suspects.append({
                    'ip': ip,
                    'total_attempts': count,
                    'targeted_users': dict(targeted_users),
                    'activity_periods': sorted(time_slots),
                    'risk_level': 'critical' if high_value_target else 'high'
                })
        return sorted(suspects, key=lambda x: x['total_attempts'], reverse=True)

class UnifiedSecurityAnalyzer(UnifiedLogAnalyzer, BTMPAnalyzer):
    """综合安全分析系统"""
    def __init__(self):
        UnifiedLogAnalyzer.__init__(self)
        BTMPAnalyzer.__init__(self)
        
    def generate_intel_report(self):
        """生成威胁情报综合报告"""
        auth_threats = super().generate_security_report()
        kernel_health = super().generate_kernel_report()
        brute_force = self.detect_brute_force()
        
        # 数据关联分析
        related_ips = set(auth_threats['threat_analysis'].get('top_attack_sources', [])) & \
                      {x['ip'] for x in brute_force}
        
        return {
            'authentication_risks': auth_threats,
            'kernel_events': kernel_health,
            'brute_force_analysis': {
                'suspicious_ips': brute_force,
                'peak_hours': sorted(
                    self.btmp_stats['time_patterns'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:3]  # 取最活跃的3个时间段
            },
            'cross_correlation': {
                'ips_in_both_logs': list(related_ips),
                'users_with_failed_sudo': [
                    user for user in auth_threats['privilege_events']['sudo_failures']
                    if user in self.SENSITIVE_USERS
                ]
            }
        }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="综合安全审计系统")
    parser.add_argument('-t', '--type', required=True,
                       choices=['auth', 'kern', 'btmp', 'full'],
                       help="日志类型: auth|kern|btmp|full")
    parser.add_argument('-f', '--file', 
                       default='/var/log/btmp',  # 默认处理btmp
                       help="日志文件路径")
    args = parser.parse_args()
    
    analyzer = UnifiedSecurityAnalyzer()
    
    if args.type == 'btmp' or args.type == 'full':
        analyzer.parse_btmp(args.file)
    
    if args.type == 'full':
        # 全量分析需要其他日志路径，此处省略示例
        pass
        
    report = analyzer.generate_intel_report()
    
    with open('threat_intel_report.json', 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print("生成威胁情报报告: threat_intel_report.json")
