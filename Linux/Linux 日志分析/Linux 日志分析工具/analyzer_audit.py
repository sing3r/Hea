import re
import json
from datetime import datetime
from collections import defaultdict

# ==================== 性能监控基类 ====================
class PerformanceAnalyzer:
    """系统性能分析基类"""
    def generate_daily_report(self):
        """生成性能监控基础报告（可扩展）"""
        return {
            'performance': {
                'cpu_usage': '98%',
                'memory_usage': '76%',
                'io_wait': '2.3%'
            },
            'security': {
                'authentication_risks': {
                    'threat_analysis': [
                        {
                            'type': 'failed_login',
                            'user': 'root',
                            'timestamp': datetime.now().isoformat()
                        }
                    ]
                }
            }
        }

class UnifiedMonitorSystem(PerformanceAnalyzer):
    """统一监控系统基类"""
    def __init__(self):
        super().__init__()
        self.baseline_config = {
            'high_cpu_threshold': 90,
            'sensitive_files': ['/etc/passwd', '/etc/shadow']
        }

# ==================== 审计分析模块 ====================
class AuditAnalyzer:
    """Linux audit.log分析核心类"""
    def __init__(self):
        self.audit_events = {
            'privilege_escalation': [],
            'sensitive_file_access': defaultdict(list),
            'account_changes': [],
            'raw_events': []
        }

        # 攻击检测规则库
        self.RULES = {
            'sudo_abuse': {
                'patterns': [r'comm="sudo".*cmd=".*(useradd|visudo|passwd)"'],
                'severity': 'high'
            },
            'secret_access': {
                'file_patterns': [r'/etc/(passwd|shadow)', r'\.(pem|key)$'],
                'open_modes': ['O_WRONLY', 'O_RDWR'],
                'severity': 'critical'
            },
            'process_injection': {
                'syscalls': ['execve', 'ptrace', 'memfd_create'],
                'suspicious_args': ['/tmp/', 'http://', ' -e '],
                'severity': 'high' 
            }
        }

    def parse_audit_log(self, filename='/var/log/audit/audit.log'):
        """解析审计日志结构化数据"""
        current_event = {}
        event_pattern = re.compile(r'(\w+)=("[^"]*"|\S+)')

        try:
            with open(filename, 'r') as f:
                for line in f:
                    if line.startswith('type='):
                        if current_event:
                            self._process_audit_event(current_event)
                        current_event = {}
                    
                    for key, value in event_pattern.findall(line):
                        value = value.strip('"')
                        if value.isdigit():
                            value = int(value)
                        current_event[key] = value
                
                if current_event:
                    self._process_audit_event(current_event)
        except FileNotFoundError:
            print(f"错误：审计日志文件 {filename} 不存在")
            exit(1)

    def _process_audit_event(self, event):
        """分析和分类审计事件"""
        self.audit_events['raw_events'].append(event)
        
        # 检测提权操作
        if event.get('proctitle', '') and 'sudo' in event['proctitle']:
            self.audit_events['privilege_escalation'].append(event)
        
        # 检测敏感文件访问
        if event.get('type') == 'SYSCALL' and 'success=yes' in event:
            file_path = event.get('name', '')
            for pattern in self.RULES['secret_access']['file_patterns']:
                if re.search(pattern, file_path):
                    self.audit_events['sensitive_file_access'][file_path].append({
                        'time': event.get('time', '未知时间'),
                        'pid': event.get('pid', 'N/A'),
                        'user': event.get('uid', 'unknown')
                    })
        
        # 跟踪账户变更
        if event.get('exe') in ['/usr/sbin/useradd', '/usr/sbin/userdel']:
            user_match = re.search(r' (\S+)$', event.get('proctitle', ''))
            if user_match:
                self.audit_events['account_changes'].append({
                    'action': '用户添加' if 'useradd' in event['exe'] else '用户删除',
                    'username': user_match.group(1),
                    'timestamp': event.get('time')
                })

    def detect_suspicious_activity(self):
        """基于规则的可疑行为检测"""
        alerts = []
        for event in self.audit_events['raw_events']:
            msg = str(event)
            
            # 检测sudo滥用
            if event.get('comm') == 'sudo':
                for pattern in self.RULES['sudo_abuse']['patterns']:
                    if re.search(pattern, msg):
                        alerts.append({
                            'type': '特权滥用',
                            'rule': 'sudo_abuse',
                            'details': event,
                            'severity': self.RULES['sudo_abuse']['severity']
                        })
            
            # 检测可疑进程
            if event.get('syscall') in self.RULES['process_injection']['syscalls']:
                cmdline = event.get('proctitle', '')
                if any(p in cmdline for p in self.RULES['process_injection']['suspicious_args']):
                    alerts.append({
                        'type': '可疑进程注入',
                        'rule': 'suspicious_exec',
                        'details': event,
                        'severity': self.RULES['process_injection']['severity']
                    })
        
        return alerts

    def analyze_attack_chain(self):
        """攻击链分析（ATT&CK框架模式）"""
        attack_sequence = []
        seen_events = set()
        
        for event in sorted(self.audit_events['raw_events'], 
                          key=lambda x: x.get('time', '')):
            event_id = event.get('msg', '')
            if event_id in seen_events:
                continue
            seen_events.add(event_id)
            
            # 侦察阶段检测
            if 'name="/etc/sudoers"' in str(event):
                attack_sequence.append({
                    '阶段': '侦察',
                    '操作': '查看sudo配置',
                    '时间': event.get('time'),
                    '用户': event.get('uid', 'unknown')
                })
            
            # 提权阶段检测
            if 'exe="/usr/bin/chmod"' in str(event):
                attack_sequence.append({
                    '阶段': '提权',
                    '操作': '修改关键文件权限',
                    '命令': event.get('proctitle', 'N/A')
                })
            
            # 横向移动检测
            if 'saddr=' in str(event) and 'daddr=' in str(event):
                attack_sequence.append({
                    '阶段': '横向移动',
                    '源IP': event.get('saddr', 'unknown'),
                    '目标IP': event.get('daddr', 'unknown')
                })
        
        return {'attack_chain': attack_sequence} if attack_sequence else {}

# ==================== 统一安全监控系统 ====================
class UnifiedSecurityMonitor(UnifiedMonitorSystem, AuditAnalyzer):
    """多维安全监测（性能指标 + 审计日志）"""
    
    def generate_incident_report(self):
        """生成综合安全事件报告"""
        base_report = super().generate_daily_report()
        audit_alerts = self.detect_suspicious_activity()
        attack_chain = self.analyze_attack_chain()
        
        # 账户异常关联分析
        account_risks = []
        for account_event in self.audit_events['account_changes']:
            matched_auth = [
                auth for auth in base_report['security']['authentication_risks']['threat_analysis']
                if auth['user'] == account_event['username']
                and self._is_timestamp_close(auth['timestamp'], account_event['timestamp'])
            ]
            
            if matched_auth:
                account_risks.append({
                    'account_change': account_event,
                    'related_auth_events': matched_auth,
                    'risk_level': 'high' if len(matched_auth) > 3 else 'medium'
                })
        
        # 文件访问基线对比
        sensitive_access = {}
        for file_path, accesses in self.audit_events['sensitive_file_access'].items():
            if file_path in self.baseline_config['sensitive_files']:
                sensitive_access[file_path] = {
                    'access_count': len(accesses),
                    'last_access': accesses[-1]['time'] if accesses else '无记录'
                }
        
        return {
            **base_report,
            'forensics': {
                'security_alerts': audit_alerts,
                'sensitive_access': sensitive_access,
                'attack_steps': attack_chain,
                'account_analysis': account_risks
            }
        }
    
    def _is_timestamp_close(self, iso_timestamp, audit_time):
        """判断两个时间戳是否在5分钟内"""
        try:
            dt1 = datetime.fromisoformat(iso_timestamp)
            dt2 = datetime.strptime(audit_time, "%H:%M:%S").replace(
                year=dt1.year, month=dt1.month, day=dt1.day)
            return abs((dt2 - dt1).total_seconds()) < 300
        except ValueError:
            return False

if __name__ == '__main__':
    # 初始化监控系统
    monitor = UnifiedSecurityMonitor()
    
    # 解析审计日志
    try:
        monitor.parse_audit_log()
    except PermissionError as e:
        print(f"权限不足: {e}，请使用sudo执行")
        exit(1)
    except Exception as e:
        print(f"解析错误: {e}")
        exit(1)
    
    # 生成并保存报告
    report = monitor.generate_incident_report()
    
    with open('security_report.json', 'w') as f:
        json.dump(report, f, 
                 indent=2, 
                 default=str, 
                 ensure_ascii=False)
    
    print("[+] 安全报告已生成: security_report.json")
    print("    可疑活动数量:", len(report['forensics']['security_alerts']))
    print("    攻击链步骤:", len(report['forensics']['attack_steps'].get('attack_chain', [])))
