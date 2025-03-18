import subprocess
from statistics import mean, stdev

class PerformanceAnalyzer:
    def __init__(self, sa_dir="/var/log/sa"):
        self.sa_dir = sa_dir
        self.metric_config = {  # 配置需要提取的核心指标
            'CPU': ['%user', '%iowait', '%steal'],
            'MEM': ['kbmemused', '%memused'],
            'DISK': ['tps', 'rkB/s', 'wkB/s'],
            'NET': ['rxkB/s', 'txkB/s']
        }
        self.baseline = {}  # 用于异常检测的动态基线

    def parse_sar_log(self, date_str):
        """解析指定日期的sar日志"""
        sa_file = f"{self.sa_dir}/sa{date_str[-2:]}"  # 例如sa01对应1号日志
        try:
            output = subprocess.check_output(
                ['sar', '-f', sa_file, '-A'], 
                text=True,
                stderr=subprocess.STDOUT
            )
            return self._parse_sar_text(output)
        except subprocess.CalledProcessError as e:
            print(f"解析sar日志失败: {e}")
            return None

    def _parse_sar_text(self, sar_output):
        """处理sar命令的文本输出"""
        metrics = defaultdict(list)
        current_section = None

        for line in sar_output.split('\n'):
            # 检测指标区域开始
            if line.startswith('Linux') and 'CPU' in line:
                current_section = 'CPU'
            elif 'Memory' in line:
                current_section = 'MEM'
            elif 'IO' in line and 'tps' in line:
                current_section = 'DISK'
            elif 'rxkB/s' in line:
                current_section = 'NET'

            # 数据行处理
            if current_section and line[0].isdigit():
                parts = line.split()
                timestamp = f"{parts[0]} {parts[1]}"
                data = self._extract_metrics(current_section, parts)
                if data:
                    metrics[current_section].append({
                        'timestamp': timestamp,
                        **data
                    })
        return metrics

    def _extract_metrics(self, section, parts):
        """根据指标配置提取数据"""
        try:
            values = {}
            if section == 'CPU':
                # 格式: HH:MM:SS    CPU     %user     %nice   ... %steal
                idx_map = {metric: i+2 for i, metric in enumerate(['%user', '%nice', '%system', '%iowait', '%steal', '%idle'])}
                for metric in self.metric_config[section]:
                    values[metric] = float(parts[idx_map[metric]])
            elif section == 'MEM':
                # 格式: HH:MM:SS kbmemfree ... kbmemused %memused 
                values = {
                    'kbmemused': int(parts[2]),
                    '%memused': float(parts[4])
                }
            elif section == 'DISK':
                # 例: 10:00:01    dev8-0   10.00    200.00    300.00
                values = {
                    'tps': float(parts[2]),
                    'rkB/s': float(parts[3]),
                    'wkB/s': float(parts[4])
                }
            elif section == 'NET':
                # 例: 10:00:01    eth0   100.00    200.00   
                values = {
                    'rxkB/s': float(parts[2]),
                    'txkB/s': float(parts[3])
                }
            return {k: v for k, v in values.items() if k in self.metric_config[section]}
        except (IndexError, ValueError):
            return None

    def detect_anomalies(self, day_metrics):
        """基于动态基线检测性能异常"""
        anomalies = []
        for section in day_metrics:
            for metric in self.metric_config.get(section, []):
                # 提取本日数据
                data_points = [entry[metric] for entry in day_metrics[section]]
                
                # 初始化基线（取前三天数据）
                if metric not in self.baseline:
                    self._init_baseline(metric)
                
                # 计算当前平均与标准差
                current_avg = mean(data_points)
                if self.baseline[metric]['std'] > 0:
                    z_score = abs((current_avg - self.baseline[metric]['mean']) / self.baseline[metric]['std'])
                    if z_score > 2.5:  # 超过2.5个标准差
                        anomalies.append({
                            'metric': metric,
                            'current': current_avg,
                            'baseline': self.baseline[metric],
                            'severity': 'high' if z_score > 3 else 'medium'
                        })
        return anomalies

    def _init_baseline(self, metric, days=3):
        """初始基线为前三天的历史数据"""
        baseline_data = []
        for i in range(1, days+1):
            date_str = (datetime.now() - timedelta(days=i)).strftime("%Y%m%d")
            day_data = self.parse_sar_log(date_str)
            if not day_data:
                continue
            # 提取对应指标的所有数据点
            points = []
            for section in day_data.values():
                for entry in section:
                    if metric in entry:
                        points.append(entry[metric])
            if points:
                baseline_data.extend(points)
        
        if baseline_data:
            self.baseline[metric] = {
                'mean': mean(baseline_data),
                'std': stdev(baseline_data) if len(baseline_data)>1 else 0
            }
        else:
            # 找不到历史数据时使用默认阈值
            self.baseline[metric] = {'mean': 0, 'std': 0} 
            
class UnifiedMonitorSystem(UnifiedSecurityAnalyzer, PerformanceAnalyzer):
    """综合监控系统（安全事件 + 性能指标）"""
    def generate_daily_report(self):
        # 安全报告
        security = super().generate_intel_report()
        
        # 性能报告
        today = datetime.now().strftime("%Y%m%d")
        perf_data = self.parse_sar_log(today)
        anomalies = self.detect_anomalies(perf_data) if perf_data else []
        
        return {
            'security': security,
            'performance': {
                'current': perf_data,
                'anomalies': anomalies,
                'highlights': self._generate_perf_highlights(perf_data),
                'baseline': self.baseline
            },
            'time_correlations': self._correlate_events_with_perf(
                security,
                perf_data
            ) if perf_data else []
        }
    
    def _generate_perf_highlights(self, data):
        """生成Top性能事件摘要"""
        highlights = []
        # CPU最高使用时段
        cpu_peak = max(data['CPU'], key=lambda x: x['%user'])
        highlights.append(f"CPU峰值: {cpu_peak['%user']}% user @ {cpu_peak['timestamp']}")
        
        # 网络流量高峰
        net_peak = max(data['NET'], key=lambda x: x['rxkB/s'] + x['txkB/s'])
        highlights.append(f"网络流量峰值: ↓{net_peak['rxkB/s']}kB/s ↑{net_peak['txkB/s']}kB/s")
        return highlights
    
    def _correlate_events_with_perf(self, sec_report, perf_data):
        """关联安全事件与性能指标时间点"""
        events_with_perf = []
        for event in sec_report.get('authentication_risks', {}).get('threat_analysis', []):
            event_time = datetime.fromisoformat(event['timestamp'])
            # 寻找前后5分钟的性能数据
            related_perf = []
            for entry in perf_data['CPU']:
                entry_time = datetime.strptime(entry['timestamp'], "%H:%M:%S %Y-%m-%d")
                if abs((entry_time - event_time).total_seconds()) <= 300:
                    related_perf.append({
                        'metric': 'CPU',
                        'value': entry['%user'],
                        'timestamp': entry_time.isoformat()
                    })
            if related_perf:
                events_with_perf.append({
                    'event_id': event.get('id'),
                    'attack_type': event.get('type'),
                    'source_ip': event.get('source_ip'),
                    'related_performance': related_perf
                })
        return events_with_perf

if __name__ == '__main__':
    monitor = UnifiedMonitorSystem()
    
    # 获取当日性能数据
    current_date = datetime.now().strftime("%Y%m%d")
    monitor.parse_sar_log(current_date)  # 需处理权限问题
    
    # 生成综合报告
    full_report = monitor.generate_daily_report()
    
    with open('daily_monitor_report.json', 'w') as f:
        json.dump(full_report, f, indent=2, ensure_ascii=False)
    
    print("生成日报表: daily_monitor_report.json")
