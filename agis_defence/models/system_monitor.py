import psutil
import time
from typing import Dict, Any
from datetime import datetime

class SystemMonitor:
    def __init__(self):
        self.last_network_check = None
        self.last_network_bytes = None
        self.network_stats_history = []
        
    def get_stats(self) -> Dict[str, float]:
        """Get current system statistics."""
        return {
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get detailed network statistics."""
        current_time = time.time()
        network_counters = psutil.net_io_counters()
        
        # Calculate bandwidth usage
        if self.last_network_check and self.last_network_bytes:
            time_delta = current_time - self.last_network_check
            bytes_sent_delta = network_counters.bytes_sent - self.last_network_bytes['sent']
            bytes_recv_delta = network_counters.bytes_recv - self.last_network_bytes['recv']
            
            bandwidth_usage = (bytes_sent_delta + bytes_recv_delta) / (time_delta * 1024 * 1024)  # MB/s
        else:
            bandwidth_usage = 0
        
        # Update last check
        self.last_network_check = current_time
        self.last_network_bytes = {
            'sent': network_counters.bytes_sent,
            'recv': network_counters.bytes_recv
        }
        
        # Get connections
        connections = psutil.net_connections(kind='inet')
        active_connections = len([conn for conn in connections if conn.status == 'ESTABLISHED'])
        
        # Calculate packet loss (simplified)
        packet_loss = (
            network_counters.packets_sent > 0 and
            (network_counters.packets_sent - network_counters.packets_recv) / network_counters.packets_sent * 100
        ) if network_counters.packets_sent > 0 else 0
        
        stats = {
            'bandwidth_usage': bandwidth_usage,
            'active_connections': active_connections,
            'packet_loss': packet_loss,
            'bytes_sent': network_counters.bytes_sent,
            'bytes_recv': network_counters.bytes_recv,
            'packets_sent': network_counters.packets_sent,
            'packets_recv': network_counters.packets_recv,
            'connections_per_second': self._calculate_connections_per_second(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Update history
        self.network_stats_history.append({
            'timestamp': datetime.now(),
            'stats': stats
        })
        
        # Keep only last hour of history
        self.network_stats_history = [
            entry for entry in self.network_stats_history
            if (datetime.now() - entry['timestamp']).total_seconds() < 3600
        ]
        
        return stats
    
    def _calculate_connections_per_second(self) -> float:
        """Calculate the rate of new connections per second."""
        if len(self.network_stats_history) < 2:
            return 0
        
        latest = self.network_stats_history[-1]
        previous = self.network_stats_history[-2]
        
        time_delta = (latest['timestamp'] - previous['timestamp']).total_seconds()
        if time_delta == 0:
            return 0
            
        conn_delta = (
            latest['stats']['active_connections'] - 
            previous['stats']['active_connections']
        )
        
        return max(0, conn_delta / time_delta)
    
    def get_process_stats(self) -> Dict[str, Any]:
        """Get statistics about running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                if pinfo['cpu_percent'] > 0 or pinfo['memory_percent'] > 0:
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu_percent': pinfo['cpu_percent'],
                        'memory_percent': pinfo['memory_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return {
            'total_processes': len(processes),
            'high_cpu_processes': len([p for p in processes if p['cpu_percent'] > 50]),
            'high_memory_processes': len([p for p in processes if p['memory_percent'] > 50]),
            'processes': sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]  # Top 10
        }
    
    def get_file_operations(self) -> Dict[str, Any]:
        """Get statistics about file operations."""
        disk_io = psutil.disk_io_counters()
        return {
            'read_bytes': disk_io.read_bytes,
            'write_bytes': disk_io.write_bytes,
            'read_count': disk_io.read_count,
            'write_count': disk_io.write_count,
            'operations_per_second': (disk_io.read_count + disk_io.write_count) / psutil.boot_time()
        } 