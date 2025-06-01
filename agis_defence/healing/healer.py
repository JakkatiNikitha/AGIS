import os
import subprocess
from typing import Dict, Any, List
from datetime import datetime
import psutil
import logging
from ..models.system_monitor import SystemMonitor

class SystemHealer:
    def __init__(self):
        self.system_monitor = SystemMonitor()
        self.healing_history = []
        self.active_repairs = []
        self.logger = logging.getLogger('system_healer')
        
    def get_status(self) -> Dict[str, Any]:
        """Get current healing system status."""
        return {
            'active_repairs': len(self.active_repairs),
            'last_updated': datetime.now().isoformat(),
            'system_health': self._calculate_system_health(),
            'system_state': self._get_system_state(),
            'recent_actions': self.healing_history[-10:] if self.healing_history else []
        }
    
    def heal_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to heal a detected threat."""
        threat_type = threat_data.get('type')
        source = threat_data.get('source')
        
        healing_action = {
            'threat_id': threat_data.get('id'),
            'type': threat_type,
            'source': source,
            'timestamp': datetime.now(),
            'status': 'initiated'
        }
        
        try:
            if threat_type in self.HEALING_METHODS:
                result = self.HEALING_METHODS[threat_type](self, threat_data)
                healing_action.update({
                    'status': 'success',
                    'action_taken': result['action'],
                    'details': result['details']
                })
            else:
                healing_action.update({
                    'status': 'failed',
                    'error': f'No healing method available for threat type: {threat_type}'
                })
        except Exception as e:
            healing_action.update({
                'status': 'failed',
                'error': str(e)
            })
        
        self.healing_history.append(healing_action)
        return healing_action
    
    def _heal_ddos(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Heal DDoS attack."""
        source = threat_data.get('source')
        
        # Implement rate limiting
        subprocess.run(['iptables', '-A', 'INPUT', '-s', source, 
                       '-m', 'limit', '--limit', '5/minute', '--limit-burst', '10', 
                       '-j', 'ACCEPT'])
        subprocess.run(['iptables', '-A', 'INPUT', '-s', source, '-j', 'DROP'])
        
        return {
            'action': 'rate_limit',
            'details': f'Applied rate limiting to source {source}'
        }
    
    def _heal_brute_force(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Heal brute force attack."""
        source = threat_data.get('source')
        
        # Implement account protection
        subprocess.run(['faillock', '--user', threat_data.get('target_user', ''), '--reset'])
        
        return {
            'action': 'account_protection',
            'details': f'Reset faillock for affected user and added source {source} to watch list'
        }
    
    def _heal_ransomware(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Heal ransomware infection."""
        # Stop suspicious processes
        suspicious_processes = self._find_suspicious_processes()
        for proc in suspicious_processes:
            try:
                psutil.Process(proc['pid']).terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return {
            'action': 'process_termination',
            'details': f'Terminated {len(suspicious_processes)} suspicious processes'
        }
    
    def _heal_malware(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Heal general malware infection."""
        # Implement malware cleanup
        affected_files = threat_data.get('affected_files', [])
        quarantined = []
        
        for file_path in affected_files:
            try:
                quarantine_path = self._quarantine_file(file_path)
                quarantined.append(quarantine_path)
            except Exception as e:
                self.logger.error(f"Failed to quarantine {file_path}: {e}")
        
        return {
            'action': 'quarantine',
            'details': f'Quarantined {len(quarantined)} affected files'
        }
    
    def _heal_system_resources(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Heal system resource issues."""
        # Find and terminate resource-heavy processes
        high_cpu_processes = [
            p for p in psutil.process_iter(['pid', 'name', 'cpu_percent'])
            if p.info['cpu_percent'] > 80
        ]
        
        terminated = []
        for proc in high_cpu_processes:
            try:
                psutil.Process(proc.info['pid']).terminate()
                terminated.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return {
            'action': 'resource_optimization',
            'details': f'Terminated {len(terminated)} resource-heavy processes'
        }
    
    def _quarantine_file(self, file_path: str) -> str:
        """Move file to quarantine directory."""
        quarantine_dir = '/var/quarantine'
        os.makedirs(quarantine_dir, exist_ok=True)
        
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(quarantine_dir, 
                                     f"{filename}.{datetime.now().timestamp()}.quarantine")
        
        os.rename(file_path, quarantine_path)
        return quarantine_path
    
    def _find_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Identify suspicious processes based on behavior."""
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                if (proc.info['cpu_percent'] > 80 or 
                    proc.info['memory_percent'] > 80 or
                    self._is_process_suspicious(proc)):
                    suspicious.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return suspicious
    
    def _is_process_suspicious(self, proc: psutil.Process) -> bool:
        """Check if a process exhibits suspicious behavior."""
        try:
            # Check for suspicious characteristics
            return any([
                proc.name() in self.SUSPICIOUS_PROCESS_NAMES,
                proc.num_threads() > 100,
                proc.num_fds() > 1000,
                self._has_suspicious_connections(proc)
            ])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _has_suspicious_connections(self, proc: psutil.Process) -> bool:
        """Check if process has suspicious network connections."""
        try:
            connections = proc.connections()
            return any([
                len(connections) > 50,  # Too many connections
                any(conn.status == 'LISTEN' for conn in connections)  # Listening ports
            ])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _calculate_system_health(self) -> float:
        """Calculate overall system health score."""
        stats = self.system_monitor.get_stats()
        
        # Base health score
        health = 100
        
        # Deduct for high resource usage
        health -= max(0, stats['cpu'] - 70) * 0.5
        health -= max(0, stats['memory'] - 70) * 0.5
        health -= max(0, stats['disk'] - 80) * 0.5
        
        # Deduct for active threats
        health -= len(self.active_repairs) * 5
        
        return max(0, min(100, health))
    
    def _get_system_state(self) -> str:
        """Get current system state description."""
        health = self._calculate_system_health()
        
        if health >= 90:
            return 'Healthy'
        elif health >= 70:
            return 'Stable'
        elif health >= 50:
            return 'Degraded'
        else:
            return 'Critical'
    
    # Mapping of threat types to healing methods
    HEALING_METHODS = {
        'ddos': _heal_ddos,
        'brute_force': _heal_brute_force,
        'ransomware': _heal_ransomware,
        'malware': _heal_malware,
        'resource_exhaustion': _heal_system_resources
    }
    
    # List of known suspicious process names
    SUSPICIOUS_PROCESS_NAMES = {
        'crypto_miner',
        'miner',
        'xmrig',
        'backdoor',
        'trojan',
        'botnet'
    } 