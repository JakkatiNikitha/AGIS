from typing import Dict, List, Any
from datetime import datetime, timedelta
import numpy as np
from ..config import ATTACK_TYPES

class ThreatDetector:
    def __init__(self):
        self.active_threats = []
        self.threat_history = {}
        self.detection_stats = {
            attack_type['id']: {
                'detected': 0,
                'blocked': 0,
                'healed': 0,
                'lastSeen': None
            }
            for category in ATTACK_TYPES.values()
            for attack_type in category['types']
        }
        
    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Get list of currently active threats."""
        # Clean up old threats
        current_time = datetime.now()
        self.active_threats = [
            threat for threat in self.active_threats
            if (current_time - threat['detected_at']).total_seconds() < 3600  # 1 hour
        ]
        return self.active_threats
    
    def get_detection_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all types of attacks."""
        return self.detection_stats
    
    def get_threat_trends(self) -> Dict[str, Any]:
        """Get threat detection trends."""
        current_time = datetime.now()
        day_ago = current_time - timedelta(days=1)
        
        # Calculate daily statistics
        daily_stats = {
            'total': 0,
            'blocked': 0,
            'critical': 0
        }
        
        # Calculate threat distribution
        distribution = {}
        
        for threat_id, history in self.threat_history.items():
            for event in history['events']:
                if event['timestamp'] > day_ago:
                    daily_stats['total'] += 1
                    if event.get('action') == 'block':
                        daily_stats['blocked'] += 1
                    if event.get('severity') == 'critical':
                        daily_stats['critical'] += 1
                    
                    threat_type = history['type']
                    distribution[threat_type] = distribution.get(threat_type, 0) + 1
        
        return {
            'daily': daily_stats,
            'distribution': distribution
        }
    
    def detect_network_threats(self, network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect network-based threats."""
        threats = []
        
        # Check for DDoS
        if self._detect_ddos(network_data):
            threats.append(self._create_threat('ddos', 'network', network_data['source']))
        
        # Check for port scanning
        if self._detect_port_scan(network_data):
            threats.append(self._create_threat('port_scan', 'network', network_data['source']))
        
        # Check for SYN flood
        if self._detect_syn_flood(network_data):
            threats.append(self._create_threat('syn_flood', 'network', network_data['source']))
        
        return threats
    
    def detect_intrusion_attempts(self, auth_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect intrusion attempts."""
        threats = []
        
        # Check for brute force
        if self._detect_brute_force(auth_data):
            threats.append(self._create_threat('brute_force', 'intrusion', auth_data['source']))
        
        # Check for SSH attacks
        if self._detect_ssh_attack(auth_data):
            threats.append(self._create_threat('ssh_attack', 'intrusion', auth_data['source']))
        
        return threats
    
    def detect_malware(self, system_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect malware activity."""
        threats = []
        
        # Check for ransomware
        if self._detect_ransomware(system_data):
            threats.append(self._create_threat('ransomware', 'malware', 'system'))
        
        # Check for cryptomining
        if self._detect_cryptomining(system_data):
            threats.append(self._create_threat('cryptominer', 'malware', 'system'))
        
        return threats
    
    def _create_threat(self, threat_type: str, category: str, source: str) -> Dict[str, Any]:
        """Create a new threat entry."""
        threat = {
            'id': f"{threat_type}-{datetime.now().timestamp()}",
            'type': threat_type,
            'category': category,
            'source': source,
            'detected_at': datetime.now(),
            'severity': self._determine_severity(threat_type),
            'confidence': self._calculate_detection_confidence(threat_type)
        }
        
        # Update detection stats
        self.detection_stats[threat_type]['detected'] += 1
        self.detection_stats[threat_type]['lastSeen'] = datetime.now().isoformat()
        
        # Update threat history
        if threat_type not in self.threat_history:
            self.threat_history[threat_type] = {
                'type': threat_type,
                'first_seen': datetime.now(),
                'events': []
            }
        
        self.threat_history[threat_type]['events'].append({
            'timestamp': datetime.now(),
            'source': source,
            'severity': threat['severity']
        })
        
        # Add to active threats
        self.active_threats.append(threat)
        
        return threat
    
    def _determine_severity(self, threat_type: str) -> str:
        """Determine threat severity based on type and context."""
        high_severity_threats = {'ransomware', 'ddos', 'apt'}
        medium_severity_threats = {'port_scan', 'brute_force', 'ssh_attack'}
        
        if threat_type in high_severity_threats:
            return 'high'
        elif threat_type in medium_severity_threats:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_detection_confidence(self, threat_type: str) -> float:
        """Calculate confidence level in threat detection."""
        # Placeholder - implement actual confidence calculation
        base_confidence = {
            'ddos': 0.9,
            'ransomware': 0.95,
            'port_scan': 0.85,
            'brute_force': 0.8,
            'ssh_attack': 0.85
        }
        return base_confidence.get(threat_type, 0.75)
    
    # Threat detection methods
    def _detect_ddos(self, data: Dict[str, Any]) -> bool:
        """Detect DDoS attacks."""
        return (
            data.get('connections_per_second', 0) > 1000 or
            data.get('bandwidth_usage', 0) > 90
        )
    
    def _detect_port_scan(self, data: Dict[str, Any]) -> bool:
        """Detect port scanning activity."""
        return data.get('unique_ports_accessed', 0) > 20
    
    def _detect_syn_flood(self, data: Dict[str, Any]) -> bool:
        """Detect SYN flood attacks."""
        return data.get('syn_packets_ratio', 0) > 0.8
    
    def _detect_brute_force(self, data: Dict[str, Any]) -> bool:
        """Detect brute force attempts."""
        return data.get('failed_logins', 0) > 5
    
    def _detect_ssh_attack(self, data: Dict[str, Any]) -> bool:
        """Detect SSH-based attacks."""
        return data.get('ssh_failed_attempts', 0) > 3
    
    def _detect_ransomware(self, data: Dict[str, Any]) -> bool:
        """Detect ransomware activity."""
        return (
            data.get('file_entropy', 0) > 0.9 and
            data.get('file_operations_per_second', 0) > 100
        )
    
    def _detect_cryptomining(self, data: Dict[str, Any]) -> bool:
        """Detect cryptomining activity."""
        return data.get('cpu_usage', 0) > 90 