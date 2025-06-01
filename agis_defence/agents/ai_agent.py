import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any
from ..models.threat_detection import ThreatDetector
from ..models.system_monitor import SystemMonitor

class AISecurityAgent:
    def __init__(self):
        self.threat_detector = ThreatDetector()
        self.system_monitor = SystemMonitor()
        self.attack_history = {}
        self.threat_patterns = {}
        self.last_analysis = None
        
    def analyze_system_state(self) -> Dict[str, Any]:
        """Analyze current system state and provide comprehensive analysis."""
        current_time = datetime.now()
        system_stats = self.system_monitor.get_stats()
        network_stats = self.system_monitor.get_network_stats()
        active_threats = self.threat_detector.get_active_threats()
        
        # Calculate threat level
        threat_level = self._calculate_threat_level(system_stats, network_stats, active_threats)
        
        # Generate predictions
        predictions = self._generate_threat_predictions()
        
        # Identify vulnerabilities
        vulnerabilities = self._identify_vulnerabilities(system_stats)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            threat_level, 
            vulnerabilities,
            active_threats
        )
        
        # Calculate health score
        health_score = self._calculate_health_score(
            system_stats,
            network_stats,
            len(active_threats),
            len(vulnerabilities)
        )
        
        self.last_analysis = {
            'timestamp': current_time.isoformat(),
            'threat_level': threat_level,
            'confidence': self._calculate_confidence(),
            'predictions': predictions,
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations,
            'healthScore': health_score,
            'healthStatus': self._get_health_status(health_score)
        }
        
        return self.last_analysis
    
    def analyze_threats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze specific threats and provide detailed analysis."""
        threats = data.get('threats', [])
        system_status = data.get('systemStatus', {})
        
        analyzed_threats = []
        for threat in threats:
            # Update attack history
            threat_key = f"{threat['type']}-{threat['source']}"
            history = self.attack_history.get(threat_key, {
                'count': 0,
                'first_seen': datetime.now(),
                'last_seen': None,
                'actions_taken': []
            })
            
            history['count'] += 1
            history['last_seen'] = datetime.now()
            self.attack_history[threat_key] = history
            
            # Analyze threat pattern
            pattern = self._analyze_threat_pattern(threat, history)
            
            # Determine recommended action
            recommended_action = 'heal' if history['count'] == 1 else 'block'
            
            analyzed_threats.append({
                **threat,
                'pattern': pattern,
                'history': history,
                'recommended_action': recommended_action,
                'confidence': self._calculate_threat_confidence(threat, pattern)
            })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'threats': analyzed_threats,
            'system_impact': self._assess_system_impact(threats, system_status),
            'recommendations': self._generate_threat_recommendations(analyzed_threats)
        }
    
    def analyze_and_respond(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat and determine appropriate response."""
        analysis = self.analyze_threats(data)
        responses = []
        
        for threat in analysis['threats']:
            response = {
                'threat_id': threat.get('id'),
                'action': threat['recommended_action'],
                'confidence': threat['confidence'],
                'timestamp': datetime.now().isoformat()
            }
            responses.append(response)
            
        return {
            'analysis': analysis,
            'responses': responses
        }
    
    def _calculate_threat_level(self, system_stats: Dict, network_stats: Dict, active_threats: List) -> str:
        """Calculate overall threat level based on various metrics."""
        threat_score = 0
        
        # System metrics impact
        if system_stats['cpu'] > 90: threat_score += 3
        elif system_stats['cpu'] > 75: threat_score += 2
        elif system_stats['cpu'] > 60: threat_score += 1
        
        if system_stats['memory'] > 90: threat_score += 3
        elif system_stats['memory'] > 75: threat_score += 2
        elif system_stats['memory'] > 60: threat_score += 1
        
        # Network metrics impact
        if network_stats['bandwidth_usage'] > 90: threat_score += 3
        if network_stats['packet_loss'] > 5: threat_score += 2
        if network_stats['active_connections'] > 1000: threat_score += 2
        
        # Active threats impact
        threat_score += len(active_threats) * 2
        
        # Determine threat level
        if threat_score >= 10:
            return 'critical'
        elif threat_score >= 7:
            return 'high'
        elif threat_score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def _generate_threat_predictions(self) -> List[Dict[str, Any]]:
        """Generate predictions about potential future threats."""
        predictions = []
        
        # Analyze historical patterns
        for threat_key, history in self.attack_history.items():
            if history['last_seen']:
                time_since_last = datetime.now() - history['last_seen']
                attack_frequency = history['count'] / max(1, (datetime.now() - history['first_seen']).days)
                
                if attack_frequency > 0.5 and time_since_last.days < 7:
                    predictions.append({
                        'type': threat_key.split('-')[0],
                        'probability': min(0.9, attack_frequency / 10 + 0.3),
                        'timeframe': '24 hours',
                        'basis': 'Historical pattern'
                    })
        
        return predictions
    
    def _identify_vulnerabilities(self, system_stats: Dict) -> List[Dict[str, Any]]:
        """Identify system vulnerabilities."""
        vulnerabilities = []
        
        if system_stats['cpu'] > 80:
            vulnerabilities.append({
                'type': 'Resource Exhaustion',
                'description': 'High CPU usage may indicate resource exhaustion attack',
                'severity': 'high'
            })
        
        if system_stats['memory'] > 80:
            vulnerabilities.append({
                'type': 'Memory Usage',
                'description': 'High memory usage increases vulnerability to DoS',
                'severity': 'medium'
            })
        
        return vulnerabilities
    
    def _generate_recommendations(self, threat_level: str, vulnerabilities: List, active_threats: List) -> List[Dict[str, Any]]:
        """Generate security recommendations."""
        recommendations = []
        
        if threat_level in ['high', 'critical']:
            recommendations.append({
                'title': 'Immediate Action Required',
                'description': 'High threat level detected. Consider enabling aggressive blocking.',
                'priority': 'high'
            })
        
        for vuln in vulnerabilities:
            recommendations.append({
                'title': f'Address {vuln["type"]}',
                'description': vuln['description'],
                'priority': vuln['severity']
            })
        
        return recommendations
    
    def _calculate_health_score(self, system_stats: Dict, network_stats: Dict, threat_count: int, vuln_count: int) -> int:
        """Calculate overall system health score."""
        base_score = 100
        
        # Deduct for system issues
        base_score -= max(0, system_stats['cpu'] - 60) * 0.5
        base_score -= max(0, system_stats['memory'] - 60) * 0.5
        
        # Deduct for network issues
        base_score -= network_stats['packet_loss'] * 2
        base_score -= max(0, (network_stats['active_connections'] - 500) / 100)
        
        # Deduct for threats and vulnerabilities
        base_score -= threat_count * 5
        base_score -= vuln_count * 3
        
        return max(0, min(100, int(base_score)))
    
    def _get_health_status(self, health_score: int) -> str:
        """Get descriptive health status."""
        if health_score >= 80:
            return 'Healthy'
        elif health_score >= 60:
            return 'Moderate'
        elif health_score >= 40:
            return 'At Risk'
        else:
            return 'Critical'
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence level in current analysis."""
        return 0.85  # Placeholder - implement actual confidence calculation
    
    def _analyze_threat_pattern(self, threat: Dict, history: Dict) -> Dict[str, Any]:
        """Analyze threat pattern based on historical data."""
        return {
            'frequency': history['count'] / max(1, (datetime.now() - history['first_seen']).days),
            'recurring': history['count'] > 1,
            'last_seen': history['last_seen'].isoformat() if history['last_seen'] else None
        }
    
    def _calculate_threat_confidence(self, threat: Dict, pattern: Dict) -> float:
        """Calculate confidence in threat analysis."""
        base_confidence = 0.7
        
        if pattern['recurring']:
            base_confidence += 0.2
        
        if pattern['frequency'] > 1:
            base_confidence += 0.1
            
        return min(0.99, base_confidence)
    
    def _assess_system_impact(self, threats: List, system_status: Dict) -> Dict[str, Any]:
        """Assess the impact of threats on the system."""
        return {
            'severity': 'high' if len(threats) > 5 else 'medium' if len(threats) > 2 else 'low',
            'affected_resources': self._identify_affected_resources(threats, system_status),
            'potential_damage': self._estimate_potential_damage(threats)
        } 