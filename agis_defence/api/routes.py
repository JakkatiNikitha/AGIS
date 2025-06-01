from flask import Blueprint, jsonify, request
from agis_defence.models.threat_detection import ThreatDetector
from agis_defence.models.system_monitor import SystemMonitor
from agis_defence.agents.ai_agent import AISecurityAgent
from agis_defence.firewall.manager import FirewallManager
from agis_defence.healing.healer import SystemHealer
from datetime import datetime

api = Blueprint('api', __name__)
threat_detector = ThreatDetector()
system_monitor = SystemMonitor()
ai_agent = AISecurityAgent()
firewall = FirewallManager()
healer = SystemHealer()

@api.route('/system/status', methods=['GET'])
def get_system_status():
    """Get complete system status including all metrics and threat data."""
    try:
        system_stats = system_monitor.get_stats()
        network_stats = system_monitor.get_network_stats()
        firewall_stats = firewall.get_status()
        attack_stats = threat_detector.get_detection_stats()
        ai_analysis = ai_agent.analyze_system_state()
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'cpu_usage': system_stats['cpu'],
            'memory_usage': system_stats['memory'],
            'disk_usage': system_stats['disk'],
            'network': network_stats,
            'firewall': firewall_stats,
            'attackStats': attack_stats,
            'anomalies': threat_detector.get_active_threats(),
            'aiAnalysis': ai_analysis,
            'trends': threat_detector.get_threat_trends(),
            'healing': healer.get_status()
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/threat/analyze', methods=['POST'])
def analyze_threat():
    """Analyze system state and detect threats."""
    try:
        data = request.get_json()
        analysis = ai_agent.analyze_threats(data)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/threat/handle', methods=['POST'])
def handle_threat():
    """Handle detected threats with specified action."""
    try:
        data = request.get_json()
        action = data.get('action', 'analyze')
        
        if action == 'block':
            result = firewall.block_threat(data)
        elif action == 'heal':
            result = healer.heal_threat(data)
        else:
            result = ai_agent.analyze_and_respond(data)
            
        return jsonify({
            'status': 'success',
            'action_taken': action,
            'result': result
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/firewall/block/<ip>', methods=['POST'])
def block_ip(ip):
    """Block specific IP address."""
    try:
        result = firewall.block_ip(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} blocked', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/firewall/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock specific IP address."""
    try:
        result = firewall.unblock_ip(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/network/stats', methods=['GET'])
def get_network_stats():
    """Get detailed network statistics."""
    try:
        stats = system_monitor.get_network_stats()
        return jsonify({'status': 'success', 'stats': stats})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/network/anomalies', methods=['GET'])
def get_network_anomalies():
    """Get detected network anomalies."""
    try:
        anomalies = threat_detector.get_network_anomalies()
        return jsonify({'status': 'success', 'anomalies': anomalies})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/healing/status', methods=['GET'])
def get_healing_status():
    """Get system healing status."""
    try:
        status = healer.get_status()
        return jsonify({'status': 'success', 'healing_status': status})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500 