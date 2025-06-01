from flask import Flask, send_from_directory, jsonify
import logging
import os
from agis_defence.api.routes import api
from agis_defence.models.system_monitor import SystemMonitor
from agis_defence.models.threat_detection import ThreatDetector
from agis_defence.agents.ai_agent import AISecurityAgent
from agis_defence.firewall.manager import FirewallManager
from agis_defence.healing.healer import SystemHealer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('agis_defence')

# Initialize Flask app with absolute path to static folder
dashboard_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'dashboard'))
app = Flask(__name__, static_folder=dashboard_dir, static_url_path='')

# Enable CORS for development
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Register API blueprint
app.register_blueprint(api, url_prefix='/api')

# Initialize components
system_monitor = SystemMonitor()
threat_detector = ThreatDetector()
ai_agent = AISecurityAgent()
firewall = FirewallManager()
healer = SystemHealer()

# Error handler for 404
@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 error: {error}")
    return jsonify({"error": "Resource not found"}), 404

# Error handler for 500
@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# Serve dashboard static files
@app.route('/')
def serve_dashboard():
    try:
        logger.info(f"Serving dashboard from {dashboard_dir}")
        return send_from_directory(dashboard_dir, 'index.html')
    except Exception as e:
        logger.error(f"Error serving dashboard: {e}")
        return jsonify({"error": "Failed to serve dashboard"}), 500

@app.route('/<path:path>')
def serve_static(path):
    try:
        logger.info(f"Serving static file: {path}")
        return send_from_directory(dashboard_dir, path)
    except Exception as e:
        logger.error(f"Error serving static file {path}: {e}")
        return jsonify({"error": f"Failed to serve file: {path}"}), 500

def start_monitoring():
    """Start the security monitoring system."""
    logger.info("Starting AGIS Defence System...")
    
    try:
        # Initialize firewall
        firewall._initialize_firewall()
        logger.info("Firewall initialized")
        
        # Start system monitoring
        initial_stats = system_monitor.get_stats()
        logger.info(f"Initial system stats: {initial_stats}")
        
        # Start threat detection
        logger.info("Threat detection system active")
        
        # Initialize AI agent
        ai_analysis = ai_agent.analyze_system_state()
        logger.info(f"Initial AI analysis: {ai_analysis}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return False

if __name__ == '__main__':
    if start_monitoring():
        # Run the Flask app
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False  # Disable reloader to prevent duplicate monitoring
        )
    else:
        logger.error("Failed to start AGIS Defence System") 