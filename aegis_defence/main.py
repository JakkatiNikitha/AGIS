"""
Main entry point for the AGIS defence system.
"""

from flask import Flask, send_from_directory
from agis_defence.agents import TrafficAgent
from agis_defence.utils.log_manager import LogManager
import os

app = Flask(__name__)
traffic_agent = TrafficAgent()
log_manager = LogManager()

# Serve React App
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# API Routes
@app.route('/api/system/status')
def system_status():
    return {
        'status': 'running',
        'traffic_stats': traffic_agent.get_traffic_stats()
    }

def main():
    """Main entry point for the application."""
    try:
        # Initialize logging
        log_manager.add_log(
            event_type="SYSTEM_START",
            severity="INFO",
            description="Starting AGIS defence system",
            source="AGIS_CORE",
            action_taken="System initialization",
            status="IN_PROGRESS"
        )
        
        # Start traffic monitoring
        traffic_agent.start_monitoring()
        
        # Log successful startup
        log_manager.add_log(
            event_type="SYSTEM_START",
            severity="INFO",
            description="AGIS defence system started successfully",
            source="AGIS_CORE",
            action_taken="System startup",
            status="COMPLETED"
        )
        
        # Start the Flask server
        app.run(host='0.0.0.0', port=5000)
        
    except Exception as e:
        log_manager.add_log(
            event_type="SYSTEM_ERROR",
            severity="ERROR",
            description=f"Failed to start AGIS: {str(e)}",
            source="AGIS_CORE",
            action_taken="System startup",
            status="FAILED"
        )
        raise

if __name__ == '__main__':
    main() 