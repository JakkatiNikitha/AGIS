# AGIS

GIS is an advanced security monitoring and threat detection system powered by artificial intelligence. It provides real-time system monitoring, threat detection, and automated response capabilities through an interactive web dashboard.

## Features

- **Real-time System Monitoring**
  - CPU, Memory, and Disk usage tracking
  - Network traffic analysis
  - Active connection monitoring
  - Bandwidth usage tracking

- **AI-Powered Threat Detection**
  - Real-time anomaly detection
  - Pattern-based threat recognition
  - Behavioral analysis
  - Predictive threat assessment

- **Automated Security Response**
  - Intelligent firewall management
  - Automated threat mitigation
  - System self-healing capabilities
  - Incident response automation

- **Interactive Dashboard**
  - Real-time security metrics
  - Threat visualization
  - System health monitoring
  - AI analysis insights

## Quick Start Guide

### 1. System Requirements
- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Administrative privileges (for full functionality)
- Windows 10/11 or Linux (Ubuntu 20.04+)

### 2. Installation Steps

1. Create a Python virtual environment:
```bash
# Create a new virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
.\venv\Scripts\activate
# On Unix or MacOS:
source venv/bin/activate
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Build the React dashboard:
```bash
cd agis_defence/dashboard
npm install
npm run build
cd ../..
```

4. Start the AGIS system:
```bash
python run.py
```

5. Access the dashboard:
- Open your web browser
- Navigate to `http://localhost:5000`
- The dashboard will automatically connect to the AGIS backend

### Troubleshooting

If you encounter a "Node.removeChild" error in the dashboard:
1. Clear your browser cache
2. Reload the page
3. Try using a different web browser
4. Ensure the React dashboard is properly built

## Project Structure
```
agis_defence/         # Main application code
├── api/             # API endpoints
├── agents/          # Security monitoring agents
├── collectors/      # Data collection modules
├── dashboard/       # Web interface files
├── firewall/        # Firewall management
├── healing/         # System self-healing
├── models/          # Core system models
└── utils/          # Utility functions
data/               # Data directory
requirements.txt    # Python dependencies
run.py             # Main runner script
```

## Security Considerations

- The system requires administrative privileges for full functionality
- API endpoints should be properly secured in production
- Firewall rules should be carefully reviewed
- System should be regularly updated

## Support

For support and questions:
- Open an issue on GitHub
- Check the documentation
- Contact the development team

---
Built with ❤️ by [Your Organization]

## Project Structure

### Key Files Explained

#### Core System Files
- `agis_defence/main.py`: The main entry point that initializes and runs the AGIS system
- `agis_defence/config.py`: System-wide configuration settings and parameters
- `requirements.txt`: Lists all Python package dependencies with versions
- `setup.py`: Package installation and distribution configuration

#### Web Dashboard
- `dashboard/index.html`: The main HTML file for the web interface
- `dashboard/js/app.js`: React-based frontend application with all UI components

#### System Components
- `agents/ai_agent.py`: Implements AI-based decision making and threat analysis
- `firewall/manager.py`: Manages system firewall rules and configurations
- `models/system_monitor.py`: Implements system resource monitoring
- `models/threat_detection.py`: Contains threat detection algorithms

#### API and Routes
- `api/routes.py`: Defines all REST API endpoints
- `api/handlers.py`: Implements the logic for API endpoints

#### Utilities and Tools
- `run.py`: Convenience script for starting the system
- `log_to_csv.py`: Utility for analyzing system logs
- `log_statistics.json`: Contains analyzed log statistics

#### Documentation
- `README.md`: Main project documentation (this file)
- `DOCS.md`: Additional technical documentation and guides

#### Data and Storage
- `models/`: Contains trained ML models and parameters
- `backups/`: Stores system backups and recovery points
- `data/`: Application data storage directory

### File Organization

The project follows a modular structure where:
- Core functionality is in the `agis_defence` package
- Web interface is in the `dashboard` directory
- ML models and data are separated in `models` and `data`
- Documentation is maintained in markdown files
- Utilities and scripts are in the root directory

This organization allows for:
- Easy navigation of the codebase
- Clear separation of concerns
- Modular development and testing
- Simple deployment and maintenance 

================================================================================
main.py Analysis
This is the core entry point of the AGIS system. Here's a detailed breakdown:
Imports and Setup (Lines 1-10)
Uses Flask for the web server
Sets up logging
Imports core system components (monitor, detector, AI agent, firewall, healer)
Flask App Configuration (Lines 12-20)
Configures logging with detailed format
Initializes Flask app with proper static file serving
Sets up dashboard directory path
CORS Configuration (Lines 22-28)
Enables Cross-Origin Resource Sharing
Necessary for development and API access
Allows specified HTTP methods and headers
Component Initialization (Lines 30-36)
Creates instances of core system components:
SystemMonitor: Tracks system resources
ThreatDetector: Identifies security threats
AISecurityAgent: Makes security decisions
FirewallManager: Manages firewall rules
SystemHealer: Handles system recovery
Error Handlers (Lines 38-48)
Handles 404 Not Found errors
Handles 500 Internal Server errors
Returns JSON responses for API consistency
Static File Serving (Lines 50-67)
Serves the main dashboard (index.html)
Serves other static files (JS, CSS, etc.)
Includes error handling and logging
System Startup (Lines 69-89)
start_monitoring() function initializes the system
Starts in sequence:
Firewall initialization
System monitoring
Threat detection
AI agent analysis
Main Execution (Lines 91-106)
Starts the monitoring system
Runs Flask server on port 5000
Disables reloader to prevent duplicate monitoring
Would you like me to continue with the next file? I can explain:
config.py - System configuration
models/system_monitor.py - System monitoring implementation
firewall/manager.py - Firewall management
dashboard/js/app.js - Frontend React application
================================================================================
Dashboard Overview (app.js)
Main Dashboard Setup
The dashboard connects to the security system through various communication channels
It automatically refreshes data every few seconds to show real-time information
Has built-in error handling to show user-friendly messages if something goes wrong
Top Header Section
Shows the AGIS Defence Dashboard title
Displays a subtitle indicating it's an AI-powered security system
Uses a professional blue color scheme for visibility
Network Status Display
Shows current network health and activity
Displays a threat level indicator (Low, Medium, or High)
Shows important network statistics like:
How many devices are connected
How much data is being transferred
Current network speed
Changes colors based on threat levels (green for safe, yellow for warnings, red for danger)
AI Security Monitor
Continuously watches system activity
Shows what the AI is currently doing
Displays recent security actions taken
Keeps track of past threats and how they were handled
Makes predictions about possible future threats
Shows confidence levels for each security decision
Attack Detection Panel
Groups different types of security threats into categories:
Network attacks (like DDoS)
Hacking attempts
Malware threats
Suspicious activities
Shows how many of each type have been detected
Displays when the last attack of each type occurred
Indicates which threats are currently active
System Health Display
Shows computer resource usage (CPU, memory, disk)
Displays firewall status and active rules
Indicates if any system components need attention
Changes colors to indicate health status
Security Response Section
Shows what actions the system is taking against threats
Allows manual blocking of suspicious IP addresses
Displays automated actions taken by the AI
Shows success or failure of security measures
Historical Data View
Keeps track of all security events
Shows patterns in attack attempts
Displays statistics about system performance
Helps identify recurring threats
Alert System
Shows important notifications about security events
Uses different colors for different urgency levels
Displays detailed information about each alert
Keeps a history of past alerts
Interactive Features
Allows users to:
View detailed information about threats
Take manual action when needed
See AI recommendations
Monitor system performance
All controls are clearly labeled and easy to use
Error Handling
Shows friendly messages if something goes wrong
Provides suggestions for fixing problems
Maintains dashboard functionality even if some parts fail
Automatically tries to reconnect if connection is lost
Performance Optimization
Only updates information when needed
Smoothly handles large amounts of data
Stays responsive even under heavy system load
Efficiently manages system resources
This dashboard is designed to be:
Easy to understand for non-technical users
Informative for security professionals
Responsive and real-time
Reliable during security incidents
Helpful in making security decisions
================================================================================

## Implementation Details

### Backend Implementation

#### System Monitor
- Uses `psutil` library for system metrics collection
- Monitors in real-time:
  - CPU usage (per core and total)
  - Memory usage (RAM and swap)
  - Disk I/O and storage
  - Network interfaces
- Sampling rate: Every 1 second
- Data retention: 24 hours rolling window

#### Threat Detection
- Implements multiple detection methods:
  - Signature-based detection using known threat patterns
  - Anomaly detection using statistical analysis
  - Behavioral analysis using ML models
  - Network traffic analysis using deep packet inspection
- Uses scikit-learn for ML-based detection
- Maintains threat database with severity levels
- Updates threat signatures every 6 hours

#### AI Security Agent
- Built on PyTorch framework
- Uses a hybrid approach:
  - Rule-based decision making for known threats
  - Neural networks for pattern recognition
  - Reinforcement learning for adaptive response
- Model architecture:
  - Input layer: 256 neurons (system state)
  - Hidden layers: 512, 256, 128 neurons
  - Output layer: 64 neurons (action space)
- Training:
  - Pre-trained on security incident dataset
  - Continuous learning from system interactions
  - Weekly model updates

#### Firewall Management
- Windows: Uses Windows Firewall API
- Linux: Integrates with iptables/nftables
- Features:
  - Dynamic rule generation
  - Port scanning protection
  - DDoS mitigation
  - IP blacklisting/whitelisting
  - Rate limiting

#### System Healing
- Automated recovery procedures:
  - Service restart on failure
  - Configuration backup/restore
  - System state rollback
  - Malware quarantine
- Uses transaction-based operations
- Maintains recovery point objectives (RPO)

### Frontend Implementation

#### Dashboard Architecture
- React-based single-page application
- State management:
  - Local state for UI components
  - Context API for global state
  - Redux for complex state management
- Real-time updates using WebSocket
- Responsive design with Tailwind CSS

#### Data Visualization
- Uses Chart.js for graphs
- D3.js for complex visualizations
- Features:
  - Real-time metric graphs
  - Threat visualization maps
  - System health indicators
  - Network traffic flows

#### Performance Optimizations
- Lazy loading of components
- Memoization of expensive calculations
- Debounced API calls
- Client-side caching
- Virtual scrolling for large datasets

### API Implementation

#### REST Endpoints
- Implemented using Flask-RESTful
- Authentication:
  - JWT-based token system
  - Role-based access control
  - API key management
- Rate limiting:
  - 100 requests per minute per IP
  - Configurable limits per endpoint

#### WebSocket Implementation
- Uses Socket.IO for real-time updates
- Implements:
  - Auto-reconnection
  - Message queuing
  - Event buffering
  - Heartbeat monitoring

### Data Storage

#### Metrics Storage
- Time-series data stored in InfluxDB
- Retention policies:
  - Raw data: 24 hours
  - Aggregated data: 30 days
  - Summary data: 1 year

#### Security Events
- Stored in PostgreSQL
- Schema includes:
  - Threat details
  - System actions
  - Resolution status
  - Timestamp data

#### Backup System
- Incremental backups every 6 hours
- Full backups daily
- Retention: 30 days of history
- Encrypted storage using AES-256

### Testing

#### Unit Tests
- PyTest for backend
- Jest for frontend
- Coverage requirement: >80%

#### Integration Tests
- End-to-end testing with Selenium
- API testing with Postman
- Load testing with Locust

#### Security Testing
- Regular penetration testing
- Vulnerability scanning
- Fuzzing tests
- Compliance checks

### Deployment

#### Development Environment
- Docker containers for services
- Hot-reloading enabled
- Debug logging
- Mock security events

#### Production Environment
- Kubernetes orchestration
- Load balancing
- High availability setup
- Automated scaling
- Monitoring with Prometheus

================================================================================
