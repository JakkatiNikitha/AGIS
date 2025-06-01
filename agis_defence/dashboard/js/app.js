const { useState, useEffect } = React;

// API endpoints with error handling
const API = {
    async fetch(endpoint, options = {}) {
        try {
            console.log(`Fetching ${endpoint}...`);
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                throw new Error(`API Error: ${response.status} ${response.statusText}`);
            }
            const data = await response.json();
            console.log(`Received data from ${endpoint}:`, data);
            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    },
    
    endpoints: {
        status: '/api/system/status',
        blockIp: (ip) => `/api/firewall/block/${ip}`,
        unblockIp: (ip) => `/api/firewall/unblock/${ip}`,
        networkStats: '/api/network/stats',
        networkAnomalies: '/api/network/anomalies',
        firewallStatus: '/api/firewall/status',
        analyzeThreat: '/api/threat/analyze',
        handleThreat: '/api/threat/handle',
        healing: {
            status: '/api/healing/status',
            backup: '/api/healing/backup',
            restore: '/api/healing/restore'
        }
    }
};

// Components
const Header = () => (
    <header className="bg-blue-600 text-white p-4">
        <h1 className="text-2xl font-bold">AGIS Defence Dashboard</h1>
        <p className="text-sm">AI-Powered Security Monitoring</p>
    </header>
);

const NetworkStatus = ({ stats, anomalies }) => {
    const [threatLevel, setThreatLevel] = useState('low');
    const [aiAnalysis, setAiAnalysis] = useState(null);

    useEffect(() => {
        if (anomalies && anomalies.length > 0) {
            // Analyze threats using AI
            const analyzeThreats = async () => {
                try {
                    const response = await fetch(API.endpoints.analyzeThreat, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ anomalies, stats })
                    });
                    const analysis = await response.json();
                    setAiAnalysis(analysis);
                    setThreatLevel(analysis.threat_level || 'medium');
                } catch (error) {
                    console.error('Failed to analyze threats:', error);
                }
            };
            analyzeThreats();
        }
    }, [anomalies, stats]);

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div className="bg-white p-4 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Network Status</h3>
                <div className={`text-sm ${threatLevel === 'low' ? 'text-green-600' : threatLevel === 'medium' ? 'text-yellow-600' : 'text-red-600'}`}>
                    Threat Level: {threatLevel.toUpperCase()}
                </div>
                {stats && (
                    <div className="mt-2 space-y-2">
                        <div className="text-sm">
                            <span className="font-medium">Packet Rate:</span> {stats.packet_rate}/s
                        </div>
                        <div className="text-sm">
                            <span className="font-medium">Active Connections:</span> {stats.active_connections}
                        </div>
                        <div className="text-sm">
                            <span className="font-medium">Bandwidth Usage:</span> {stats.bandwidth_usage} MB/s
                        </div>
                    </div>
                )}
            </div>
            
    <div className="bg-white p-4 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">AI Analysis</h3>
                {aiAnalysis ? (
                    <div className="space-y-2">
                        <div className="text-sm">
                            <span className="font-medium">Risk Assessment:</span> {aiAnalysis.risk_level}
                        </div>
                        <div className="text-sm">
                            <span className="font-medium">Detected Patterns:</span> {aiAnalysis.detected_patterns?.join(', ')}
                        </div>
                        <div className="text-sm">
                            <span className="font-medium">Recommendation:</span> {aiAnalysis.recommendation}
                        </div>
                    </div>
                ) : (
                    <div className="text-sm text-gray-500">No threats detected</div>
                )}
            </div>
        </div>
    );
};

const ThreatList = ({ threats, onBlock, onHeal }) => (
    <div className="bg-white p-4 rounded-lg shadow mb-4">
        <h3 className="text-lg font-semibold mb-4">Active Threats</h3>
        {threats.length > 0 ? (
            <div className="space-y-2">
                {threats.map((threat, i) => (
                    <div key={i} className="p-3 border rounded hover:bg-gray-50">
                        <div className="flex justify-between items-start">
                            <div>
                                <div className="font-medium">{threat.type}</div>
                                <div className="text-sm text-gray-600">Source: {threat.source}</div>
                                <div className="text-sm text-gray-600">Detected: {new Date(threat.timestamp).toLocaleString()}</div>
                                <div className="text-sm mt-1">
                                    <span className={`inline-block px-2 py-1 rounded ${
                                        threat.severity === 'high' ? 'bg-red-100 text-red-800' :
                                        threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                        'bg-blue-100 text-blue-800'
                                    }`}>
                                        {threat.severity.toUpperCase()}
                                    </span>
                                </div>
                            </div>
                            <div className="space-x-2">
                                <button
                                    onClick={() => onBlock(threat.source)}
                                    className="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700 text-sm"
                                >
                                    Block
                                </button>
                                <button
                                    onClick={() => onHeal(threat)}
                                    className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm"
                                >
                                    Heal
                                </button>
                            </div>
                        </div>
                        {threat.details && (
            <div className="mt-2 text-sm text-gray-600">
                                {threat.details}
                            </div>
                        )}
                    </div>
                ))}
            </div>
        ) : (
            <div className="text-sm text-gray-500">No active threats detected</div>
        )}
    </div>
);

const SecurityMetrics = ({ metrics }) => (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Blocked IPs</h3>
            <div className="text-3xl font-bold text-blue-600">{metrics.blocked_ips}</div>
            <div className="text-sm text-gray-600">Last 24 hours</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Threats Detected</h3>
            <div className="text-3xl font-bold text-yellow-600">{metrics.threats_detected}</div>
            <div className="text-sm text-gray-600">Last 24 hours</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">System Health</h3>
            <div className="text-3xl font-bold text-green-600">{metrics.system_health}%</div>
            <div className="text-sm text-gray-600">Current Status</div>
        </div>
    </div>
);

const AIMonitoringPanel = ({ systemStatus }) => {
    const [aiAnalysis, setAiAnalysis] = useState(null);
    const [recentActions, setRecentActions] = useState([]);
    const [monitoringStatus, setMonitoringStatus] = useState('active');
    const [attackHistory, setAttackHistory] = useState(new Map());

    const updateAttackHistory = (threat) => {
        const threatKey = `${threat.type}-${threat.source}`;
        const history = attackHistory.get(threatKey) || { count: 0, lastSeen: null };
        
        // Update history with new occurrence
        const updatedHistory = {
            count: history.count + 1,
            lastSeen: new Date(),
            type: threat.type,
            source: threat.source
        };
        
        setAttackHistory(new Map(attackHistory.set(threatKey, updatedHistory)));
        return updatedHistory;
    };

    const handleThreat = async (threat) => {
        try {
            const history = updateAttackHistory(threat);
            const isRepeatAttack = history.count > 1;
            
            // Determine response based on attack history
            const response = await API.fetch(API.endpoints.handleThreat, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...threat,
                    action: isRepeatAttack ? 'block' : 'heal',
                    history: {
                        occurrences: history.count,
                        lastSeen: history.lastSeen
                    }
                })
            });

            // Record the action taken
            const action = {
                timestamp: new Date(),
                action: isRepeatAttack ? 'Blocked' : 'Healed',
                threat: threat.type,
                source: threat.source,
                severity: threat.severity,
                result: response.status,
                isRepeatAttack,
                occurrences: history.count
            };

            setRecentActions(prev => [action, ...prev].slice(0, 10));

            // If it's a repeat attack, also block the source
            if (isRepeatAttack) {
                await API.fetch(API.endpoints.blockIp(threat.source), {
                    method: 'POST'
                });
            }

            return response;
        } catch (error) {
            console.error('Failed to handle threat:', error);
            throw error;
        }
    };

    useEffect(() => {
        const analyzeAndRespond = async () => {
            try {
                // Get AI analysis of current system state
                const analysis = await API.fetch(API.endpoints.analyzeThreat, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ systemStatus })
                });
                
                setAiAnalysis(analysis);

                // Automatically respond to detected threats
                if (analysis.threats && analysis.threats.length > 0) {
                    for (const threat of analysis.threats) {
                        await handleThreat(threat);
                    }
                }
            } catch (error) {
                console.error('AI monitoring error:', error);
                setMonitoringStatus('error');
            }
        };

        const interval = setInterval(analyzeAndRespond, 5000);
        return () => clearInterval(interval);
    }, [systemStatus]);

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div className="bg-white p-4 rounded-lg shadow">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-lg font-semibold">AI Security Monitor</h3>
                    <div className={`px-3 py-1 rounded-full text-sm ${
                        monitoringStatus === 'active' ? 'bg-green-100 text-green-800' :
                        'bg-red-100 text-red-800'
                    }`}>
                        {monitoringStatus === 'active' ? 'Active' : 'Error'}
                    </div>
                </div>
                
                {aiAnalysis && (
                    <div className="space-y-3">
                        <div className="p-3 bg-gray-50 rounded">
                            <div className="font-medium">Current Risk Assessment</div>
                            <div className="text-sm mt-1">
                                <div>Threat Level: {aiAnalysis.threat_level}</div>
                                <div>Confidence: {aiAnalysis.confidence}%</div>
                                <div>Active Threats: {aiAnalysis.threats?.length || 0}</div>
                            </div>
                        </div>
                        
                        {aiAnalysis.recommendations && (
                            <div className="p-3 bg-blue-50 text-blue-800 rounded">
                                <div className="font-medium">AI Recommendations</div>
                                <ul className="text-sm mt-1 list-disc list-inside">
                                    {aiAnalysis.recommendations.map((rec, i) => (
                                        <li key={i}>{rec}</li>
                                    ))}
                                </ul>
                            </div>
                        )}
                    </div>
                )}
            </div>

        <div className="bg-white p-4 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-4">Recent AI Actions</h3>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                    {recentActions.map((action, i) => (
                        <div key={i} className={`p-3 rounded text-sm ${
                            action.severity === 'critical' ? 'bg-red-100 text-red-800' :
                            action.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            'bg-blue-100 text-blue-800'
                        }`}>
                            <div className="font-medium">
                                {action.action} - {action.threat}
                                {action.isRepeatAttack && 
                                    <span className="ml-2 text-xs bg-yellow-200 px-2 py-1 rounded">
                                        Repeat Attack ({action.occurrences}x)
                                    </span>
                                }
                            </div>
                            <div className="text-sm mt-1">
                                <div>Source: {action.source}</div>
                                <div>Result: {action.result}</div>
                                <div className="text-xs">{action.timestamp.toLocaleString()}</div>
                            </div>
                        </div>
                    ))}
                    {recentActions.length === 0 && (
                        <div className="text-sm text-gray-500">No recent actions</div>
                    )}
                </div>
            </div>
        </div>
    );
};

const SystemStatusPanel = ({ status }) => (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">System Health</h3>
            <div className="space-y-2">
                <div className="flex justify-between items-center">
                    <span className="text-sm">CPU Usage</span>
                    <span className={`text-sm ${status.cpu_usage > 80 ? 'text-red-600' : 'text-green-600'}`}>
                        {status.cpu_usage}%
                    </span>
                </div>
                <div className="flex justify-between items-center">
                    <span className="text-sm">Memory Usage</span>
                    <span className={`text-sm ${status.memory_usage > 80 ? 'text-red-600' : 'text-green-600'}`}>
                        {status.memory_usage}%
                    </span>
                </div>
                <div className="flex justify-between items-center">
                    <span className="text-sm">Disk Usage</span>
                    <span className={`text-sm ${status.disk_usage > 80 ? 'text-red-600' : 'text-green-600'}`}>
                        {status.disk_usage}%
                    </span>
                </div>
            </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Firewall Status</h3>
            <div className="space-y-2">
                <div className="text-sm">
                    <span className="font-medium">Active Rules:</span> {status.firewall.active_rules}
                </div>
                <div className="text-sm">
                    <span className="font-medium">Blocked IPs:</span> {status.firewall.blocked_ips?.length || 0}
                </div>
                <div className="text-sm">
                    <span className="font-medium">Last Updated:</span> {new Date(status.firewall.last_updated).toLocaleString()}
                </div>
            </div>
        </div>

    <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Network Status</h3>
            <div className="space-y-2">
                <div className="text-sm">
                    <span className="font-medium">Active Connections:</span> {status.network.active_connections}
                </div>
                <div className="text-sm">
                    <span className="font-medium">Bandwidth Usage:</span> {status.network.bandwidth_usage} MB/s
                </div>
                <div className="text-sm">
                    <span className="font-medium">Packet Loss:</span> {status.network.packet_loss}%
                </div>
            </div>
        </div>
    </div>
);

const ThreatTrendsPanel = ({ trends }) => (
    <div className="bg-white p-4 rounded-lg shadow mb-4">
        <h3 className="text-lg font-semibold mb-4">Security Trends</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 bg-gray-50 rounded">
                <h4 className="font-medium mb-2">24-Hour Summary</h4>
        <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                        <span>Total Threats Detected:</span>
                        <span className="font-medium">{trends?.daily?.total || 0}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                        <span>Blocked Attacks:</span>
                        <span className="font-medium">{trends?.daily?.blocked || 0}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                        <span>Critical Incidents:</span>
                        <span className="font-medium text-red-600">{trends?.daily?.critical || 0}</span>
                    </div>
                </div>
            </div>
            
            <div className="p-3 bg-gray-50 rounded">
                <h4 className="font-medium mb-2">Threat Distribution</h4>
                <div className="space-y-2">
                    {Object.entries(trends?.distribution || {}).map(([type, count]) => (
                        <div key={type} className="flex justify-between text-sm">
                            <span>{type}:</span>
                            <span className="font-medium">{count}</span>
                </div>
            ))}
                </div>
            </div>
        </div>
    </div>
);

const AIAnalysisReport = ({ analysis }) => (
    <div className="bg-white p-4 rounded-lg shadow mb-4">
        <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold">AI Security Analysis</h3>
            <div className="text-sm text-gray-500">
                Updated: {new Date(analysis?.timestamp).toLocaleString()}
            </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-4">
                <div className="p-3 bg-gray-50 rounded">
                    <h4 className="font-medium mb-2">Threat Prediction</h4>
                    <div className="space-y-2">
                        {analysis?.predictions?.map((pred, i) => (
                            <div key={i} className={`p-2 rounded text-sm ${
                                pred.probability > 0.7 ? 'bg-red-100 text-red-800' :
                                pred.probability > 0.4 ? 'bg-yellow-100 text-yellow-800' :
                                'bg-blue-100 text-blue-800'
                            }`}>
                                <div className="font-medium">{pred.type}</div>
                                <div>Probability: {(pred.probability * 100).toFixed(1)}%</div>
                                <div>Time Frame: {pred.timeframe}</div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="p-3 bg-gray-50 rounded">
                    <h4 className="font-medium mb-2">System Vulnerabilities</h4>
                    <div className="space-y-2">
                        {analysis?.vulnerabilities?.map((vuln, i) => (
                            <div key={i} className="text-sm">
                                <div className="font-medium">{vuln.type}</div>
                                <div className="text-gray-600">{vuln.description}</div>
                                <div className={`text-sm ${
                                    vuln.severity === 'high' ? 'text-red-600' :
                                    vuln.severity === 'medium' ? 'text-yellow-600' :
                                    'text-blue-600'
                                }`}>
                                    Severity: {vuln.severity}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <div className="space-y-4">
                <div className="p-3 bg-gray-50 rounded">
                    <h4 className="font-medium mb-2">Security Recommendations</h4>
                    <div className="space-y-2">
                        {analysis?.recommendations?.map((rec, i) => (
                            <div key={i} className="text-sm">
                                <div className="font-medium">{rec.title}</div>
                                <div className="text-gray-600">{rec.description}</div>
                                <div className="text-blue-600">Priority: {rec.priority}</div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="p-3 bg-gray-50 rounded">
                    <h4 className="font-medium mb-2">System Health Score</h4>
                    <div className="text-center">
                        <div className={`text-4xl font-bold ${
                            analysis?.healthScore >= 80 ? 'text-green-600' :
                            analysis?.healthScore >= 60 ? 'text-yellow-600' :
                            'text-red-600'
                        }`}>
                            {analysis?.healthScore}/100
                        </div>
                        <div className="text-sm text-gray-600 mt-2">
                            {analysis?.healthStatus}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
);

const ATTACK_TYPES = {
    NETWORK: {
        category: 'Network Attacks',
        types: [
            { id: 'ddos', name: 'DDoS Attack', description: 'Distributed Denial of Service attacks' },
            { id: 'syn_flood', name: 'SYN Flood', description: 'TCP SYN flooding attack' },
            { id: 'port_scan', name: 'Port Scan', description: 'Port scanning attempts' },
            { id: 'arp_spoof', name: 'ARP Spoofing', description: 'Address Resolution Protocol spoofing' }
        ]
    },
    INTRUSION: {
        category: 'Intrusion Attempts',
        types: [
            { id: 'brute_force', name: 'Brute Force', description: 'Password brute force attempts' },
            { id: 'ssh_attack', name: 'SSH Attack', description: 'SSH-based attacks' },
            { id: 'rdp_attack', name: 'RDP Attack', description: 'Remote Desktop Protocol attacks' },
            { id: 'credential_stuff', name: 'Credential Stuffing', description: 'Automated credential testing' }
        ]
    },
    MALWARE: {
        category: 'Malware Threats',
        types: [
            { id: 'ransomware', name: 'Ransomware', description: 'Ransomware activity detection' },
            { id: 'trojan', name: 'Trojan', description: 'Trojan horse malware' },
            { id: 'fileless_malware', name: 'Fileless Malware', description: 'Memory-based malware' },
            { id: 'cryptominer', name: 'Cryptominer', description: 'Cryptocurrency mining malware' }
        ]
    },
    WEB: {
        category: 'Web Attacks',
        types: [
            { id: 'sql_injection', name: 'SQL Injection', description: 'SQL injection attempts' },
            { id: 'xss', name: 'XSS', description: 'Cross-site scripting attacks' },
            { id: 'csrf', name: 'CSRF', description: 'Cross-site request forgery' },
            { id: 'rce', name: 'RCE', description: 'Remote code execution attempts' }
        ]
    },
    INSIDER: {
        category: 'Insider Threats',
        types: [
            { id: 'data_exfil', name: 'Data Exfiltration', description: 'Unauthorized data transfer' },
            { id: 'priv_escalation', name: 'Privilege Escalation', description: 'Unauthorized privilege increase' },
            { id: 'policy_violation', name: 'Policy Violation', description: 'Security policy violations' }
        ]
    },
    ADVANCED: {
        category: 'Advanced Threats',
        types: [
            { id: 'apt', name: 'APT', description: 'Advanced Persistent Threat activity' },
            { id: 'zero_day', name: 'Zero-day Exploit', description: 'Unknown vulnerability exploitation' },
            { id: 'supply_chain', name: 'Supply Chain', description: 'Supply chain attack attempts' }
        ]
    }
};

const AttackTypesPanel = ({ detectionStats }) => {
    const [selectedCategory, setSelectedCategory] = useState(Object.keys(ATTACK_TYPES)[0]);

    return (
        <div className="bg-white p-4 rounded-lg shadow mb-4">
            <h3 className="text-lg font-semibold mb-4">Attack Detection Coverage</h3>
            
            <div className="flex space-x-2 mb-4 overflow-x-auto pb-2">
                {Object.keys(ATTACK_TYPES).map(category => (
                <button
                        key={category}
                        onClick={() => setSelectedCategory(category)}
                        className={`px-3 py-1 rounded-full text-sm whitespace-nowrap ${
                            selectedCategory === category
                                ? 'bg-blue-600 text-white'
                                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                        }`}
                >
                        {ATTACK_TYPES[category].category}
                </button>
                ))}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {ATTACK_TYPES[selectedCategory].types.map(attack => {
                    const stats = detectionStats?.[attack.id] || { 
                        detected: 0, 
                        blocked: 0,
                        healed: 0,
                        lastSeen: null
                    };
                    
                    return (
                        <div key={attack.id} className="p-3 bg-gray-50 rounded">
                            <div className="flex justify-between items-start">
                                <div>
                                    <div className="font-medium">{attack.name}</div>
                                    <div className="text-sm text-gray-600">{attack.description}</div>
                                </div>
                                <div className={`px-2 py-1 rounded text-xs ${
                                    stats.detected > 0 
                                        ? 'bg-yellow-100 text-yellow-800' 
                                        : 'bg-green-100 text-green-800'
                                }`}>
                                    {stats.detected > 0 ? 'Active' : 'Clear'}
                                </div>
                            </div>
                            
                            {stats.detected > 0 && (
                                <div className="mt-2 text-sm">
                                    <div className="grid grid-cols-3 gap-2 text-center">
                                        <div>
                                            <div className="font-medium">{stats.detected}</div>
                                            <div className="text-xs text-gray-600">Detected</div>
                                        </div>
                                        <div>
                                            <div className="font-medium">{stats.blocked}</div>
                                            <div className="text-xs text-gray-600">Blocked</div>
                                        </div>
                                        <div>
                                            <div className="font-medium">{stats.healed}</div>
                                            <div className="text-xs text-gray-600">Healed</div>
                                        </div>
                                    </div>
                                    {stats.lastSeen && (
                                        <div className="text-xs text-gray-500 mt-2">
                                            Last detected: {new Date(stats.lastSeen).toLocaleString()}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

// Main App with Error Boundary
const App = () => {
    const [systemStatus, setSystemStatus] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchStatus = async () => {
        try {
            setLoading(true);
            const data = await API.fetch(API.endpoints.status);
            setSystemStatus(data);
            setError(null);
        } catch (err) {
            setError('Failed to fetch system status: ' + err.message);
            console.error('Status fetch error:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleBlock = async (ip) => {
        try {
            await API.fetch(API.endpoints.blockIp(ip), { method: 'POST' });
            fetchStatus();
        } catch (err) {
            setError(`Failed to block IP: ${err.message}`);
        }
    };

    const handleUnblock = async (ip) => {
        try {
            await API.fetch(API.endpoints.unblockIp(ip), { method: 'POST' });
            fetchStatus();
        } catch (err) {
            setError(`Failed to unblock IP: ${err.message}`);
        }
    };

    const handleHeal = async (threat) => {
        try {
            await API.fetch(API.endpoints.handleThreat, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(threat)
            });
            fetchStatus();
        } catch (err) {
            setError(`Failed to heal threat: ${err.message}`);
        }
    };

    useEffect(() => {
        fetchStatus();
        const interval = setInterval(fetchStatus, 5000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <div className="min-h-screen">
                <Header />
                <div className="p-4 flex justify-center items-center">
                    <div className="loading">⌛</div> Loading system status...
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="min-h-screen">
                <Header />
                <div className="p-4">
                    <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative">
                        <strong className="font-bold">Error: </strong>
                        <span className="block sm:inline">{error}</span>
                    </div>
                </div>
            </div>
        );
    }

    const metrics = {
        blocked_ips: systemStatus?.firewall?.blocked_ips?.length || 0,
        threats_detected: systemStatus?.anomalies?.length || 0,
        system_health: systemStatus?.healing?.system_health || 100
    };

    return (
        <div className="min-h-screen">
            <Header />
            <main className="p-4">
                <SystemStatusPanel status={systemStatus} />
                
                <AttackTypesPanel detectionStats={systemStatus?.attackStats} />
                
                <NetworkStatus 
                    stats={systemStatus?.network}
                    anomalies={systemStatus?.anomalies}
                    />
                
                <AIMonitoringPanel systemStatus={systemStatus} />
                
                <ThreatTrendsPanel trends={systemStatus?.trends} />
                
                <AIAnalysisReport analysis={systemStatus?.aiAnalysis} />
                
                <ThreatList 
                    threats={systemStatus?.anomalies || []}
                    onBlock={handleBlock}
                    onHeal={handleHeal}
                />
            </main>
        </div>
    );
};

// Error Boundary Component
class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error('Dashboard Error:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="p-4 bg-red-100 text-red-700 rounded">
                    <h2 className="text-lg font-bold mb-2">Something went wrong</h2>
                    <p>{this.state.error?.message || 'Unknown error occurred'}</p>
                </div>
            );
        }
        return this.props.children;
    }
}

// Initialize React
const rootElement = document.getElementById('root');

const renderApp = () => {
    try {
        console.log('Initializing React application...');
        const app = (
            <React.StrictMode>
                <ErrorBoundary>
                    <App />
                </ErrorBoundary>
            </React.StrictMode>
        );
        
        ReactDOM.render(app, rootElement);
        console.log('React application initialized successfully');
    } catch (error) {
        console.error('Failed to render app:', error);
        rootElement.innerHTML = `
            <div class="p-4 bg-red-100 text-red-700">
                <h2 class="text-lg font-bold">Failed to initialize dashboard</h2>
                <p>${error.message}</p>
                <pre class="mt-2 text-sm">${error.stack}</pre>
            </div>
        `;
    }
};

// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderApp);
} else {
    renderApp();
} 