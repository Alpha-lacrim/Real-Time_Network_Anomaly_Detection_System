import numpy as np
import pandas as pd
import random
import time
import threading
from datetime import datetime

# ML Imports
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.mixture import GaussianMixture
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

# Flask/SocketIO Imports
from flask import Flask, render_template_string
from flask_socketio import SocketIO, emit

# ====================================================================
# Static Model Training & Threshold Analysis
# ====================================================================

print("--- Starting Hybrid Anomaly Detector Setup ---")

# Load Data and Prepare Features
try:
    ns_data = pd.read_csv('embedded_system_network_security_dataset.csv')
    sus_ports_df = pd.read_csv('suspicious_ports_list.csv')
except FileNotFoundError as e:
    print(f"Error: Missing required file: {e}")
    print("Please ensure 'embedded_system_network_security_dataset.csv' and 'suspicious_ports_list.csv' are in the same directory.")
    exit()

# Define features (all columns except 'label')
PACKET_FEATURE_NAMES = [col for col in ns_data.columns if col != 'label']
X = ns_data[PACKET_FEATURE_NAMES].values

# Scale all features (Scaler is saved for live traffic)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Define Rule-Based Components
sus_ports_df.drop(columns=['metadata_link', 'metadata_reference'], inplace=True, errors='ignore')
# Note: The .values and sorting is preserved from the notebook for compatibility
sus_ports_df = pd.DataFrame(sorted(sus_ports_df.values, key=lambda x: x[2]))
SUSPICIOUS_PORTS = set(sus_ports_df[0].astype(int))
# Sample a few suspicious ports for the traffic generator to use
sus_ports_sample = random.sample(list(SUSPICIOUS_PORTS), 20)
print(f"Rule-Based Engine loaded with {len(SUSPICIOUS_PORTS)} suspicious ports.")


# Train ML Models and Calculate Thresholds
contamination_pct = 0.05

# IsolationForest
iso = IsolationForest(n_estimators=200, contamination=contamination_pct, random_state=42)
iso.fit(X_scaled)
scores_iso = iso.decision_function(X_scaled)

# Iso Percentile
threshold_iso_pct = np.percentile(scores_iso, 100 * contamination_pct)

# Iso Knee Detection
s = np.sort(scores_iso)
n = len(s)
x = np.arange(n)
num = abs((s[-1]-s[0])*x - (n-1)*(s - s[0]))
den = np.sqrt((s[-1]-s[0])**2 + (n-1)**2)
dist = num / den
knee_idx = np.argmax(dist)
threshold_iso_knee = s[knee_idx]

# Iso GMM Component Mean
s_col = scores_iso.reshape(-1,1)
gmm = GaussianMixture(n_components=2, random_state=0).fit(s_col)
# anomaly_comp will hold the index (0 or 1) of the component with the lower score mean
anomaly_comp_idx = np.argmin(gmm.means_.ravel())


# Local Outlier Factor (LOF)
lof = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=contamination_pct).fit(X_scaled)
scores_lof = lof.decision_function(X_scaled)

# LOF Percentile
threshold_lof_pct = np.percentile(scores_lof, 100 * contamination_pct)


# One-Class SVM (OCSVM)
ocsvm = OneClassSVM(nu=contamination_pct, gamma='scale').fit(X_scaled)
scores_ocsvm = ocsvm.decision_function(X_scaled)

# OC-SVM Percentile
threshold_ocsvm_pct = np.percentile(scores_ocsvm, 100 * contamination_pct)


# Ensemble Average Score
mms = MinMaxScaler()
# Train MinMaxScaler on the scores from all three models
norm_scores_train = mms.fit_transform(np.vstack([scores_iso, scores_lof, scores_ocsvm]).T)
avg_score_train = np.mean(norm_scores_train, axis=1)

# Ensemble Percentile
threshold_ens_pct = np.percentile(avg_score_train, 100 * contamination_pct)

print("ML Models (IF, LOF, OCSVM) and 6 thresholds successfully trained and saved for live use.")


# ====================================================================
# Real-Time Hybrid Anomaly Detection Flask App
# ====================================================================

# Flask App Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global State Variables
MAX_HISTORY = 200
traffic_history = []
anomaly_history = []
stats = {
    'total_packets': 0,
    'normal_traffic': 0,
    'anomalies_detected': 0,
    'rule_based_detections': 0,
    'hybrid_detections': 0,
    'threat_level': 'Low'
}
ATTACK_TYPES = ['DDoS', 'Port Scan', 'Brute Force', 'Data Exfiltration', 'Malware C&C']


#  Helper Functions
def generate_network_packet():
    """Generate simulated network traffic matching the 17-feature CSV structure"""

    # 1. Simulate the 8 numeric features (scaled 0-1 like the CSV dataset)
    packet = {
        'packet_size': random.uniform(0, 1),
        'inter_arrival_time': random.uniform(0, 1),
        'packet_count_5s': random.uniform(0, 1),
        'mean_packet_size': 0.0,
        'spectral_entropy': random.uniform(0, 1),
        'frequency_band_energy': random.uniform(0, 1),
        'src_port': random.randint(1024, 65535),
        # ~15% chance of suspicious port from the sample list
        'dst_port': random.choice([80, 443, 53] * 50 + sus_ports_sample * 10)
    }

    # 2. Simulate the 9 boolean/categorical features
    tcp_syn = random.choice([True, False])
    tcp_fin = random.choice([True, False])
    tcp_syn_ack = random.choice([True, False]) if not tcp_syn and not tcp_fin else False

    # Protocol types
    packet['protocol_type_TCP'] = random.choice([True, False])
    packet['protocol_type_UDP'] = random.choice([True, False]) if not packet['protocol_type_TCP'] else False

    # IP addresses (simplified simulation)
    src_2 = random.choice([True, False])
    src_3 = random.choice([True, False]) if not src_2 else False
    packet['src_ip_192.168.1.2'] = src_2
    packet['src_ip_192.168.1.3'] = src_3

    dst_5 = random.choice([True, False])
    dst_6 = random.choice([True, False]) if not dst_5 else False
    packet['dst_ip_192.168.1.5'] = dst_5
    packet['dst_ip_192.168.1.6'] = dst_6

    # TCP Flags
    packet['tcp_flags_FIN'] = tcp_fin
    packet['tcp_flags_SYN'] = tcp_syn
    packet['tcp_flags_SYN-ACK'] = tcp_syn_ack

    # 3. Add non-feature metadata for the dashboard
    packet['id'] = time.time() + random.random()
    packet['timestamp'] = datetime.now().strftime('%H:%M:%S')
    packet['src_ip_str'] = '192.168.1.2' if src_2 else ('192.168.1.3' if src_3 else '192.168.1.1')
    packet['dst_ip_str'] = '192.168.1.5' if dst_5 else ('192.168.1.6' if dst_6 else '10.0.0.10')

    return packet


def rule_based_security_engine(packet):
    """Checks packet against security rules and returns a confidence score (0-100)"""
    global SUSPICIOUS_PORTS

    confidence = 0

    # Rule 1: Suspicious Port Access (High Confidence)
    if packet['dst_port'] in SUSPICIOUS_PORTS:
        confidence += 50

    # Rule 2: Suspicious Flag combination (e.g., FIN/SYN set in the same TCP segment)
    if packet['tcp_flags_SYN'] and not packet['tcp_flags_SYN-ACK'] and packet['protocol_type_TCP']:
        confidence += 30

    # Rule 3: Combined high-entropy/size values (simulated rule based on CSV features)
    if packet['spectral_entropy'] > 0.9 and packet['packet_size'] > 0.9:
        confidence += 10

    return min(confidence, 100)


def process_packet(packet):
    """Process a packet using the Hybrid ML Voting and Rule-Based logic"""
    global stats, traffic_history, anomaly_history

    # ML Model Scoring and Voting
    try:
        # Create feature vector in the *exact* order
        X = np.array([[packet[name] for name in PACKET_FEATURE_NAMES]])
    except KeyError as e:
        print(f"Error: Missing feature {e} in simulated packet. Skipping.")
        return packet

    X_scaled = scaler.transform(X)

    # Get scores
    score_iso = iso.decision_function(X_scaled)[0]
    score_lof = lof.decision_function(X_scaled)[0]
    score_ocsvm = ocsvm.decision_function(X_scaled)[0]

    # Individual ML Votes (1 = Anomaly, 0 = Normal)
    vote_iso_pct = 1 if score_iso < threshold_iso_pct else 0
    vote_iso_knee = 1 if score_iso < threshold_iso_knee else 0

    # GMM prediction based on which component the score falls into
    gmm_label = gmm.predict(np.array([[score_iso]]))[0]
    vote_gmm = 1 if gmm_label == anomaly_comp_idx else 0

    vote_lof_pct = 1 if score_lof < threshold_lof_pct else 0
    vote_ocsvm_pct = 1 if score_ocsvm < threshold_ocsvm_pct else 0

    # Ensemble Score prediction
    norm_s = mms.transform(np.array([[score_iso, score_lof, score_ocsvm]]))
    avg_s = np.mean(norm_s)
    vote_ens_pct = 1 if avg_s < threshold_ens_pct else 0

    # Total ML Votes (Max 6)
    ml_votes = vote_iso_pct + vote_iso_knee + vote_gmm + vote_lof_pct + vote_ocsvm_pct + vote_ens_pct

    # Rule-Based Scoring
    rule_confidence = rule_based_security_engine(packet)

    # Hybrid Anomaly Decision Logic
    is_anomaly = False
    if ml_votes == 6:
        # 6 votes: Anomaly if Rule-Based confidence >= 50
        if rule_confidence >= 60:
            is_anomaly = True
            reason = f"High ML Vote (6/6) + Rule-Based Confidence ({rule_confidence}%) - threshold >= 60%"
        else:
            reason = "Normal: 6/6 ML Votes, but Rule-Based Confidence < 60%"

    elif ml_votes == 5:
        # 5 votes: Anomaly if Rule-Based confidence >= 80%
        if rule_confidence >= 80:
            is_anomaly = True
            reason = f"High ML Vote (5/6) + Rule-Based Confidence ({rule_confidence}%) - threshold >= 80%"
        else:
            reason = "Normal: 5/6 ML Votes, but Rule-Based Confidence < 80%"
    elif ml_votes == 4:
        # 4 votes: Anomaly if Rule-Based confidence >= 90%
        if rule_confidence >= 90:
            is_anomaly = True
            reason = f"Medium ML Vote (4/6) + Rule-Based Confidence ({rule_confidence}%) - threshold >= 90%"
        else:
            reason = "Normal: 4/6 ML Votes, but Rule-Based Confidence < 90%"
    else:
        # 0 to 3 votes: Always Normal (for this logic)
        is_anomaly = False
        reason = "Normal (Low ML Votes)"

    # Update Packet and Stats
    packet.update({
        'is_anomaly': is_anomaly,
        'ml_votes': int(ml_votes),
        'rule_confidence': int(rule_confidence),
        'reason': reason,
        'attack_type': random.choice(ATTACK_TYPES) if is_anomaly else 'Normal'
    })

    stats['total_packets'] += 1
    # Count packets that triggered any rule, even if not flagged as final anomaly
    if rule_confidence > 0: stats['rule_based_detections'] += 1

    if is_anomaly:
        stats['anomalies_detected'] += 1
        stats['hybrid_detections'] += 1
        anomaly_history.append(packet)
        anomaly_history = anomaly_history[-10:]  # Keep last 10
    else:
        stats['normal_traffic'] += 1

    # Update threat level based on current anomaly rate
    anomaly_rate = (stats['anomalies_detected'] / stats['total_packets']) * 100 if stats['total_packets'] > 0 else 0
    if anomaly_rate > 20:
        stats['threat_level'] = 'Critical'
    elif anomaly_rate > 10:
        stats['threat_level'] = 'High'
    elif anomaly_rate > 5:
        stats['threat_level'] = 'Medium'
    else:
        stats['threat_level'] = 'Low'

    # Add to traffic history
    traffic_history.append(packet)
    traffic_history = traffic_history[-MAX_HISTORY:]

    return packet


def background_traffic_generator():
    """Generate network traffic in background"""
    while True:
        packet = generate_network_packet()
        processed_packet = process_packet(packet)

        # Emit to connected clients
        socketio.emit('new_packet', {
            'packet': processed_packet,
            'stats': stats,
            'anomalies': anomaly_history
        })

        time.sleep(2)  # 2 seconds interval


# HTML Template (Dashboard)
# HTML Template with Dashboard UI - Updated for Rule-Based and Hybrid Voting
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Hybrid Network Anomaly Detection System</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #111827;
            color: #f3f4f6;
            padding: 24px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 32px;
        }
        .header h1 { font-size: 28px; }
        .header p { color: #9ca3af; margin-top: 4px; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 8px;
            padding: 20px;
        }
        .stat-label { color: #9ca3af; font-size: 14px; margin-bottom: 8px; }
        .stat-value { font-size: 32px; font-weight: bold; }
        .threat-low { color: #10b981; }
        .threat-medium { color: #f59e0b; }
        .threat-high { color: #f97316; }
        .threat-critical { color: #ef4444; }
        .hybrid-card {
            background: linear-gradient(135deg, #6d28d9 0%, #7c3aed 100%);
            border: 1px solid #8b5cf6;
        }
        .rule-card {
            background: linear-gradient(135deg, #059669 0%, #10b981 100%);
            border: 1px solid #10b981;
        }
        .section {
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .section-title {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 16px;
        }
        .anomaly-item {
            background: #111827;
            border: 1px solid #7f1d1d;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            margin-right: 8px;
        }
        .badge-attack { background: #dc2626; color: white; }
        .badge-votes { background: #9333ea; color: white; }
        .badge-rule { background: #10b981; color: white; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th { text-align: left; color: #9ca3af; padding: 12px 8px; border-bottom: 1px solid #374151; }
        td { padding: 12px 8px; border-bottom: 1px solid #374151; }
        .anomaly-row { background: rgba(127, 29, 29, 0.2); }
        .ip { color: #60a5fa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Hybrid Network Anomaly Detection System (ML+Rule Based)</h1>
                <p>Real-time monitoring with a two-stage hybrid decision engine</p>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Packets</div>
                <div class="stat-value" id="total-packets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Normal Traffic</div>
                <div class="stat-value" style="color: #10b981;" id="normal-traffic">0</div>
            </div>
            <div class="stat-card hybrid-card">
                <div class="stat-label" style="color: #e9d5ff;">Hybrid Anomalies (ML+Rule)</div>
                <div class="stat-value" style="color: white;" id="hybrid-detections">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Threat Level</div>
                <div class="stat-value" id="threat-level">Low</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">ML Model Status</div>
                <div class="stat-value" style="color: #a7f3d0;" id="ml-status">Active </div>
            </div>
            <div class="stat-card rule-card">
                <div class="stat-label" style="color: #d1fae5;">Rule-Based Checks Run</div>
                <div class="stat-value" style="color: white;" id="rule-based-detections">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Decision Logic</div>
                <div class="stat-value" style="font-size: 24px; color: #f59e0b;">ML Model Votes + Rule</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Anomaly Rate (Total)</div>
                <div class="stat-value" id="anomaly-rate">0.00%</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Recent Anomalies (Hybrid Detection)</div>
            <div id="anomalies-list"></div>
        </div>

        <div class="section">
            <div class="section-title">Live Traffic Feed</div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Dst Port</th>
                        <th>ML Votes</th>
                        <th>Rule Conf</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="traffic-table"></tbody>
            </table>
        </div>
    </div>

    <script>
        const socket = io();
        let trafficData = [];

        socket.on('new_packet', function(data) {
            updateStats(data.stats);
            updateAnomalies(data.anomalies);
            if (data.packet) updateTrafficTable(data.packet);
        });


        function updateStats(stats) {
            document.getElementById('total-packets').textContent = stats.total_packets.toLocaleString();
            document.getElementById('normal-traffic').textContent = stats.normal_traffic.toLocaleString();
            document.getElementById('hybrid-detections').textContent = stats.hybrid_detections;
            document.getElementById('rule-based-detections').textContent = stats.rule_based_detections;

            const anomalyRate = stats.total_packets > 0 ? ((stats.anomalies_detected / stats.total_packets) * 100).toFixed(2) : '0.00';
            document.getElementById('anomaly-rate').textContent = anomalyRate + '%';

            const threatLevel = document.getElementById('threat-level');
            threatLevel.textContent = stats.threat_level;
            threatLevel.className = 'stat-value threat-' + stats.threat_level.toLowerCase();
        }

        function updateAnomalies(anomalies) {
            const list = document.getElementById('anomalies-list');
            if (anomalies.length === 0) {
                list.innerHTML = '<p style="text-align: center; color: #6b7280; padding: 40px;">No anomalies detected yet...</p>';
                return;
            }

            list.innerHTML = anomalies.slice().reverse().map(a => `
                <div class="anomaly-item">
                    <div style="margin-bottom: 8px;">
                        <span class="badge badge-attack">${a.attack_type}</span>
                        <span class="badge badge-votes">ML VOTES: ${a.ml_votes}/6</span>
                        <span class="badge badge-rule">RULE CONF: ${a.rule_confidence}%</span>
                        <span style="color: #9ca3af; font-size: 13px;">${a.timestamp}</span>
                    </div>
                    <div style="color: #e5e7eb; font-size: 13px;">
                        <span style="color: #9ca3af;">Reason:</span> ${a.reason}
                    </div>
                    <div style="display: flex; gap: 24px; margin-top: 8px; font-size: 13px;">
                        <div><span style="color: #9ca3af;">Source:</span> <span class="ip">${a.src_ip_str}:${a.src_port}</span></div>
                        <div><span style="color: #9ca3af;">Dest:</span> <span class="ip">${a.dst_ip_str}:${a.dst_port}</span></div>
                    </div>
                </div>
            `).join('');
        }

        function updateTrafficTable(packet) {
            trafficData.unshift(packet);
            trafficData = trafficData.slice(0, 20);

            const tbody = document.getElementById('traffic-table');
            tbody.innerHTML = trafficData.map(p => `
                <tr class="${p.is_anomaly ? 'anomaly-row' : ''}">
                    <td style="color: #9ca3af;">${p.timestamp}</td>
                    <td class="ip">${p.src_ip_str}</td>
                    <td class="ip">${p.dst_ip_str}</td>
                    <td>${p.dst_port}</td>
                    <td style="color: ${p.is_anomaly ? '#f97316' : '#9ca3af'}; font-weight: bold;">${p.ml_votes}</td>
                    <td style="color: ${p.rule_confidence >= 75 ? '#ef4444' : (p.rule_confidence > 0 ? '#f59e0b' : '#34d399')}; font-weight: bold;">
                        ${p.rule_confidence}%
                    </td>
                    <td>
                        <span class="badge" style="background: ${p.is_anomaly ? '#dc2626' : '#10b981'}; color: white;">
                            ${p.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                        </span>
                    </td>
                </tr>
            `).join('');
        }
    </script>
</body>
</html>
"""


# Flask Routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('new_packet', {
        'packet': None,
        'stats': stats,
        'anomalies': anomaly_history
    })


# Main Execution
if __name__ == '__main__':
    # Start background traffic generator in a separate thread
    traffic_thread = threading.Thread(target=background_traffic_generator, daemon=True)
    traffic_thread.start()

    print("\n" + "="*60)
    print("          Hybrid Anomaly Detection System Started")
    print("="*60)
    print("Dashboard: http://localhost:8080")
    print("ML Model: Using 6 pre-trained models/thresholds")
    print("Detection: Hybrid (ML Voting [6, 5, 4] + Rule-Based Confidence)")
    print("="*60 + "\n")

    # Run the Flask server

    socketio.run(app, debug=False, host='0.0.0.0', port=8080, allow_unsafe_werkzeug=True)
