"""
Network Anomaly Detection System with Hybrid ML + Rule-Based Detection
Requirements: pip install numpy pandas scikit-learn flask flask-socketio
Run: python this_file.py
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import time
import random
from flask import Flask, render_template_string
from flask_socketio import SocketIO, emit
import threading

# -------------------------
# Configuration / Globals
# -------------------------
MAX_HISTORY = 200
TRAIN_THRESHOLD = 50

ATTACK_TYPES = ['DDoS', 'Port Scan', 'Brute Force', 'Data Exfiltration', 'Malware C&C']
PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
# Force threading async mode so background thread and socketio.emit work reliably
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

traffic_history = []
anomaly_history = []
stats = {
    'total_packets': 0,
    'normal_traffic': 0,
    'anomalies_detected': 0,
    'rule_based_detections': 0,
    'ml_based_detections': 0,
    'hybrid_detections': 0,
    'threat_level': 'Low',
    'ml_trained': False
}

# -------------------------
# Detectors
# -------------------------
class NetworkAnomalyDetector:
    def __init__(self):
        """Initialize the ML model (Isolation Forest)"""
        self.model = IsolationForest(
            contamination=0.15,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def extract_features(self, packet):
        """Extract features from network packet using packet timestamp (if present)."""
        # get hour from packet timestamp when possible, fallback to now
        try:
            hour = datetime.strptime(packet.get('timestamp', ''), '%H:%M:%S').hour
        except Exception:
            hour = datetime.now().hour

        # safe protocol numeric mapping
        proto_idx = 0
        if packet.get('protocol') in PROTOCOLS:
            if len(PROTOCOLS) > 1:
                proto_idx = PROTOCOLS.index(packet['protocol']) / (len(PROTOCOLS) - 1)
            else:
                proto_idx = 0.0

        return {
            'packet_rate': packet.get('packets', 0) / 100.0,
            'byte_rate': packet.get('bytes', 0) / 10000.0,
            'protocol_numeric': proto_idx,
            'time_of_day': hour / 24.0,
            'src_entropy': self._calculate_entropy(packet.get('src_ip', '')),
            'dst_entropy': self._calculate_entropy(packet.get('dst_ip', '')),
            'packet_size_avg': packet.get('bytes', 0) / max(packet.get('packets', 1), 1)
        }

    def _calculate_entropy(self, ip_address):
        """Calculate Shannon entropy of IP address characters (simple proxy)."""
        ip_str = str(ip_address).replace('.', '')
        if not ip_str:
            return 0.0
        entropy = 0.0
        for ch in set(ip_str):
            prob = ip_str.count(ch) / len(ip_str)
            entropy -= prob * np.log2(prob)
        # normalize roughly by max possible entropy (digits/characters up to length 8)
        return float(entropy / 8.0)

    def train(self, data):
        """Train the model on historical data"""
        if len(data) < TRAIN_THRESHOLD:
            print(f"[ML] Not enough data to train: have {len(data)}, need {TRAIN_THRESHOLD}")
            return False

        feature_matrix = []
        for packet in data:
            features = self.extract_features(packet)
            feature_matrix.append(list(features.values()))

        X = np.array(feature_matrix)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        print("[ML] Training completed.")
        return True

    def predict(self, packet):
        """Predict if packet is anomalous using ML"""
        if not self.is_trained:
            return {
                'is_anomaly': False,
                'confidence': 0.5,
                'anomaly_score': 0.0
            }

        features = self.extract_features(packet)
        X = np.array([list(features.values())])
        X_scaled = self.scaler.transform(X)

        prediction = self.model.predict(X_scaled)[0]
        anomaly_score = self.model.score_samples(X_scaled)[0]  # larger => more "normal" in sklearn

        # Invert so larger => more anomalous, scale down to reduce saturation
        mapped_score = -anomaly_score / 4.0

        # Sigmoid -> probability-like confidence (higher => more anomalous)
        confidence = 1.0 / (1.0 + np.exp(-mapped_score))
        confidence = float(np.clip(confidence, 0.0, 1.0))

        return {
            'is_anomaly': prediction == -1,
            'confidence': float(confidence),
            'anomaly_score': float(anomaly_score)
        }


class RuleBasedDetector:
    """Simple rule-based detector (deterministic except small simulated noise)."""

    @staticmethod
    def detect(packet):
        anomaly_score = 0.0
        reasons = []

        p = packet.get('packets', 0)
        b = packet.get('bytes', 0)
        proto = packet.get('protocol', '')

        if p > 800:
            anomaly_score += 0.3
            reasons.append('High packet count')

        if b > 40000:
            anomaly_score += 0.25
            reasons.append('Large data transfer')

        # keep randomness small but deterministic during tests (seed can be set externally)
        if proto == 'ICMP' and random.random() > 0.7:
            anomaly_score += 0.2
            reasons.append('Suspicious protocol')

        if p < 100 and random.random() > 0.9:
            anomaly_score += 0.25
            reasons.append('Possible port scan')

        anomaly_score += random.uniform(0, 0.15)
        is_anomaly = anomaly_score > 0.7

        return {
            'is_anomaly': is_anomaly,
            'confidence': float(min(anomaly_score, 0.95)),
            'reasons': reasons if is_anomaly else []
        }


class HybridDetector:
    """Combine rule-based and ML results into final decision."""

    @staticmethod
    def detect(packet, rule_result, ml_result):
        if rule_result['is_anomaly'] and ml_result['is_anomaly']:
            return {
                'is_anomaly': True,
                'confidence': max(rule_result['confidence'], ml_result['confidence']),
                'detected_by': 'Both',
                'rule_score': rule_result['confidence'],
                'ml_score': ml_result['confidence']
            }

        if ml_result['is_anomaly'] and ml_result['confidence'] > 0.85:
            return {
                'is_anomaly': True,
                'confidence': ml_result['confidence'],
                'detected_by': 'ML',
                'rule_score': rule_result['confidence'],
                'ml_score': ml_result['confidence']
            }

        if rule_result['is_anomaly'] and rule_result['confidence'] > 0.80:
            return {
                'is_anomaly': True,
                'confidence': rule_result['confidence'],
                'detected_by': 'Rule',
                'rule_score': rule_result['confidence'],
                'ml_score': ml_result['confidence']
            }

        return {
            'is_anomaly': False,
            'confidence': 1 - max(rule_result['confidence'], ml_result['confidence']),
            'detected_by': 'None',
            'rule_score': rule_result['confidence'],
            'ml_score': ml_result['confidence']
        }

# initialize detectors
ml_detector = NetworkAnomalyDetector()
rule_detector = RuleBasedDetector()
hybrid_detector = HybridDetector()

# -------------------------
# Traffic generation & processing
# -------------------------
def generate_network_packet():
    """Generate simulated network traffic"""
    return {
        'id': time.time() + random.random(),
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'src_ip': f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}",
        'dst_ip': f"10.0.{random.randint(0, 255)}.{random.randint(0, 255)}",
        'protocol': random.choice(PROTOCOLS),
        'packets': random.randint(50, 1050),
        'bytes': random.randint(1000, 51000)
    }


def process_packet(packet):
    """Process a packet through all detection systems"""
    global stats, traffic_history, anomaly_history, ml_detector

    rule_result = rule_detector.detect(packet)
    ml_result = ml_detector.predict(packet)
    hybrid_result = hybrid_detector.detect(packet, rule_result, ml_result)

    packet.update({
        'is_anomaly': hybrid_result['is_anomaly'],
        'confidence': hybrid_result['confidence'],
        'detected_by': hybrid_result['detected_by'],
        'rule_score': hybrid_result['rule_score'],
        'ml_score': hybrid_result['ml_score'],
        'attack_type': random.choice(ATTACK_TYPES) if hybrid_result['is_anomaly'] else None
    })

    # Update statistics
    stats['total_packets'] += 1

    if packet['is_anomaly']:
        stats['anomalies_detected'] += 1
        anomaly_history.append(packet)
        anomaly_history = anomaly_history[-10:]

        if packet['detected_by'] == 'Rule':
            stats['rule_based_detections'] += 1
        elif packet['detected_by'] == 'ML':
            stats['ml_based_detections'] += 1
        elif packet['detected_by'] == 'Both':
            stats['hybrid_detections'] += 1
    else:
        stats['normal_traffic'] += 1

    anomaly_rate = (stats['anomalies_detected'] / stats['total_packets']) * 100
    if anomaly_rate > 20:
        stats['threat_level'] = 'Critical'
    elif anomaly_rate > 10:
        stats['threat_level'] = 'High'
    elif anomaly_rate > 5:
        stats['threat_level'] = 'Medium'
    else:
        stats['threat_level'] = 'Low'

    # Add to traffic history and keep a larger buffer so ML can train
    traffic_history.append(packet)
    traffic_history = traffic_history[-MAX_HISTORY:]

    # Train ML model periodically using TRAIN_THRESHOLD
    if len(traffic_history) >= TRAIN_THRESHOLD and not ml_detector.is_trained:
        trained = ml_detector.train(traffic_history)
        stats['ml_trained'] = ml_detector.is_trained
        if trained:
            print("[Main] ML model trained on historical data")

    return packet


def background_traffic_generator():
    """Generate network traffic in background and broadcast to clients"""
    while True:
        packet = generate_network_packet()
        processed_packet = process_packet(packet)

        socketio.emit('new_packet', {
            'packet': processed_packet,
            'stats': stats,
            'anomalies': anomaly_history
        })

        time.sleep(2)


# -------------------------
# HTML Dashboard
# -------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Anomaly Detection System</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #111827; color: #f3f4f6; padding: 24px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; align-items: center; gap: 12px; margin-bottom: 32px; }
        .header h1 { font-size: 28px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 20px; }
        .stat-label { color: #9ca3af; font-size: 14px; margin-bottom: 8px; }
        .stat-value { font-size: 32px; font-weight: bold; }
        .threat-low { color: #10b981; } .threat-medium { color: #f59e0b; } .threat-high { color: #f97316; } .threat-critical { color: #ef4444; }
        .ml-card { background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%); border: 1px solid #3b82f6; }
        .section { background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 20px; margin-bottom: 24px; }
        .anomaly-item { background: #111827; border: 1px solid #7f1d1d; border-radius: 6px; padding: 12px; margin-bottom: 8px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 8px; }
        .badge-attack { background: #dc2626; color: white; } .badge-hybrid { background: #9333ea; color: white; } .badge-ml { background: #3b82f6; color: white; } .badge-rule { background: #06b6d4; color: white; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; } th { text-align: left; color: #9ca3af; padding: 12px 8px; border-bottom: 1px solid #374151; } td { padding: 12px 8px; border-bottom: 1px solid #374151; }
        .anomaly-row { background: rgba(127, 29, 29, 0.2); } .ip { color: #60a5fa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ Hybrid Network Anomaly Detection System</h1>
                <p>Real-time monitoring with ML-powered threat detection</p>
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
            <div class="stat-card">
                <div class="stat-label">Anomalies Detected</div>
                <div class="stat-value" style="color: #ef4444;" id="anomalies">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Threat Level</div>
                <div class="stat-value" id="threat-level">Low</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card ml-card">
                <div class="stat-label" style="color: #bfdbfe;">ML Model Status</div>
                <div class="stat-value" style="color: white;" id="ml-status">Training...</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Rule-Based Detections</div>
                <div class="stat-value" style="color: #06b6d4;" id="rule-detections">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">ML Detections</div>
                <div class="stat-value" style="color: #3b82f6;" id="ml-detections">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Hybrid Confirmations</div>
                <div class="stat-value" style="color: #9333ea;" id="hybrid-detections">0</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">🚨 Recent Anomalies</div>
            <div id="anomalies-list"></div>
        </div>

        <div class="section">
            <div class="section-title">📡 Live Traffic Feed</div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Protocol</th>
                        <th>Packets</th>
                        <th>Status</th>
                        <th>Method</th>
                        <th>Confidence</th>
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
            if (!data) return;
            updateStats(data.stats);
            updateAnomalies(data.anomalies || []);
            if (data.packet) updateTrafficTable(data.packet);
        });

        function updateStats(stats) {
            document.getElementById('total-packets').textContent = stats.total_packets.toLocaleString();
            document.getElementById('normal-traffic').textContent = stats.normal_traffic.toLocaleString();
            document.getElementById('anomalies').textContent = stats.anomalies_detected;

            const threatLevel = document.getElementById('threat-level');
            threatLevel.textContent = stats.threat_level;
            threatLevel.className = 'stat-value threat-' + stats.threat_level.toLowerCase();

            document.getElementById('rule-detections').textContent = stats.rule_based_detections;
            document.getElementById('ml-detections').textContent = stats.ml_based_detections;
            document.getElementById('hybrid-detections').textContent = stats.hybrid_detections;

            document.getElementById('ml-status').textContent = stats.ml_trained ? 'Active' : 'Training...';
        }

        function updateAnomalies(anomalies) {
            const list = document.getElementById('anomalies-list');
            if (!anomalies || anomalies.length === 0) {
                list.innerHTML = '<p style="text-align: center; color: #6b7280; padding: 40px;">No anomalies detected yet...</p>';
                return;
            }

            list.innerHTML = anomalies.map(a => `
                <div class="anomaly-item">
                    <div style="margin-bottom: 8px;">
                        <span class="badge badge-attack">${a.attack_type || ''}</span>
                        ${getMethodBadge(a.detected_by)}
                        <span style="color: #9ca3af; font-size: 13px;">${a.timestamp}</span>
                        <span style="float: right; font-size: 12px; background: #374151; padding: 4px 8px; border-radius: 4px;">
                            ${(a.confidence * 100).toFixed(0)}% confidence
                        </span>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; font-size: 13px;">
                        <div><span style="color: #9ca3af;">Source:</span> <span class="ip">${a.src_ip}</span></div>
                        <div><span style="color: #9ca3af;">Dest:</span> <span class="ip">${a.dst_ip}</span></div>
                        <div><span style="color: #9ca3af;">Protocol:</span> ${a.protocol}</div>
                        <div><span style="color: #9ca3af;">Packets:</span> ${a.packets}</div>
                    </div>
                    <div style="margin-top: 8px; font-size: 12px;">
                        <span style="color: #9ca3af;">Rule Score:</span> <span style="color: #06b6d4;">${(a.rule_score * 100).toFixed(0)}%</span>
                        <span style="margin-left: 16px; color: #9ca3af;">ML Score:</span> <span style="color: #3b82f6;">${(a.ml_score * 100).toFixed(0)}%</span>
                    </div>
                </div>
            `).join('');
        }

        function getMethodBadge(method) {
            if (method === 'Both') return '<span class="badge badge-hybrid">HYBRID</span>';
            if (method === 'ML') return '<span class="badge badge-ml">ML</span>';
            if (method === 'Rule') return '<span class="badge badge-rule">RULE</span>';
            return '';
        }

        function updateTrafficTable(packet) {
            trafficData.unshift(packet);
            trafficData = trafficData.slice(0, 20);

            const tbody = document.getElementById('traffic-table');
            tbody.innerHTML = trafficData.map(p => `
                <tr class="${p.is_anomaly ? 'anomaly-row' : ''}">
                    <td style="color: #9ca3af;">${p.timestamp}</td>
                    <td class="ip">${p.src_ip}</td>
                    <td class="ip">${p.dst_ip}</td>
                    <td>${p.protocol}</td>
                    <td>${p.packets}</td>
                    <td>
                        <span class="badge" style="background: ${p.is_anomaly ? '#dc2626' : '#10b981'}; color: white;">
                            ${p.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                        </span>
                    </td>
                    <td>${p.is_anomaly ? getMethodBadge(p.detected_by) : ''}</td>
                    <td style="color: ${p.is_anomaly ? '#f87171' : '#34d399'};">
                        ${(p.confidence * 100).toFixed(0)}%
                    </td>
                </tr>
            `).join('');
        }
    </script>
</body>
</html>
"""

# -------------------------
# Flask routes / socket events
# -------------------------
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@socketio.on('connect')
def handle_connect():
    print('Client connected')
    # Safely send no initial packet (client will not try to render missing fields)
    emit('new_packet', {
        'packet': None,
        'stats': stats,
        'anomalies': anomaly_history
    })


# -------------------------
# App entry
# -------------------------
if __name__ == '__main__':
    traffic_thread = threading.Thread(target=background_traffic_generator, daemon=True)
    traffic_thread.start()

    print("\n" + "="*60)
    print("🛡️  Network Anomaly Detection System Started")
    print("="*60)
    print("📊 Dashboard: http://localhost:5000")
    print("🤖 ML Model: Isolation Forest (scikit-learn)")
    print("📡 Detection: Hybrid (Rule-based + ML)")
    print("="*60 + "\n")

    # Allow unsafe werkzeug only for local dev; adjust host/port for production
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
