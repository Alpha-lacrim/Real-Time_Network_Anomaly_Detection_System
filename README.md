# Hybrid Network Anomaly Detection System
( Rule-Based and ML-Based Security Engine )

This project is a real-time **Network Anomaly Detection System (NADS)** that uses a hybrid approach, combining a **Machine Learning (ML)** model (**Isolation Forest**) with a traditional **rule-based** engine to identify suspicious network activity.

It features a live web dashboard built with **Flask** and **Flask-SocketIO** to visualize network statistics, live traffic, and detected anomalies as they happen.


<img width="1893" height="887" alt="image" src="https://github.com/user-attachments/assets/7094340d-303b-41bb-98ba-06a65a2000e7" />

-----

## Key Features

  * **Hybrid Detection Engine:** Combines the strengths of **Machine Learning** (scikit-learn's `IsolationForest`) for catching unusual outliers and a fast **rule-based** system for known patterns.
  * **Real-Time Dashboard:** A sleek, dark-mode web UI built with **Flask** and **Socket.IO** to monitor traffic as it happens.
  * **Packet Simulator:** Includes a built-in background thread that generates random network packets every **two** seconds to simulate a live feed for demonstration.
  * **Key Statistics:** Tracks total packets, normal traffic vs. anomalies, threat level, and detection methods (**ML** vs. **Rule** vs. **Hybrid**).
  * **Live Anomaly Feed:** Displays a running list of the most recent anomalies detected, including the suspected attack type, confidence score, and packet details.

-----

## How It Works

The system is a single-file **Flask** application with a background thread.

1.  **Packet Simulator:** A background thread (`background_traffic_generator`) creates a new random "packet" (simulated flow) every **two** seconds.
2.  **Feature Extraction:** Key features (like packet rate, byte rate, protocol, and IP entropy) are extracted from the packet.
3.  **Hybrid Analysis:** The packet is sent to both detection engines simultaneously:
      * **Rule-Based Engine:** Checks the packet against hard-coded rules (e.g., `packet['packets'] > 800`).
      * **ML Engine (Isolation Forest):** A pre-trained `IsolationForest` model predicts if the packet's features are "anomalous" (**an outlier**) compared to the "normal" traffic it was trained on.
4.  **Hybrid Logic:** A final decision is made based on the confidence scores from both engines. For example, if both engines flag the packet, it's an anomaly with high confidence.
5.  **WebSocket Emission (Socket.IO):** The processed packet (now tagged as **"Normal"** or **"Anomaly"**) is broadcast to all connected web clients via **Socket.IO**, which instantly updates the dashboard.
6.  **ML Training:** The **ML** model initially starts untrained. It automatically trains itself on the first **20** packets it sees, learning what "normal" traffic looks like for that session.

***since this is a practical project, it is continually being maintained and improved.**

-----

## Getting Started

### Prerequisites

  * Python **3.7+**
  * **The required** Python libraries

### Installation

1.  Clone the repository (or just download the `app.py` file):

    ```bash
    git clone https://github.com/Alpha-lacrim/Real-Time_Network_Anomaly_Detection_System
    cd your-project-name
    ```

2.  Install the required Python packages:

    ```bash
    pip install numpy pandas scikit-learn flask flask-socketio
    ```

### Usage

**Important:** You must run the Python script directly. **Do NOT use `flask run`**. The `flask run` command will not start the background packet-generating thread, and your dashboard will show no data.

1.  Run the main application file from your terminal:

    ```bash
    python app.py
    ```

2.  You should see output in your terminal indicating the server has started and the background thread is running:

    ```
    Background traffic generator thread started...

    ============================================================
              Network Anomaly Detection System Started
    ============================================================
    Dashboard: http://localhost:8080
    ML Model: Isolation Forest (scikit-learn)
    Detection: Hybrid (Rule-based + ML)
    Mode: SIMULATOR (Generating random packets)
    ============================================================

    (Werkzeug) Running on [http://127.0.0.1:8080](http://127.0.0.1:8080)
    ...
    Client connected
    ```

3.  Open your browser and navigate to:

    ```
    http://localhost:8080
    ```

    You should immediately see the dashboard come alive with simulated data, with the **"Total Packets"** count increasing with a **two-second** interval.
    The packets are currently generated randomly, I will try to use scapy to capture real packets after making some changes in Security Engine models.
